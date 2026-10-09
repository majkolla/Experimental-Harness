"""WP2: contracts threaded through the backends; the Google adapter; retries.

Every SDK is replaced by a fake module in sys.modules. Nothing here can reach
the network (and the conftest guard would refuse it anyway).
"""

import sys
import types

import pytest

from hp import providers, schema
from hp.schema import OK, REQUEST_ERROR, TIMEOUT, TRANSPORT_ERROR, TRUNCATED

CFG = {"timeout_s": 5, "temperature": 0.7, "top_p": 1.0, "max_tokens": 50, "max_attempts": 4}
V13 = {"verdict": "approve", "risk": 22, "justification": "fine"}


def _ns(**kw):
    return types.SimpleNamespace(**kw)


@pytest.fixture
def fake_anthropic(monkeypatch):
    seen = {}

    class Messages:
        def create(self, **kw):
            seen.update(kw)
            if "tools" in kw:
                content = [_ns(type="tool_use", input=dict(V13))]
            else:
                content = [_ns(type="text", text="```diff\n--- a/x\n+++ b/x\n```")]
            return _ns(model=kw["model"], stop_reason=seen.get("_stop", "end_turn"),
                       usage=_ns(input_tokens=11, output_tokens=7), content=content)

    class Anthropic:
        def __init__(self, **kw):
            seen["client"] = kw
            self.messages = Messages()

    monkeypatch.setitem(sys.modules, "anthropic", _ns(Anthropic=Anthropic))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return seen


@pytest.fixture
def fake_openai(monkeypatch):
    seen = {}

    class Responses:
        def create(self, **kw):
            seen.update(kw)
            text = '{"verdict": "reject", "risk": 90, "justification": "no"}' if "text" in kw else "plain"
            return _ns(model=kw["model"], incomplete_details=None, status="completed",
                       usage=_ns(input_tokens=3, output_tokens=4), output_text=text)

    class OpenAI:
        def __init__(self, **kw):
            self.responses = Responses()

    monkeypatch.setitem(sys.modules, "openai", _ns(OpenAI=OpenAI))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    return seen


def test_anthropic_asks_for_the_v13_schema_and_passes_config_knobs(fake_anthropic):
    spec = {"provider": "anthropic", "model": "test-a-2026-01-01",
            "reasoning_params": {"metadata": {"user_id": "t"}}}
    rec = providers.call_once(spec, "p", CFG, schema.REVIEW_V13)
    assert rec["status"] == OK and rec["decision"] == "approve" and rec["risk"] == 22.0
    assert fake_anthropic["tools"][0]["input_schema"] is schema.REVIEW_V13_SCHEMA
    assert fake_anthropic["tool_choice"] == {"type": "tool", "name": "submit_review"}
    assert fake_anthropic["temperature"] == 0.7 and fake_anthropic["top_p"] == 1.0
    assert fake_anthropic["metadata"] == {"user_id": "t"}
    assert fake_anthropic["client"]["max_retries"] == 0


def test_a_recorded_omission_drops_the_parameter(fake_anthropic):
    spec = {"provider": "anthropic", "model": "m-2026-01-01", "send_temperature": False,
            "send_top_p": False, "tool_choice": "auto"}
    providers.call_once(spec, "p", CFG, schema.REVIEW_V13)
    assert "temperature" not in fake_anthropic and "top_p" not in fake_anthropic
    assert fake_anthropic["tool_choice"] == {"type": "auto"}


def test_text_mode_sends_no_tools(fake_anthropic):
    rec = providers.call_once({"provider": "anthropic", "model": "m"}, "p", CFG, schema.TEXT)
    assert rec["status"] == OK and rec["text"].startswith("```diff")
    assert "tools" not in fake_anthropic


def test_openai_uses_the_strict_wire_schema(fake_openai):
    rec = providers.call_once({"provider": "openai", "model": "m"}, "p", CFG, schema.REVIEW_V13)
    assert rec["status"] == OK and rec["decision"] == "reject"
    fmt = fake_openai["text"]["format"]
    assert fmt["strict"] is True and fmt["schema"] is schema.REVIEW_V13_STRICT_SCHEMA
    providers.call_once({"provider": "openai", "model": "m"}, "p", CFG, schema.TEXT)


# --- Google ----------------------------------------------------------------


class _GoogleError(Exception):
    def __init__(self, code):
        super().__init__(f"google error {code}")
        self.code = code


@pytest.fixture
def fake_google(monkeypatch):
    state = {"finish": "STOP", "parsed": dict(V13), "text": None, "raise": None,
             "version": "test-c-model-001"}

    class Models:
        def generate_content(self, model, contents, config):
            state["config"] = config
            if state["raise"]:
                raise state["raise"]
            return _ns(candidates=[_ns(finish_reason=_ns(name=state["finish"]))],
                       parsed=state["parsed"], text=state["text"], model_version=state["version"],
                       usage_metadata=_ns(prompt_token_count=9, candidates_token_count=5))

    class Client:
        def __init__(self, api_key, http_options):
            state["timeout_ms"] = http_options.timeout
            self.models = Models()

    gtypes = _ns(HttpOptions=lambda timeout: _ns(timeout=timeout),
                 GenerateContentConfig=lambda **kw: kw)
    genai = _ns(Client=Client, types=gtypes)
    monkeypatch.setitem(sys.modules, "google", _ns(genai=genai))
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", gtypes)
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    return state


GSPEC = {"provider": "google", "model": "test-c-model-001"}


def test_google_structured_output_and_drift_echo(fake_google):
    rec = providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)
    assert rec["status"] == OK and rec["risk"] == 22.0
    assert rec["served_model"] == "test-c-model-001"
    conf = fake_google["config"]
    assert conf["response_mime_type"] == "application/json"
    assert "additionalProperties" not in conf["response_schema"]
    assert "minimum" not in conf["response_schema"]["properties"]["risk"]
    assert conf["temperature"] == 0.7 and conf["max_output_tokens"] == 50
    assert fake_google["timeout_ms"] == 5000


def test_google_falls_back_to_text_when_nothing_is_parsed(fake_google):
    fake_google["parsed"] = None
    fake_google["text"] = '{"verdict": "abstain", "risk": 50, "justification": ""}'
    assert providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)["decision"] == "abstain"


def test_google_truncation(fake_google):
    fake_google["finish"] = "MAX_TOKENS"
    assert providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)["status"] == TRUNCATED


def test_google_error_codes_are_classified(fake_google):
    fake_google["raise"] = _GoogleError(429)
    assert providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)["status"] == TRANSPORT_ERROR
    fake_google["raise"] = _GoogleError(400)
    assert providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)["status"] == REQUEST_ERROR


def test_missing_google_key_is_our_fault():
    rec = providers.call_once(GSPEC, "p", CFG, schema.REVIEW_V13)
    assert rec["status"] == REQUEST_ERROR


# --- retries and pins --------------------------------------------------------


def test_the_attempt_budget_continues_across_resumes(monkeypatch):
    class APITimeoutError(Exception):
        pass

    def always_timeout(spec, prompt, cfg, contract):
        raise APITimeoutError()

    monkeypatch.setitem(providers.PROVIDERS, "flaky", always_timeout)
    recs = providers.call_with_retries({"provider": "flaky", "model": "m"}, "p", CFG,
                                       contract=schema.REVIEW_V13, max_attempts=2,
                                       attempt_offset=2, sleep=lambda s: None)
    assert [r["attempt"] for r in recs] == [3, 4]
    assert all(r["status"] == TIMEOUT for r in recs)


def test_a_pin_violation_is_never_swallowed(monkeypatch):
    def drift(spec, prompt, cfg, contract):
        raise providers.PinViolation("served weights differ")

    monkeypatch.setitem(providers.PROVIDERS, "drifting", drift)
    with pytest.raises(providers.PinViolation):
        providers.call_with_retries({"provider": "drifting", "model": "m"}, "p", CFG,
                                    contract=schema.REVIEW_V13, sleep=lambda s: None)


def test_integer_code_attribute_is_read_as_a_status_code():
    assert providers._classify(_GoogleError(503)) == TRANSPORT_ERROR
    assert providers._classify(_GoogleError(404)) == REQUEST_ERROR
