"""WP2: open-weight pins (checksum, precision, serving stack), overflow, logging."""

import pytest

from hp import providers, schema
from hp.providers import openweight
from hp.schema import OK, REQUEST_ERROR

SHA = "ab" * 32
SPEC = {"provider": "openweight", "model": "test-open-X", "weights_sha": SHA,
        "precision": "q8", "serving_stack": "ollama 0.0-test", "host": "http://h:1",
        "num_ctx": 4000, "gpus": 2, "reload_threshold_s": 1.0, "tier": "open"}
CFG = {"timeout_s": 5, "temperature": 0.7, "top_p": 1.0, "max_tokens": 500, "max_attempts": 4}


class Probe:
    calls = 0
    facts_value = {"weights_sha": SHA, "precision": "q8"}
    version_value = "0.0-test"

    def __init__(self, host):
        pass

    def version(self):
        return Probe.version_value

    def facts(self, model):
        Probe.calls += 1
        return dict(Probe.facts_value)


@pytest.fixture(autouse=True)
def fake_server(monkeypatch):
    Probe.calls = 0
    Probe.facts_value = {"weights_sha": SHA, "precision": "q8"}
    Probe.version_value = "0.0-test"
    openweight.set_probe_factory(Probe)
    state = {"in_tokens": 300, "load_ns": 0}

    def chat(spec, prompt, cfg, contract):
        return ({"verdict": "approve", "risk": 10, "justification": "ok"},
                {"served_model": spec["model"], "stop_reason": "stop",
                 "in_tokens": state["in_tokens"], "out_tokens": 20,
                 "_durations_ns": {"load_duration": state["load_ns"],
                                   "prompt_eval_duration": 1_500_000_000,
                                   "eval_duration": 500_000_000}})

    monkeypatch.setattr(openweight, "_chat", chat)
    yield state
    openweight.set_probe_factory(openweight.OllamaProbe)


def test_pins_verified_and_extension_fields_logged(fake_server):
    rec = providers.call_once(SPEC, "short prompt", CFG, schema.REVIEW_V13)
    assert rec["status"] == OK
    assert rec["weights_sha"] == SHA and rec["precision"] == "q8"
    assert rec["serving_stack"] == "ollama 0.0-test"
    assert rec["gpu_seconds"] == pytest.approx(2.0 * 2)


@pytest.mark.parametrize("field, value", [("weights_sha", "cd" * 32), ("precision", "q4")])
def test_served_weights_that_differ_from_the_pins_abort(field, value):
    Probe.facts_value = {**Probe.facts_value, field: value}
    with pytest.raises(providers.PinViolation, match=field):
        providers.call_with_retries(SPEC, "p", CFG, contract=schema.REVIEW_V13, sleep=lambda s: None)


def test_a_different_server_version_aborts():
    Probe.version_value = "0.1"
    with pytest.raises(providers.PinViolation, match="serving_stack"):
        openweight.verify_all([SPEC])


def test_overflow_before_the_call_is_a_request_error_and_not_retried():
    prompt = "x" * (4 * 4000)
    recs = providers.call_with_retries(SPEC, prompt, CFG, contract=schema.REVIEW_V13, sleep=lambda s: None)
    assert len(recs) == 1
    assert recs[0]["status"] == REQUEST_ERROR and recs[0]["reason"] == "context_overflow"


def test_overflow_reported_by_the_server_is_caught(fake_server):
    fake_server["in_tokens"] = 3600
    rec = providers.call_once(SPEC, "p", CFG, schema.REVIEW_V13)
    assert rec["status"] == REQUEST_ERROR and rec["reason"] == "context_overflow"


def test_a_model_reload_triggers_a_fresh_pin_check(fake_server):
    providers.call_once(SPEC, "p", CFG, schema.REVIEW_V13)
    before = Probe.calls
    fake_server["load_ns"] = 5_000_000_000
    providers.call_once(SPEC, "p", CFG, schema.REVIEW_V13)
    assert Probe.calls == before + 1
    Probe.facts_value = {**Probe.facts_value, "weights_sha": "ef" * 32}
    with pytest.raises(providers.PinViolation):
        providers.call_once(SPEC, "p", CFG, schema.REVIEW_V13)
