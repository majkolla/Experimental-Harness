"""One network call in, one status-tagged record out.

Two things this module is responsible for beyond making the call.

**Schema enforcement at the provider.** Every backend here is asked for the
verdict through its native structured-output mechanism (Anthropic tool_use,
OpenAI json_schema, Ollama format=<schema>, Google response schema), so a
malformed verdict is rare rather than routine. The text fallback in
`schema.parse_verdict` still exists, because "rare" is not "never" and a
dropped panel is a biased panel.

**Classifying failures rather than flattening them.** A timeout, a rate limit,
a 400, and a truncated response have different scientific meanings and
different retry policies. Flattening them into one exception -- and then into
one `status: "error"` -- is what made the previous runner unable to distinguish
"try again" from "this call will never succeed".

Retries here are *operational* retries against the identical call_id. They are
never scientific replicates, and each attempt is logged separately with its own
`attempt` index so the missingness structure stays auditable.

**Contracts (v1.3 study).** Every backend now receives a `schema.Contract`:
the legacy Experiment 1 verdict (the default, so the legacy path is
unchanged), the v1.3 review verdict (verdict / risk / justification), or plain
text for patch generation. Provider-native knobs (`reasoning_params`,
`send_temperature`, `send_top_p`) come from the config, never from code.

This file was `hp/providers.py` until WP2; it became a package so the Google,
open-weight and synthetic-world backends can live next to it. Every legacy
import (`from hp import providers`, `providers._classify`, ...) still works.
"""

import hashlib
import json
import os
import random
import time

from .. import schema
from ..schema import (
    OK,
    REQUEST_ERROR,
    RETRYABLE,
    SCHEMA_INVALID,
    TIMEOUT,
    TRANSPORT_ERROR,
    TRUNCATED,
)

# OpenAI strict json_schema rejects validation keywords like minimum/maximum,
# so the wire schema is the structural subset; `schema.validate` still enforces
# the numeric range on the way back in.
_STRICT_SCHEMA = schema.LEGACY_STRICT_SCHEMA

_TOOL_DESC = schema.LEGACY.tool_desc


class Truncated(Exception):
    """Provider stopped on the token limit; the verdict is unusable."""


class ContextOverflow(Exception):
    """The prompt does not fit the model's context; the call cannot succeed.

    Logged as status `request_error` with reason `context_overflow`, so the
    six-status taxonomy stays as it is (SPEC_ANSWERS Q2).
    """


class PinViolation(RuntimeError):
    """The served model is not the pinned one. Never swallowed: aborts the run."""


def _classify(exc):
    """Map a provider exception onto the status taxonomy.

    Matched on class name and any `status_code` attribute rather than on
    imported SDK exception types, so this module stays importable without the
    SDKs installed (the test suite never touches the network). An integer
    `code` attribute (the Google SDK's convention) is read as a status code too.
    """
    name = type(exc).__name__.lower()
    code = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    if code is None:
        alt = getattr(exc, "code", None)
        if isinstance(alt, int) and not isinstance(alt, bool):
            code = alt
    if "timeout" in name or "timedout" in name:
        return TIMEOUT
    if code in (400, 401, 403, 404, 405, 413, 422):
        return REQUEST_ERROR
    if code == 429 or (isinstance(code, int) and code >= 500):
        return TRANSPORT_ERROR
    if any(w in name for w in ("connection", "ratelimit", "apistatus", "internalserver")):
        return TRANSPORT_ERROR
    if "badrequest" in name or "notfound" in name or "permission" in name:
        return REQUEST_ERROR
    return TRANSPORT_ERROR


def _overrides(spec):
    """Provider-native request parameters from the config (e.g. reasoning)."""
    rp = spec.get("reasoning_params")
    if rp in (None, "", {}):
        return {}
    if not isinstance(rp, dict):
        raise KeyError(f"reasoning_params must be an object, got {rp!r}")
    return dict(rp)


def _sampling(spec, cfg):
    """temperature / top_p as configured, minus any recorded omission (Q16)."""
    out = {}
    if spec.get("send_temperature", True) and cfg.get("temperature") is not None:
        out["temperature"] = cfg["temperature"]
    if spec.get("send_top_p", True) and cfg.get("top_p") is not None:
        out["top_p"] = cfg["top_p"]
    return out


def _attr(obj, key, default=None):
    """Read a field from an SDK object or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# --------------------------------------------------------------------------
# backends: each returns (payload, meta); payload is a dict or raw text
# --------------------------------------------------------------------------


def _anthropic(spec, prompt, cfg, contract=schema.LEGACY):
    from anthropic import Anthropic

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        timeout=cfg["timeout_s"],
        max_retries=0,  # attempts are counted and logged by us, not the SDK
    )
    kwargs = _sampling(spec, cfg)
    kwargs.update(_overrides(spec))
    if contract.kind == "json":
        kwargs["tools"] = [
            {
                "name": contract.tool_name,
                "description": contract.tool_desc,
                "input_schema": contract.schema,
            }
        ]
        # Forced tool use is the default; a config may set tool_choice="auto"
        # (e.g. where forced tool use and a reasoning mode do not combine).
        if spec.get("tool_choice", "forced") == "auto":
            kwargs["tool_choice"] = {"type": "auto"}
        else:
            kwargs["tool_choice"] = {"type": "tool", "name": contract.tool_name}
    r = client.messages.create(
        model=spec["model"],
        max_tokens=cfg["max_tokens"],
        messages=[{"role": "user", "content": prompt}],
        **kwargs,
    )
    meta = {
        "served_model": r.model,
        "stop_reason": r.stop_reason,
        "in_tokens": r.usage.input_tokens,
        "out_tokens": r.usage.output_tokens,
    }
    if r.stop_reason == "max_tokens":
        raise Truncated(meta["stop_reason"])
    if contract.kind == "json":
        for block in r.content:
            if getattr(block, "type", None) == "tool_use":
                return block.input, meta
    text = "".join(getattr(b, "text", "") or "" for b in r.content)
    return text, meta


def _openai(spec, prompt, cfg, contract=schema.LEGACY):
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        timeout=cfg["timeout_s"],
        max_retries=0,
    )
    # Reasoning models reject `temperature`; set send_temperature=false for
    # those in the config (with a deviation_note) and the decode setting is
    # recorded as the provider default.
    kwargs = _sampling(spec, cfg)
    kwargs.update(_overrides(spec))
    if contract.kind == "json":
        kwargs["text"] = {
            "format": {
                "type": "json_schema",
                "name": contract.name,
                "schema": contract.strict_schema,
                "strict": True,
            }
        }
    r = client.responses.create(
        model=spec["model"],
        input=prompt,
        max_output_tokens=cfg["max_tokens"],
        **kwargs,
    )
    reason = getattr(getattr(r, "incomplete_details", None), "reason", None)
    meta = {
        "served_model": r.model,
        "stop_reason": reason or getattr(r, "status", None),
        "in_tokens": getattr(r.usage, "input_tokens", None),
        "out_tokens": getattr(r.usage, "output_tokens", None),
    }
    if reason == "max_output_tokens":
        raise Truncated(reason)
    return r.output_text, meta


def _ollama(spec, prompt, cfg, contract=schema.LEGACY):
    from ollama import Client

    client = Client(host=spec.get("host"), timeout=cfg["timeout_s"])
    options = {"temperature": cfg["temperature"], "num_predict": cfg["max_tokens"]}
    if spec.get("send_top_p", True) and cfg.get("top_p") is not None:
        options["top_p"] = cfg["top_p"]
    if spec.get("num_ctx") is not None:
        options["num_ctx"] = spec["num_ctx"]
    options.update(_overrides(spec))
    kwargs = {}
    if contract.kind == "json":
        kwargs["format"] = contract.schema
    r = client.chat(
        model=spec["model"],
        messages=[{"role": "user", "content": prompt}],
        options=options,
        **kwargs,
    )
    meta = {
        "served_model": spec["model"],  # local runtime does not echo a snapshot
        "stop_reason": _attr(r, "done_reason"),
        "in_tokens": _attr(r, "prompt_eval_count"),
        "out_tokens": _attr(r, "eval_count"),
        "_durations_ns": {
            k: _attr(r, k)
            for k in ("total_duration", "load_duration", "prompt_eval_duration", "eval_duration")
        },
    }
    if meta["stop_reason"] == "length":
        raise Truncated("length")
    message = _attr(r, "message")
    content = _attr(message, "content")
    return content, meta


def _synthetic(spec, prompt, cfg, contract=schema.LEGACY):
    """A deterministic pseudo-reviewer. Not a model; a pipeline test fixture.

    LEGACY (Experiment 1). Used by the offline end-to-end check and the dry run
    so the whole path -- schedule, dispatch, log, estimators, bootstrap -- can
    be exercised without a network or a budget. The shared-cause strength is
    configurable so a planted effect can be recovered by the analysis as a
    self-test. The v1.3 study uses `synthetic_world` instead.

    It reads the *packet* out of the prompt, which is exactly how a real shared
    context induces coupling: same packet, same nudge, all seats at once.
    """
    p = spec.get("base_rate", 0.4)
    shared = spec.get("shared_effect", 0.0)
    salt = spec.get("salt", "")

    def u(*parts):
        h = hashlib.sha256("|".join(str(x) for x in parts).encode()).hexdigest()
        return int(h[:12], 16) / 16**12

    key = spec.get("_call_key", prompt[:64])
    pkt = spec.get("_packet_id", "")
    lift = shared * (1 if u("pkt", salt, pkt) < 0.34 else 0)
    approve = u("call", salt, key) < min(1.0, p + lift)
    payload = {
        "merge_verdict": "approve" if approve else "reject",
        "confidence": round(0.5 + 0.4 * u("conf", salt, key), 2),
        "findings": [] if approve else [{"severity": "high", "summary": "synthetic"}],
    }
    return payload, {"served_model": spec["model"], "stop_reason": "end_turn"}


PROVIDERS = {
    "anthropic": _anthropic,
    "openai": _openai,
    "ollama": _ollama,
    "synthetic": _synthetic,
}


def call_once(spec, prompt, cfg, contract=None):
    """A single attempt. Returns a record; never raises for a provider fault.

    `PinViolation` is the one exception that propagates: a served model that is
    not the pinned one is not a failed call, it is a different experiment.
    """
    contract = contract or schema.LEGACY
    started = time.time()
    try:
        payload, meta = PROVIDERS[spec["provider"]](spec, prompt, cfg, contract)
    except PinViolation:
        raise
    except Truncated as exc:
        return _record(TRUNCATED, None, None, {"stop_reason": str(exc)}, started, contract)
    except ContextOverflow as exc:
        return _record(
            REQUEST_ERROR, None, None,
            {"reason": "context_overflow", "error": str(exc)}, started, contract,
        )
    except (KeyError, ImportError) as exc:
        # Missing API key, unknown provider, or an SDK that is not installed.
        # Our fault, not the provider's: retrying is guaranteed to fail again.
        return _record(REQUEST_ERROR, None, None, {"error": repr(exc)}, started, contract)
    except Exception as exc:  # noqa: BLE001 -- a failed call is data, not a crash
        return _record(_classify(exc), None, None, {"error": repr(exc)}, started, contract)

    if contract is schema.LEGACY:
        verdict, reason = schema.parse_verdict(payload)
    else:
        verdict, reason = schema.parse_with(payload, contract)
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    if verdict is None:
        meta = {**meta, "schema_error": reason}
        return _record(SCHEMA_INVALID, None, raw, meta, started, contract)
    return _record(OK, verdict, raw, meta, started, contract)


def _record(status, verdict, raw, meta, started, contract=None):
    contract = contract or schema.LEGACY
    finished = time.time()
    if contract is schema.LEGACY:
        flat = {
            "decision": verdict["merge_verdict"] if verdict else None,
            "confidence": verdict["confidence"] if verdict else None,
        }
    else:
        flat = contract.summarise(verdict) if verdict else {"decision": None}
    return {
        "status": status,
        "verdict": verdict if contract.kind == "json" else None,
        **flat,
        "response": raw,
        "started": started,
        "finished": finished,
        "latency_s": round(finished - started, 3),
        **meta,
    }


def call_with_retries(spec, prompt, cfg, rng=None, contract=None, max_attempts=None,
                      attempt_offset=0, sleep=time.sleep):
    """Return the list of attempt records for one call_id.

    Every attempt is returned, not just the last, so the log carries the full
    missingness structure. `attempt` is an operational counter and must never
    be treated as a replicate index in analysis.

    `max_attempts` and `attempt_offset` let a resumed run continue the attempt
    budget of a call across invocations (SPEC_ANSWERS Q1: four attempts in
    total, counted across resumes). By default they reproduce the legacy
    behaviour exactly.
    """
    rng = rng or random.Random(0)
    budget = cfg["max_attempts"] if max_attempts is None else max_attempts
    out = []
    for i in range(1, budget + 1):
        attempt = attempt_offset + i
        # `_attempt` is read only by the synthetic backends (to model transient
        # failures); real backends send nothing from the spec but the model id
        # and the configured provider knobs.
        rec = call_once({**spec, "_attempt": attempt}, prompt, cfg, contract)
        rec["attempt"] = attempt
        out.append(rec)
        if rec["status"] == OK or rec["status"] not in RETRYABLE:
            break
        if i < budget:
            sleep(min(30.0, 2**i * (0.5 + rng.random())))
    return out


# Backends that live in their own modules register themselves here. Imported
# last so they can use the helpers above.
from . import google as _google_mod  # noqa: E402
from . import openweight as _openweight_mod  # noqa: E402
from . import synthetic as _synthetic_mod  # noqa: E402

PROVIDERS["google"] = _google_mod.call
PROVIDERS["openweight"] = _openweight_mod.call
PROVIDERS["synthetic_world"] = _synthetic_mod.call
