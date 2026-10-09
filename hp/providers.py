"""One network call in, one status-tagged record out.

Two things this module is responsible for beyond making the call.

**Schema enforcement at the provider.** Every backend here is asked for the
verdict through its native structured-output mechanism (Anthropic tool_use,
OpenAI json_schema, Ollama format=<schema>), so a malformed verdict is rare
rather than routine. The text fallback in `schema.parse_verdict` still exists,
because "rare" is not "never" and a dropped panel is a biased panel.

**Classifying failures rather than flattening them.** A timeout, a rate limit,
a 400, and a truncated response have different scientific meanings and
different retry policies. Flattening them into one exception -- and then into
one `status: "error"` -- is what made the previous runner unable to distinguish
"try again" from "this call will never succeed".

Retries here are *operational* retries against the identical call_id. They are
never scientific replicates, and each attempt is logged separately with its own
`attempt` index so the missingness structure stays auditable.
"""

import hashlib
import json
import os
import random
import time

from . import schema
from .schema import (
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
_STRICT_SCHEMA = {
    "type": "object",
    "properties": {
        "merge_verdict": {"type": "string", "enum": list(schema.DECISIONS)},
        "confidence": {"type": "number"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": list(schema.SEVERITIES)},
                    "summary": {"type": "string"},
                },
                "required": ["severity", "summary"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["merge_verdict", "confidence", "findings"],
    "additionalProperties": False,
}

_TOOL_DESC = (
    "Submit your merge verdict for the patch under review. "
    "merge_verdict must be one of approve, reject, abstain."
)


class Truncated(Exception):
    """Provider stopped on the token limit; the verdict is unusable."""


def _classify(exc):
    """Map a provider exception onto the status taxonomy.

    Matched on class name and any `status_code` attribute rather than on
    imported SDK exception types, so this module stays importable without the
    SDKs installed (the test suite never touches the network).
    """
    name = type(exc).__name__.lower()
    code = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
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


# --------------------------------------------------------------------------
# backends: each returns (payload, meta); payload is a dict or raw text
# --------------------------------------------------------------------------


def _anthropic(spec, prompt, cfg):
    from anthropic import Anthropic

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        timeout=cfg["timeout_s"],
        max_retries=0,  # attempts are counted and logged by us, not the SDK
    )
    kwargs = {}
    if spec.get("send_temperature", True):
        kwargs["temperature"] = cfg["temperature"]
    r = client.messages.create(
        model=spec["model"],
        max_tokens=cfg["max_tokens"],
        tools=[
            {
                "name": "submit_review",
                "description": _TOOL_DESC,
                "input_schema": schema.VERDICT_SCHEMA,
            }
        ],
        tool_choice={"type": "tool", "name": "submit_review"},
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
    for block in r.content:
        if getattr(block, "type", None) == "tool_use":
            return block.input, meta
    text = "".join(getattr(b, "text", "") for b in r.content)
    return text, meta


def _openai(spec, prompt, cfg):
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        timeout=cfg["timeout_s"],
        max_retries=0,
    )
    kwargs = {}
    if spec.get("send_temperature", True):
        # Reasoning models reject `temperature`; set send_temperature=false for
        # those in the config and record that the decode setting is the
        # provider default.
        kwargs["temperature"] = cfg["temperature"]
    r = client.responses.create(
        model=spec["model"],
        input=prompt,
        max_output_tokens=cfg["max_tokens"],
        text={
            "format": {
                "type": "json_schema",
                "name": "merge_review",
                "schema": _STRICT_SCHEMA,
                "strict": True,
            }
        },
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


def _ollama(spec, prompt, cfg):
    from ollama import Client

    client = Client(host=spec.get("host"), timeout=cfg["timeout_s"])
    r = client.chat(
        model=spec["model"],
        messages=[{"role": "user", "content": prompt}],
        format=schema.VERDICT_SCHEMA,
        options={
            "temperature": cfg["temperature"],
            "num_predict": cfg["max_tokens"],
        },
    )
    meta = {
        "served_model": spec["model"],  # local runtime does not echo a snapshot
        "stop_reason": r.get("done_reason") if isinstance(r, dict) else r.done_reason,
        "in_tokens": (r.get("prompt_eval_count") if isinstance(r, dict) else None),
        "out_tokens": (r.get("eval_count") if isinstance(r, dict) else None),
    }
    if meta["stop_reason"] == "length":
        raise Truncated("length")
    content = r["message"]["content"] if isinstance(r, dict) else r.message.content
    return content, meta


def _synthetic(spec, prompt, cfg):
    """A deterministic pseudo-reviewer. Not a model; a pipeline test fixture.

    Used by the offline end-to-end check and the dry run so the whole path --
    schedule, dispatch, log, estimators, bootstrap -- can be exercised without
    a network or a budget. The shared-cause strength is configurable so a
    planted effect can be recovered by the analysis as a self-test.

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


def call_once(spec, prompt, cfg):
    """A single attempt. Returns a record; never raises for a provider fault."""
    started = time.time()
    try:
        payload, meta = PROVIDERS[spec["provider"]](spec, prompt, cfg)
    except Truncated as exc:
        return _record(TRUNCATED, None, None, {"stop_reason": str(exc)}, started)
    except (KeyError, ImportError) as exc:
        # Missing API key, unknown provider, or an SDK that is not installed.
        # Our fault, not the provider's: retrying is guaranteed to fail again.
        return _record(REQUEST_ERROR, None, None, {"error": repr(exc)}, started)
    except Exception as exc:  # noqa: BLE001 -- a failed call is data, not a crash
        return _record(_classify(exc), None, None, {"error": repr(exc)}, started)

    verdict, reason = schema.parse_verdict(payload)
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    if verdict is None:
        meta = {**meta, "schema_error": reason}
        return _record(SCHEMA_INVALID, None, raw, meta, started)
    return _record(OK, verdict, raw, meta, started)


def _record(status, verdict, raw, meta, started):
    finished = time.time()
    return {
        "status": status,
        "verdict": verdict,
        "decision": verdict["merge_verdict"] if verdict else None,
        "confidence": verdict["confidence"] if verdict else None,
        "response": raw,
        "started": started,
        "finished": finished,
        "latency_s": round(finished - started, 3),
        **meta,
    }


def call_with_retries(spec, prompt, cfg, rng=None):
    """Return the list of attempt records for one call_id.

    Every attempt is returned, not just the last, so the log carries the full
    missingness structure. `attempt` is an operational counter and must never
    be treated as a replicate index in analysis.
    """
    rng = rng or random.Random(0)
    out = []
    for attempt in range(1, cfg["max_attempts"] + 1):
        rec = call_once(spec, prompt, cfg)
        rec["attempt"] = attempt
        out.append(rec)
        if rec["status"] == OK or rec["status"] not in RETRYABLE:
            break
        if attempt < cfg["max_attempts"]:
            time.sleep(min(30.0, 2**attempt * (0.5 + rng.random())))
    return out
