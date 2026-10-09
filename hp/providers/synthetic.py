"""`synthetic_world`: the nine synthetic models of the v1.3 offline self-test.

Not a model; a pipeline fixture. Behaviour comes from `hp.synthworld.World`,
keyed by the explicit `_context` (cve, generator, state, pair, trial) that the
dispatcher attaches only for this backend. Real backends never receive a
context, and nothing here reads the prompt to find out what it is reviewing.

Failures are realistic in shape: a timeout raises an exception whose class name
contains "timeout" (classified `timeout`, retried), truncation raises
`Truncated`, a schema violation returns an invalid payload. Transient failures
hit only the first attempt; persistent ones hit every attempt, so some calls
end unresolved after the four-attempt budget and are coded fail-closed.
"""

import json

from .. import schema
from ..tokens import proxy_tokens


class SyntheticTimeout(Exception):
    """Classified as `timeout` by name, like an SDK's APITimeoutError."""


def call(spec, prompt, cfg, contract=schema.LEGACY):
    from . import Truncated

    world = spec["_world"]
    ctx = spec["_context"]
    key = spec["_call_key"]
    meta = {
        "served_model": spec.get("snapshot") or spec["model"],
        "stop_reason": "end_turn",
        "in_tokens": proxy_tokens(prompt),
    }
    if spec.get("tier") == "open":
        meta.update(
            weights_sha=spec.get("weights_sha"),
            precision=spec.get("precision"),
            serving_stack=spec.get("serving_stack"),
        )

    if contract.kind == "text":
        text = world.generation_text(ctx["cve"], ctx["generator"], key)
        meta["out_tokens"] = proxy_tokens(text)
        if spec.get("tier") == "open":
            meta["gpu_seconds"] = round(meta["out_tokens"] / 1000.0, 6)
        return text, meta

    kind, payload = world.review(spec["_ref"], spec["synthetic"], ctx, key, spec.get("_attempt", 1))
    if kind == "timeout":
        raise SyntheticTimeout("synthetic timeout")
    if kind == "truncated":
        raise Truncated("synthetic max_tokens")
    if kind == "schema_invalid":
        payload = {"verdict": "maybe", "risk": "high"}
    meta["out_tokens"] = proxy_tokens(json.dumps(payload))
    if spec.get("tier") == "open":
        meta["gpu_seconds"] = round(meta["out_tokens"] / 1000.0, 6)
    return payload, meta
