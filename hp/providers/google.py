"""Google backend (family 3), on the `google-genai` SDK.

Same contract as the other backends: one call in, (payload, meta) out, every
failure mapped onto the status taxonomy by `providers._classify` (which reads
the SDK's integer `code` attribute as a status code).

* Structured output: `response_mime_type="application/json"` with a response
  schema. The wire schema is the structural subset (no ranges, no
  additionalProperties); the local validator enforces the rest.
* Truncation: a finish reason of MAX_TOKENS raises `Truncated`.
* Drift: `model_version` is echoed as `served_model`, so the dispatcher's
  served-model check (abort on mismatch) works for this provider too.

The SDK is imported lazily, so the test suite runs without it. Tests use a
fake client; the field names used here (`candidates[0].finish_reason`,
`model_version`, `usage_metadata.prompt_token_count / candidates_token_count`,
`HttpOptions(timeout=<milliseconds>)`) must be checked against the installed
SDK version before the first paid run (see docs/study.html, "still to verify").
"""

import os

from .. import schema


def _wire_schema(contract):
    """Structural subset of the contract's schema that the response-schema API takes."""

    def strip(node):
        if isinstance(node, dict):
            return {
                k: strip(v)
                for k, v in node.items()
                if k not in ("additionalProperties", "minimum", "maximum")
            }
        if isinstance(node, list):
            return [strip(v) for v in node]
        return node

    return strip(contract.schema)


def call(spec, prompt, cfg, contract=schema.LEGACY):
    from google import genai
    from google.genai import types

    from . import Truncated, _overrides, _sampling

    key_env = spec.get("api_key_env", "GOOGLE_API_KEY")
    client = genai.Client(
        api_key=os.environ[key_env],
        http_options=types.HttpOptions(timeout=int(cfg["timeout_s"] * 1000)),
    )
    conf = {"max_output_tokens": cfg["max_tokens"]}
    conf.update(_sampling(spec, cfg))
    if contract.kind == "json":
        conf["response_mime_type"] = "application/json"
        conf["response_schema"] = _wire_schema(contract)
    conf.update(_overrides(spec))
    r = client.models.generate_content(
        model=spec["model"],
        contents=prompt,
        config=types.GenerateContentConfig(**conf),
    )
    cands = getattr(r, "candidates", None) or []
    finish = getattr(cands[0], "finish_reason", None) if cands else None
    finish_s = str(getattr(finish, "name", finish) or "")
    usage = getattr(r, "usage_metadata", None)
    meta = {
        "served_model": getattr(r, "model_version", None),
        "stop_reason": finish_s or None,
        "in_tokens": getattr(usage, "prompt_token_count", None),
        "out_tokens": getattr(usage, "candidates_token_count", None),
    }
    if "MAX_TOKENS" in finish_s.upper():
        raise Truncated(finish_s)
    if contract.kind == "json":
        parsed = getattr(r, "parsed", None)
        if isinstance(parsed, dict):
            return parsed, meta
    return getattr(r, "text", None) or "", meta
