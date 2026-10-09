"""Open-weight models (families 4-6, X/Y/Z), served locally through Ollama.

Wraps the Ollama backend with what an API provider gives for free and a local
runtime does not:

* **Pins.** Ollama echoes the requested model name, so the served-model check
  of the API backends cannot detect drift. Instead the weights checksum (the
  SHA-256 of the weights blob), the precision (quantisation level) and the
  serving-stack version are read from the server and compared with the config.
  Checked at start-up, at the end of each run, and whenever a call reports that
  the model was (re)loaded (SPEC_ANSWERS Q17). A mismatch raises `PinViolation`,
  which aborts the run.
* **Context overflow.** Ollama silently truncates a prompt to its context
  length. A call is refused before it is sent if the proxy token count plus the
  output cap exceeds `num_ctx`, and flagged afterwards if the reported prompt
  token count shows the context was filled. Either way the record is
  `request_error` with reason `context_overflow` (fail-closed in review,
  `indeterminate (context_overflow)` in generation).
* **Logging.** Every record carries `weights_sha`, `precision`,
  `serving_stack` and `gpu_seconds` (prompt + eval duration x configured GPUs).
"""

import json
import re
import threading
import urllib.request

from .. import schema
from ..tokens import proxy_tokens

_LOCK = threading.Lock()
_VERIFIED = {}


class OllamaProbe:
    """Reads version, weights checksum and precision from an Ollama server."""

    def __init__(self, host):
        self.host = (host or "http://localhost:11434").rstrip("/")

    def version(self):
        with urllib.request.urlopen(self.host + "/api/version", timeout=10) as fh:
            return json.loads(fh.read().decode()).get("version")

    def facts(self, model):
        from ollama import Client

        client = Client(host=self.host)
        info = client.show(model)
        get = (lambda o, k: o.get(k)) if isinstance(info, dict) else getattr
        modelfile = get(info, "modelfile") or ""
        m = re.search(r"sha256[-:]([0-9a-f]{64})", modelfile)
        details = get(info, "details") or {}
        dget = (lambda o, k: o.get(k)) if isinstance(details, dict) else getattr
        return {
            "weights_sha": m.group(1) if m else None,
            "precision": dget(details, "quantization_level"),
        }


_probe_factory = OllamaProbe


def set_probe_factory(factory):
    """Tests replace the probe; production uses OllamaProbe."""
    global _probe_factory
    _probe_factory = factory
    _VERIFIED.clear()


def verify(spec, force=False):
    """Check the served weights against the pins. Returns the facts; raises on mismatch."""
    from . import PinViolation

    key = (spec.get("host"), spec["model"])
    with _LOCK:
        if not force and key in _VERIFIED:
            return _VERIFIED[key]
    probe = _probe_factory(spec.get("host"))
    facts = probe.facts(spec["model"])
    facts["serving_stack"] = f"ollama {probe.version()}"
    bad = []
    for k in ("weights_sha", "precision", "serving_stack"):
        if facts.get(k) != spec.get(k):
            bad.append(f"{k}: pinned {spec.get(k)!r}, served {facts.get(k)!r}")
    if bad:
        raise PinViolation(
            f"open-weight model {spec['model']!r} does not match its pins: " + "; ".join(bad)
        )
    with _LOCK:
        _VERIFIED[key] = facts
    return facts


def _chat(spec, prompt, cfg, contract):
    from . import _ollama

    return _ollama(spec, prompt, cfg, contract)


def call(spec, prompt, cfg, contract=schema.LEGACY):
    from . import ContextOverflow

    num_ctx = spec["num_ctx"]
    need = proxy_tokens(prompt) + cfg["max_tokens"]
    if need > num_ctx:
        raise ContextOverflow(
            f"prompt proxy {proxy_tokens(prompt)} + output cap {cfg['max_tokens']} > num_ctx {num_ctx}"
        )
    facts = verify(spec)
    payload, meta = _chat(spec, prompt, cfg, contract)
    durations = meta.pop("_durations_ns", None) or {}

    load_s = (durations.get("load_duration") or 0) / 1e9
    if load_s > spec.get("reload_threshold_s", 1.0):
        facts = verify(spec, force=True)  # the server (re)loaded the model

    used = meta.get("in_tokens")
    if isinstance(used, int) and used + cfg["max_tokens"] >= num_ctx:
        raise ContextOverflow(
            f"reported prompt tokens {used} + output cap {cfg['max_tokens']} reach num_ctx {num_ctx}"
        )

    busy_ns = (durations.get("prompt_eval_duration") or 0) + (durations.get("eval_duration") or 0)
    meta.update(
        weights_sha=facts.get("weights_sha"),
        precision=facts.get("precision"),
        serving_stack=facts.get("serving_stack"),
        gpu_seconds=round(busy_ns / 1e9 * float(spec.get("gpus", 1)), 6),
        load_seconds=round(load_s, 6),
    )
    return payload, meta


def verify_all(specs, force=True):
    """Start-of-run / end-of-run check over every open-weight model in use."""
    return {s["model"]: verify(s, force=force) for s in specs if s.get("provider") == "openweight"}
