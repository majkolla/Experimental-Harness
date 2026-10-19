"""Fill in the open-weight pins of a config from the Ollama server that serves them.

`python study.py pin CONFIG [--write]` asks the Ollama server, for every
model with provider "openweight", for the weights checksum (SHA-256 of the
weights blob), the quantisation level and the server version, and prints them.
With --write it puts them into the config file in place (comments and layout
are kept; only the three values of each model change). The values are what
`hp.providers.openweight.verify` compares on every run, so a model that is
re-pulled, re-quantised or served by another Ollama version stops the run.

Pins are facts read from the server, never typed by hand. Run this on the
machine (or against the host) that will serve the study, after `ollama pull`.
"""

import json
import pathlib
import re

from . import study_config as S

PIN_KEYS = ("weights_sha", "precision", "serving_stack")


def read_config(path):
    text = pathlib.Path(path).read_text()
    return text, S.parse_jsonc(text)


def facts_for(models, probe_factory=None):
    """{ref: {weights_sha, precision, serving_stack}} for every open-weight model."""
    from .providers import openweight

    factory = probe_factory or openweight.OllamaProbe
    out = {}
    for ref, m in sorted(models.items()):
        if m.get("provider") != "openweight":
            continue
        probe = factory(m.get("host"))
        f = probe.facts(m["model"])
        f["serving_stack"] = f"ollama {probe.version()}"
        if not f.get("weights_sha"):
            raise RuntimeError(f"{ref}: no weights checksum for {m['model']!r}; is it pulled?")
        out[ref] = {k: f.get(k) for k in PIN_KEYS}
    return out


def _object_span(text, start):
    """(begin, end) of the JSON object whose '{' is at or after `start`; skips
    strings and // or /* */ comments."""
    i = text.index("{", start)
    depth, j, n = 0, i, len(text)
    in_str = esc = False
    while j < n:
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif text.startswith("//", j):
            j = text.find("\n", j)
            j = n if j == -1 else j
            continue
        elif text.startswith("/*", j):
            j = text.find("*/", j + 2) + 2
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i, j + 1
        j += 1
    raise ValueError("unbalanced braces in config")


def write_pins(text, pins):
    """Return `text` with each model's pin values replaced (layout and comments kept)."""
    models_at = re.search(r'"models"\s*:\s*\{', text)
    if not models_at:
        raise ValueError("no models block")
    m_begin, m_end = _object_span(text, models_at.start())
    block = text[m_begin:m_end]
    for ref, values in pins.items():
        key = re.search(r'"%s"\s*:\s*\{' % re.escape(ref), block)
        if not key:
            raise ValueError(f"model {ref} not found in the models block")
        b, e = _object_span(block, key.start())
        obj = block[b:e]
        for k, v in values.items():
            pat = re.compile(r'("%s"\s*:\s*)("(?:[^"\\]|\\.)*"|null)' % re.escape(k))
            if not pat.search(obj):
                raise ValueError(f"models.{ref}.{k} not found; add the key first")
            obj = pat.sub(lambda mm: mm.group(1) + json.dumps(v), obj, count=1)
        block = block[:b] + obj + block[e:]
    return text[:m_begin] + block + text[m_end:]


def vul4j_digest(image, run=None):
    """(pin, pin_kind) of the local Vul4J image: its registry digest ('repo_digest')
    when it was pulled from a registry, else its image id ('image_id') for an image
    built locally (setup.sh builds it from the pinned Vul4J commit)."""
    import subprocess

    run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True))
    p = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}|{{.Id}}", image])
    if p.returncode:
        raise RuntimeError(f"docker image inspect {image} failed: {p.stderr.strip()} "
                           "(build or pull the image first: scripts/azure/setup.sh)")
    raw = (p.stdout or "").strip()
    digests_raw, _, image_id = raw.partition("|")
    digests = json.loads(digests_raw or "[]")
    repo = image.split("@")[0].rsplit(":", 1)[0] if "/" in image or ":" in image else image
    for d in digests:
        if d.split("@")[0] == repo and "@sha256:" in d:
            return d.split("@", 1)[1], "repo_digest"
    if image_id.startswith("sha256:"):
        return image_id, "image_id"
    raise RuntimeError(f"no digest or image id for {image}: {raw}")


def write_vul4j_pin(text, digest, kind):
    at = re.search(r'"vul4j"\s*:\s*\{', text)
    if not at:
        raise ValueError("no vul4j block")
    b, e = _object_span(text, at.start())
    obj = text[b:e]
    for key, value in (("image_digest", digest), ("pin_kind", kind)):
        pat = re.compile(r'("%s"\s*:\s*)("(?:[^"\\]|\\.)*"|null)' % key)
        if pat.search(obj):
            obj = pat.sub(lambda mm: mm.group(1) + json.dumps(value), obj, count=1)
        elif key == "pin_kind":
            obj = obj[:-1].rstrip() + f',\n            "pin_kind": {json.dumps(value)}}}'
        else:
            raise ValueError(f"vul4j.{key} not found")
    return text[:b] + obj + text[e:]


def run(path, write=False, probe_factory=None, docker_run=None, vul4j=True):
    """Pins of every open-weight model, plus the Vul4J image digest."""
    text, cfg = read_config(path)
    pins = facts_for(cfg["models"], probe_factory)
    digest = kind = None
    v = cfg.get("vul4j") or {}
    if vul4j and v.get("runner") == "container":
        digest, kind = vul4j_digest(v["image"], docker_run)
    if write:
        new = write_pins(text, pins)
        if digest:
            new = write_vul4j_pin(new, digest, kind)
        assert S.parse_jsonc(new)  # still valid JSONC
        pathlib.Path(path).write_text(new)
    return pins, (digest, kind) if digest else None
