"""Stage 2: generate repairs (section 8).

Generator input, identical for every generator: the advisory (CWE and a
neutral summary, no CVE id), the full current content of the files the human
patch changes, and the instruction to output one unified diff. This is
perfect fault localisation. The PoV test, its name and its output never enter
the input: `generation_input` has no parameter through which they could
arrive, and the built text is scanned (`hp.leaks`) before dispatch.

Ten fresh calls per (CVE, generator), at the configured generation sampling
settings; core generators A, B, C, plus X, Y, Z when the extension is on.
Test-split CVEs are refused until the study is frozen.
"""

import hashlib
import json

from .. import engine, leaks, schema, study_config as S, synthworld
from . import difftools
from .split import assert_accessible, load_split


def generation_input(template, advisory, files):
    """The *only* builder of generator input. No PoV parameter exists."""
    adv = f"Weakness class: {advisory['cwe']}\n\n{advisory['summary']}"
    parts = []
    for path in sorted(files):
        parts.append(f"### {path}\n\n```java\n{files[path].rstrip()}\n```")
    return template.replace("{{ADVISORY}}", adv).replace("{{FILES}}", "\n\n".join(parts))


def advisory_for(cfg, cve):
    if cfg["mode"] == "synthetic":
        return synthworld.world_for(cfg).cves[cve]["advisory"]
    p = cfg["_root"] / cfg["paths"]["inputs"] / "advisories" / f"{cve}.json"
    if not p.is_file():
        raise FileNotFoundError(f"advisory for {cve} missing: {p} (author-written, section 8)")
    adv = json.loads(p.read_text())
    if cfg["mode"] == "live" and adv.get("status") == "draft":
        raise ValueError(f"advisory for {cve} is still a draft: review it and remove "
                         "\"status\" (docs/advisories_review.md)")
    return adv


def generators(cfg):
    gens = list(S.CORE_GENERATORS)
    if cfg["extension"]["enabled"]:
        gens += list(S.OPEN_MODELS)
    return gens


def block_of(generator, reviewer=None):
    core = generator in S.CORE_GENERATORS and (reviewer is None or reviewer in S.CORE_REVIEWERS)
    return "core" if core else "extension"


def build_calls(cfg, cves):
    split = load_split(cfg)
    k = cfg["design"]["attempts_per_cell"]
    calls = []
    for cve in cves:
        assert_accessible(cfg, cve, "generation")
        for g in generators(cfg):
            for j in range(k):
                cid = f"gen|{cve}|{g}|{j:02d}"
                calls.append({
                    "call_id": cid, "attempt_id": cid, "panel_key": cid, "model_ref": g,
                    "cve": cve, "cluster": split.cluster_of[cve], "split": split.split_of[cve],
                    "generator": g, "block": block_of(g),
                    "_context": {"cve": cve, "generator": g, "attempt": j},
                })
    return calls


def run(cfg, runner, split_name, log_path, sleep=None):
    """Generate every attempt for the eligible CVEs of one split."""
    from .. import logs

    repro = logs.latest(
        (r for r in logs.read(log_path.parent / logs.FILES["reproduction"])
         if r.get("kind") == "reproduction"), "cve")
    split = load_split(cfg)
    cves = [c for c in split.cves(split_name) if repro.get(c, {}).get("status") == "eligible"]
    calls = build_calls(cfg, cves)
    template = cfg["_prompts"]["generate"]["text"]
    cache = {}

    def make_prompt(call):
        cve = call["cve"]
        if cve not in cache:
            files = runner.read_files(cve, runner.human_files(cve))
            text = generation_input(template, advisory_for(cfg, cve), files)
            leaks.scan(text, leaks.oracle_patterns(runner.metadata(cve)))
            cache[cve] = (text, hashlib.sha256(text.encode()).hexdigest())
        return cache[cve]

    world = synthworld.world_for(cfg) if cfg["mode"] == "synthetic" else None
    prov = engine.provenance(cfg, "generate")
    settings = engine.call_settings(cfg, "generation")

    def make_row(call, rec, extra):
        m = cfg["models"][call["model_ref"]]
        diff = difftools.extract_diff(rec.get("text")) if rec["status"] == schema.OK else None
        return {
            **prov, "kind": "generation", "attempt_id": call["attempt_id"],
            "cve": call["cve"], "cluster": call["cluster"], "split": call["split"],
            "generator": call["generator"], "block": call["block"], "model": m["model"],
            "snapshot": m.get("snapshot") or m.get("weights_sha"),
            "served_model": rec.get("served_model"), "input_sha": extra["input_sha"],
            "temperature": settings["temperature"], "top_p": settings["top_p"],
            "seed": extra["seed"], "status": rec["status"], "call_attempt": rec["attempt"],
            "reason": rec.get("reason") or rec.get("schema_error") or rec.get("error"),
            "diff_text": diff, "diff_sha": difftools.sha(diff) if diff else None,
            "tokens": {"in": rec.get("in_tokens"), "out": rec.get("out_tokens")},
            "latency_s": rec.get("latency_s"), "cost": extra["cost"],
            "cost_sensitivity": extra["cost_sensitivity"],
            **{k: rec.get(k) for k in ("weights_sha", "precision", "serving_stack", "gpu_seconds")},
        }

    return engine.run_calls(cfg, calls, log_path, "generation", schema.TEXT, make_prompt,
                            make_row, "generation", world=world, sleep=sleep)
