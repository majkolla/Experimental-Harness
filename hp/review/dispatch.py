"""Stage 5: build the review inputs, schedule the calls, run them (section 11).

1. For every pair of the split, build e0 for V and for F (`review.input`) and
   scan it (`hp.leaks`). A pair whose V or F input overflows the cap
   (`review_input_overflow`) or trips the leak scan is excluded, V and F
   together, and logged in `inputs.jsonl` with the reason.
2. For the Experiment B CVEs (development only), build the three packets per
   candidate and log them too.
3. Build the crossed schedule (`review.schedule`) and dispatch it through the
   shared engine: admission keyed on the candidate, the four-attempt budget
   across resumes, pins checked, cost logged. One `reviews.jsonl` row per
   attempt; `verdict` is the reviewer's verdict string (approve / reject /
   abstain), `risk` its 0-100 score.

Test-split pairs are refused until the study is frozen.
"""

import pathlib

from .. import engine, leaks, logs, schema, synthworld
from ..bank import assemble, difftools
from ..bank.generate import advisory_for
from ..bank.split import assert_accessible
from . import packets as P
from . import schedule
from .input import build_review_input


def _blob(runs_dir, text):
    d = pathlib.Path(runs_dir) / "inputs"
    d.mkdir(parents=True, exist_ok=True)
    sha = difftools.sha(text)
    p = d / f"{sha}.txt"
    if not p.exists():
        p.write_text(text)
    return sha


def _post_files(runner, cve, diff):
    changed = difftools.changed_lines(diff)
    base = runner.read_files(cve, sorted(changed), "vulnerable")
    return difftools.apply(base, diff), changed


def prepare_inputs(cfg, runner, pairs, runs_dir, expb=False):
    """Build, scan and log every input. Returns (texts, excluded_pairs, expb_pairs)."""
    template = cfg["_prompts"]["review"]["text"]
    cap, ctx = cfg["caps"]["review_input_tokens"], cfg["caps"]["context_lines"]
    ids, terms = leaks.model_identity(cfg)
    logged = logs.latest((r for r in logs.read(runs_dir / logs.FILES["inputs"])),
                         lambda r: (r["candidate_id"], r["packet"]))
    texts, excluded, rows = {}, {}, []

    def log_row(p, state, packet, res, status, extra=None):
        key = (p["cand"][state], packet)
        prev = logged.get(key)
        if prev and prev["input_sha"] != res.get("sha256"):
            raise RuntimeError(f"review input for {key} changed since it was logged")
        if prev:
            return
        rows.append({"kind": "review_input", "candidate_id": p["cand"][state],
                     "pair_id": p["pair_id"], "state": state, "cve": p["cve"],
                     "split": p["split"], "packet": packet, "status": status,
                     "input_sha": res.get("sha256"), "proxy_tokens": res.get("proxy_tokens"),
                     "truncated_context": res.get("truncated_context"),
                     "context_method": res.get("context_method"),
                     "allowed_project_tokens": meta.get("allowed_project_tokens"),
                     **(extra or {})})

    ok_pairs = []
    for p in pairs:
        assert_accessible(cfg, p["cve"], "review")
        meta = runner.metadata(p["cve"])
        pats = leaks.patterns(meta, ids, terms)
        summary = advisory_for(cfg, p["cve"])["summary"]
        built, status = {}, "ok"
        for state in schedule.STATES:
            diff = p["v_diff"] if state == "V" else p["f_diff"]
            post, _ = _post_files(runner, p["cve"], diff)
            res = build_review_input(template, summary, diff, post, cap, ctx)
            if res["status"] == "ok":
                hits = leaks.find(res["text"], pats)
                if hits:
                    res = {**res, "status": "leak", "leak": sorted({h[0] for h in hits})}
            built[state] = res
            if res["status"] != "ok" and status == "ok":
                status = res["status"]
        for state in schedule.STATES:
            log_row(p, state, None, built[state], status,
                    {"leak": built[state].get("leak")} if built[state].get("leak") else None)
        if status != "ok":
            excluded[p["pair_id"]] = status
            continue
        ok_pairs.append(p)
        for state in schedule.STATES:
            texts[(p["cand"][state], None)] = built[state]["text"]
            _blob(runs_dir, built[state]["text"])

    expb_pairs = []
    if expb:
        chosen = set(schedule.expb_cves(cfg, ok_pairs))
        expb_pairs = [p for p in ok_pairs if p["cve"] in chosen and p["block"] == "core"]
        pcap = cfg["caps"]["packet_tokens"]
        for p in expb_pairs:
            meta = runner.metadata(p["cve"])
            pats = leaks.patterns(meta, ids, terms)
            summary = advisory_for(cfg, p["cve"])["summary"]
            listing = runner.list_files(p["cve"])
            main = runner.read_files(p["cve"], [f for f in listing if "/test/" not in f])
            tests = runner.read_files(p["cve"], [f for f in listing if "/test/" in f])
            for state in schedule.STATES:
                diff = p["v_diff"] if state == "V" else p["f_diff"]
                post, changed = _post_files(runner, p["cve"], diff)
                main_post = {**main, **post}
                classes = sorted({pathlib.PurePosixPath(f).stem for f in changed})
                note = ("Regression check for this patch: every ordinary test passed in the "
                        f"screening run and in {cfg['design']['reruns']} of "
                        f"{cfg['design']['reruns']} reruns.")
                for kind in cfg["experiment_b"]["packets"]:
                    if kind == "structure":
                        pk = P.build(kind, post_files=post, main_files=main_post, changed=changed,
                                     cap_tokens=pcap)
                    elif kind == "contracts":
                        pk = P.build(kind, post_files=post, main_files=main_post, changed=changed,
                                     cap_tokens=pcap)
                    else:
                        pk = P.build(kind, test_files=tests, pov_test_files=runner.pov_test_files(p["cve"]),
                                     changed_classes=classes, regression_note=note, cap_tokens=pcap)
                    res = build_review_input(template, summary, diff, post, cfg["caps"]["review_input_tokens"],
                                             cfg["caps"]["context_lines"], evidence=pk["text"])
                    status = res["status"]
                    if status == "ok" and leaks.find(res["text"], pats):
                        status = "leak"
                    log_row(p, state, kind, res, status,
                            {"packet_sha": pk["sha256"], "packet_tokens": pk["proxy_tokens"],
                             "packet_truncated": pk["truncated"], "packet_method": pk["method"]})
                    if status == "ok":
                        texts[(p["cand"][state], kind)] = res["text"]
                        _blob(runs_dir, res["text"])
    if rows:
        logs.append(runs_dir / logs.FILES["inputs"], rows)
    return texts, excluded, expb_pairs


def run(cfg, runner, split_name, runs_dir, blocks=("core", "extension"), expb=False, sleep=None):
    pairs = assemble.pairs(runs_dir, split_name)
    texts, excluded, _ = prepare_inputs(cfg, runner, pairs, runs_dir, expb=expb)
    ok_pairs = [p for p in pairs if p["pair_id"] not in excluded]
    calls = schedule.build(cfg, ok_pairs, split_name, blocks=blocks, expb=expb)
    calls = [c for c in calls if (c["candidate_id"], c["packet"]) in texts]
    world = synthworld.world_for(cfg) if cfg["mode"] == "synthetic" else None
    prov = engine.provenance(cfg, "review")

    def make_prompt(call):
        text = texts[(call["candidate_id"], call["packet"])]
        return text, difftools.sha(text)

    def make_row(call, rec, extra):
        m = cfg["models"][call["model_ref"]]
        return {
            **prov, "kind": "review", "call_id": call["call_id"],
            "candidate_id": call["candidate_id"], "pair_id": call["pair_id"],
            "state": call["state"], "cve": call["cve"], "cluster": call["cluster"],
            "split": call["split"], "generator": call["generator"], "reviewer": call["reviewer"],
            "block": call["block"], "packet": call["packet"], "trial": call["trial"],
            "model": m["model"], "snapshot": m.get("snapshot") or m.get("weights_sha"),
            "served_model": rec.get("served_model"), "input_sha": extra["input_sha"],
            "status": rec["status"], "attempt": rec["attempt"],
            "reason": rec.get("reason") or rec.get("schema_error") or rec.get("error"),
            "verdict": rec.get("decision"), "risk": rec.get("risk"),
            "justification_words": rec.get("justification_words"),
            "justification": (rec.get("verdict") or {}).get("justification"),
            "tokens": {"in": rec.get("in_tokens"), "out": rec.get("out_tokens")},
            "latency_s": rec.get("latency_s"), "cost": extra["cost"],
            "cost_sensitivity": extra["cost_sensitivity"], "seed": extra["seed"],
            **{k: rec.get(k) for k in ("weights_sha", "precision", "serving_stack", "gpu_seconds")},
        }

    summary = engine.run_calls(cfg, calls, runs_dir / logs.FILES["reviews"], "review",
                               schema.REVIEW_V13, make_prompt, make_row, "review",
                               world=world, sleep=sleep)
    summary["excluded_pairs"] = excluded
    return summary
