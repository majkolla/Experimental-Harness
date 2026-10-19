"""Classify each generation attempt into the six classes of section 8.

Per attempt (SPEC_ANSWERS Q14): apply and build ONCE, one screening run of the
full suite, then `design.reruns` (10) test reruns, each in a clean state.

| class             | rule                                                              |
|-------------------|-------------------------------------------------------------------|
| `apply_fail`      | no diff in the response, or the diff does not apply               |
| `build_fail`      | the patched project does not build                                |
| `regression_fail` | an ordinary test fails in the screening run                       |
| `blocked`         | ordinary tests pass and the PoV passes in every rerun             |
| `near_miss`       | ordinary tests pass, and the PoV fails with the ORIGINAL failure  |
|                   | signature in every rerun                                          |
| `indeterminate`   | anything else, with a reason: `inconsistent` (an outcome flips,   |
|                   | including an ordinary test failing inside the reruns),            |
|                   | `signature_mismatch`, `incomplete`, `context_overflow`, or        |
|                   | `generation_<status>` for a call that never produced output       |

Scope (Q19): `stage1.suite_scope` = `full` reruns the full suite;
`module_fallback` runs the full suite once (the screening run) and reruns the
PoV plus the affected module's ordinary tests. The scope is recorded per
attempt.
"""

from . import difftools
from .vul4j import ApplyError, BuildError, same_signature

CLASSES = ("apply_fail", "build_fail", "regression_fail", "blocked", "near_miss", "indeterminate")


def classify(runner, gen_row, repro_row, reruns, scope="full"):
    """Return the classification fields for one attempt (no I/O besides the runner)."""
    out = {"class": None, "reason": None, "rerun_results": [], "signature_match": None,
           "scope": scope, "diff_changed_lines": None, "similarity_to_human": None, "wall_s": 0.0}
    status = gen_row.get("status")
    if status != "ok":
        reason = gen_row.get("reason") or ""
        out.update({"class": "indeterminate",
                    "reason": "context_overflow" if "context_overflow" in str(reason)
                    else f"generation_{status}"})
        return out
    diff = gen_row.get("diff_text")
    if not diff:
        out.update({"class": "apply_fail", "reason": "no_diff"})
        return out
    try:
        out["diff_changed_lines"] = difftools.diff_size(diff)
        out["similarity_to_human"] = round(
            difftools.similarity(diff, runner.human_patch(gen_row["cve"])), 6)
    except difftools.DiffError:
        out.update({"class": "apply_fail", "reason": "malformed_diff"})
        return out

    cve = gen_row["cve"]
    try:
        h = runner.prepare(cve, "vulnerable", diff)
    except ApplyError as exc:
        out.update({"class": "apply_fail", "reason": str(exc)[:200]})
        return out
    except BuildError as exc:
        out.update({"class": "build_fail", "reason": str(exc)[:200]})
        return out

    try:
        ordinary = list(repro_row["ordinary_tests"])
        pov = list(repro_row["pov_tests"])
        original = repro_row["signature"] or {}

        screen = runner.run_tests(h, scope="full")
        out["wall_s"] += screen.wall_s
        if not screen.completed:
            out.update({"class": "indeterminate", "reason": "incomplete"})
            return out
        broken = [t for t in ordinary if screen.outcome(t) != "pass"]
        if broken:
            out.update({"class": "regression_fail", "reason": f"{len(broken)} ordinary test(s) fail",
                        "rerun_results": [{"run": 0, "ordinary_failures": broken[:10]}]})
            return out

        if scope == "module_fallback":
            module = set(runner.module_tests(cve) or ordinary)
            tests = pov + [t for t in ordinary if t in module]
        else:
            tests = None
        in_scope = ordinary if tests is None else [t for t in ordinary if t in set(tests)]

        pov_states, ord_fail, incomplete = [], False, False
        for i in range(1, reruns + 1):
            r = runner.run_tests(h, scope=scope, tests=tests)
            out["wall_s"] += r.wall_s
            if not r.completed:
                incomplete = True
                out["rerun_results"].append({"run": i, "completed": False})
                continue
            fails = [t for t in in_scope if r.outcome(t) != "pass"]
            ord_fail = ord_fail or bool(fails)
            state = []
            for t in pov:
                o = r.outcome(t)
                if o == "pass":
                    state.append("pass")
                elif same_signature(r.signature(t), original.get(t)):
                    state.append("fail_original")
                else:
                    state.append("fail_other")
            pov_states.append(tuple(state))
            out["rerun_results"].append({"run": i, "pov": state, "ordinary_failures": fails[:10]})
    finally:
        runner.release(h)
    out["wall_s"] = round(out["wall_s"], 3)

    if incomplete:
        out.update({"class": "indeterminate", "reason": "incomplete"})
    elif ord_fail:
        out.update({"class": "indeterminate", "reason": "inconsistent"})
    elif all(all(s == "pass" for s in st) for st in pov_states):
        out.update({"class": "blocked"})
    elif all(all(s == "fail_original" for s in st) for st in pov_states):
        out.update({"class": "near_miss", "signature_match": True})
    elif all(all(s != "pass" for s in st) for st in pov_states):
        out.update({"class": "indeterminate", "reason": "signature_mismatch",
                    "signature_match": False})
    else:
        out.update({"class": "indeterminate", "reason": "inconsistent"})
    return out


def run(cfg, runner, split_name, runs_dir, jobs=1):
    """Classify every generated attempt of a split that is not classified yet.

    `jobs` attempts are classified at once (each in its own containers); every
    row is logged the moment its attempt is done, so an interrupted run keeps
    them. Rows are returned in attempt order whatever the completion order."""
    import threading

    from .. import logs
    from .parallel import run_items

    repro = logs.latest((r for r in logs.read(runs_dir / logs.FILES["reproduction"])), "cve")
    rows = list(logs.read(runs_dir / logs.FILES["attempts"]))
    gens = logs.latest((r for r in rows if r["kind"] == "generation" and r["split"] == split_name),
                       "attempt_id")
    done = {r["attempt_id"] for r in rows if r["kind"] == "classification"}
    todo = []
    for aid in sorted(gens):
        if aid in done:
            continue
        g = gens[aid]
        if g["status"] in ("timeout", "transport_error") and g["call_attempt"] < cfg["max_attempts"]:
            continue  # still open: a resume may complete it
        todo.append(aid)
    lock = threading.Lock()

    def one(aid):
        g = gens[aid]
        res = classify(runner, g, repro[g["cve"]], cfg["design"]["reruns"],
                       cfg["stage1"]["suite_scope"])
        row = {"kind": "classification", "attempt_id": aid, "cve": g["cve"],
               "cluster": g["cluster"], "split": g["split"], "generator": g["generator"],
               "block": g["block"], "diff_sha": g["diff_sha"], **res}
        with lock:
            logs.append(runs_dir / logs.FILES["attempts"], [row])
        return row

    return run_items(todo, one, jobs, runner)
