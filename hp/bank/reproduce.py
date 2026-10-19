"""Stage 1: reproduce each CVE (section 7), and the timing pilot (Q19).

For each CVE, the vulnerable and the human-fixed version are each built once
and their test suite is run `design.reruns` (10) times, each run in a clean
state. A CVE is

* `build_fail`     if either version does not build;
* `suite_unstable` if any of its runs did not complete, or no test passes on
                   both versions in every run (provisional rule for v1.3 §7
                   step 6; PLAN.md section 10 item 1);
* `pov_unstable`   unless the PoV fails on the vulnerable version and passes on
                   the fixed version in every run, with one failure signature;
* `eligible`       otherwise.

Ordinary tests are the non-PoV tests that pass on both versions in all runs.
Tests that pass in some runs and fail in others are flaky: listed, excluded,
and not disqualifying on their own. Tests that fail consistently on one
version are listed as excluded. Ineligible CVEs stay in the log and the report.
"""

import time

from .vul4j import ApplyError, BuildError, signature_key


def status_for(runs_complete, pov_stable, ordinary):
    if not runs_complete or not ordinary:
        return "suite_unstable"
    if not pov_stable:
        return "pov_unstable"
    return "eligible"


def reproduce_cve(runner, cve, cluster, split_name, reruns, scope="full"):
    row = {
        "kind": "reproduction", "cve": cve, "cluster": cluster, "split": split_name,
        "status": None, "reason": None, "pov_tests": runner.pov_tests(cve), "signature": None,
        "ordinary_tests": [], "flaky_tests": [], "excluded_tests": [], "runs": {},
        "scope": scope, "runner": runner.describe(),
    }
    pov = set(row["pov_tests"])
    outcomes = {}
    complete = True
    for version in ("vulnerable", "fixed"):
        try:
            h = runner.prepare(cve, version)
        except (BuildError, ApplyError) as exc:   # ApplyError: the human patch did not apply
            row.update(status="build_fail", reason=f"{version}: {exc}"[:2000])
            return row
        try:
            runs = [runner.run_tests(h, scope=scope) for _ in range(reruns)]
        finally:
            runner.release(h)
        row["runs"][version] = [
            {"completed": r.completed, "wall_s": round(r.wall_s, 3),
             "pov": {t: r.outcome(t) for t in sorted(pov)}, "error": r.error}
            for r in runs
        ]
        complete = complete and all(r.completed for r in runs)
        outcomes[version] = runs

    # the PoV: fails on vulnerable, passes on fixed, every run, one signature
    vul, fix = outcomes["vulnerable"], outcomes["fixed"]
    pov_stable = bool(pov) and complete
    for t in pov:
        sigs = set()  # one stable signature PER PoV test (a CVE may have several)
        for r in vul:
            if r.outcome(t) not in ("fail", "error"):
                pov_stable = False
            sigs.add(signature_key(r.signature(t)))
        for r in fix:
            if r.outcome(t) != "pass":
                pov_stable = False
        if len(sigs) != 1 or None in sigs:
            pov_stable = False
    if pov_stable:
        row["signature"] = {t: vul[0].signature(t) for t in sorted(pov)}

    names = set()
    for r in vul + fix:
        names |= set(r.results)
    names -= pov
    for t in sorted(names):
        seen = [r.outcome(t) for r in vul + fix if r.completed]
        if seen and all(o == "pass" for o in seen):
            row["ordinary_tests"].append(t)
        elif any(o == "pass" for o in seen) and any(o != "pass" for o in seen) and (
            len({r.outcome(t) for r in vul}) > 1 or len({r.outcome(t) for r in fix}) > 1
        ):
            row["flaky_tests"].append(t)
        else:
            row["excluded_tests"].append(t)

    row["status"] = status_for(complete, pov_stable, row["ordinary_tests"])
    if row["status"] == "suite_unstable":
        row["reason"] = "incomplete run" if not complete else "no ordinary tests"
    elif row["status"] == "pov_unstable":
        row["reason"] = "PoV outcome or signature not stable across runs"
    return row


def timing_pilot(runner, cves, runs, reruns, scope="full"):
    """Wall-clock time per suite run, per CVE and version (Q19).

    `projected_stage1_s` = one build plus `reruns` suite runs at the mean time,
    for one version: what Stage 1 will cost for that CVE.
    """
    rows = []
    for cve in cves:
        for version in ("vulnerable", "fixed"):
            t0 = time.time()
            try:
                h = runner.prepare(cve, version)
            except BuildError as exc:
                rows.append({"cve": cve, "version": version, "build_s": round(time.time() - t0, 3),
                             "error": str(exc), "run_wall_s": []})
                continue
            build_s = time.time() - t0
            try:
                walls = [round(runner.run_tests(h, scope=scope).wall_s, 3) for _ in range(runs)]
            finally:
                runner.release(h)
            rows.append({"cve": cve, "version": version, "build_s": round(build_s, 3),
                         "run_wall_s": walls, "mean_run_s": round(sum(walls) / len(walls), 3),
                         "projected_stage1_s": round(build_s + reruns * sum(walls) / len(walls), 3)})
    return rows


def run(cfg, runner, runs_dir, cves=None, jobs=1):
    """Stage 1 for every CVE in the split (or `cves`) not yet reproduced.

    `jobs` CVEs are reproduced at once (each in its own containers); every row
    is logged the moment its CVE is done, so an interrupted run keeps them."""
    import threading

    from .. import logs
    from .parallel import run_items
    from .split import load_split

    split = load_split(cfg)
    done = {r["cve"] for r in logs.read(runs_dir / logs.FILES["reproduction"])}
    todo = [c for c in (cves or (split.cves("development") + split.cves("test"))) if c not in done]
    lock = threading.Lock()

    def one(cve):
        row = reproduce_cve(runner, cve, split.cluster_of[cve], split.split_of[cve],
                            cfg["design"]["reruns"], scope="full")
        with lock:
            logs.append(runs_dir / logs.FILES["reproduction"], [row])
        return row

    return run_items(todo, one, jobs, runner)
