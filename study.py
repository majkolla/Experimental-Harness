#!/usr/bin/env python3
"""Command line for the v1.3 study (Experiment Specification v1.3).

    python study.py validate      study.jsonc
    python study.py timing-pilot  study.jsonc --cves VUL4J-51,VUL4J-15,VUL4J-3 --runs 3
    python study.py reproduce     study.jsonc                 # Stage 1, all 79 CVEs
    python study.py generate      study.jsonc --split development
    python study.py classify      study.jsonc --split development
    python study.py select        study.jsonc --split development
    python study.py sibling       study.jsonc --split development
    python study.py bank          study.jsonc --split development
    python study.py review        study.jsonc --split development [--expb] [--blocks core,extension]
    python study.py analyse-dev   study.jsonc                 # thresholds, policies, regret, promotion
    python study.py freeze        study.jsonc                 # opens the test split
    python study.py confirm       study.jsonc                 # test-set inference and the report
    python study.py selftest      [--full] [--dir DIR]        # whole pipeline offline, synthetic
    python study.py audit-logs    study.jsonc                 # every row against its schema
    python study.py pin           study.rehearsal.jsonc --write   # pins from Ollama and Docker
    python study.py vul4j-check   study.rehearsal.jsonc --cve VUL4J-12   # one-CVE image smoke test

Modes: `synthetic` (offline, mock Vul4J), `rehearsal` (real container and real
models, every slot an open-weight stand-in, development split only, never
frozen) and `live` (the study).

Every command validates the config first (a live config refuses to run while
any pin is still a placeholder) and appends to the logs under `paths.runs`.
Test-split generation, correction and review are refused until `freeze`.
The legacy Experiment 1 entry points (main.py, analyze.py) are unchanged.
"""

import argparse
import json
import sys

from hp import logs, study_config as S


def _cfg(a):
    cfg = S.load(a.config)
    rd = S.runs_dir(cfg)
    rd.mkdir(parents=True, exist_ok=True)
    return cfg, rd


def cmd_validate(a):
    cfg = S.load(a.config)
    print(f"{a.config}: valid ({cfg['mode']}), config sha256 {cfg['_config_sha256']}")
    print(f"freeze: {S.freeze_status(cfg)[1]}")


def cmd_timing_pilot(a):
    from hp.bank import reproduce, vul4j

    cfg, rd = _cfg(a)
    from hp.bank.split import load_split

    cves = [c.strip() for c in a.cves.split(",") if c.strip()]
    known = load_split(cfg).split_of
    unknown = [c for c in cves if c not in known]
    if unknown:
        raise SystemExit(f"not in the active split: {unknown} (synthetic runs use a subset)")
    with vul4j.runner_for(cfg) as runner:
        rows = reproduce.timing_pilot(runner, cves, a.runs, cfg["design"]["reruns"],
                                      scope=a.scope or cfg["stage1"]["suite_scope"])
    print(f"{'cve':<10}{'version':<12}{'build_s':>9}{'mean_run_s':>12}{'stage1_s':>11}  runs")
    for r in rows:
        print(f"{r['cve']:<10}{r['version']:<12}{r['build_s']:>9}{r.get('mean_run_s', 'n/a'):>12}"
              f"{r.get('projected_stage1_s', 'n/a'):>11}  {r['run_wall_s']}")
    (rd / "timing_pilot.json").write_text(json.dumps(rows, indent=2))


def cmd_reproduce(a):
    from collections import Counter

    from hp.bank import reproduce, vul4j

    cfg, rd = _cfg(a)
    with vul4j.runner_for(cfg) as runner:
        rows = reproduce.run(cfg, runner, rd, cves=a.cves.split(",") if a.cves else None,
                             jobs=a.jobs)
    print(f"reproduced {len(rows)} CVEs: {dict(Counter(r['status'] for r in rows))}")


def cmd_generate(a):
    from hp.bank import generate, vul4j

    cfg, rd = _cfg(a)
    with vul4j.runner_for(cfg) as runner:
        print(generate.run(cfg, runner, a.split, rd / logs.FILES["attempts"]))


def cmd_classify(a):
    from collections import Counter

    from hp.bank import classify, vul4j

    cfg, rd = _cfg(a)
    with vul4j.runner_for(cfg) as runner:
        rows = classify.run(cfg, runner, a.split, rd, jobs=a.jobs)
    print(f"classified {len(rows)} attempts: {dict(Counter(r['class'] for r in rows))}")


def cmd_select(a):
    from hp.bank import select

    cfg, rd = _cfg(a)
    rows = select.run(cfg, a.split, rd)
    print(f"selected {len(rows)} cells")


def cmd_sibling(a):
    from collections import Counter

    from hp.bank import sibling, vul4j

    cfg, rd = _cfg(a)
    with vul4j.runner_for(cfg) as runner:
        rows = sibling.run(cfg, runner, a.split, rd)
    print(dict(Counter(r.get("status") or r["kind"] for r in rows)))


def cmd_bank(a):
    from collections import Counter

    from hp.bank import assemble

    cfg, rd = _cfg(a)
    pairs = assemble.pairs(rd, a.split)
    print(f"{len(pairs)} pairs in the {a.split} bank: "
          f"{dict(Counter((p['block'], p['generator']) for p in pairs))}")


def cmd_review(a):
    from hp.bank import vul4j
    from hp.review import dispatch

    cfg, rd = _cfg(a)
    blocks = tuple(b for b in a.blocks.split(",") if b)
    if not cfg["extension"]["enabled"]:
        blocks = tuple(b for b in blocks if b != "extension")
    with vul4j.runner_for(cfg) as runner:
        s = dispatch.run(cfg, runner, a.split, rd, blocks=blocks, expb=a.expb)
    print({k: v for k, v in s.items() if k != "excluded_pairs"})
    if s["excluded_pairs"]:
        print(f"excluded pairs (V and F together): {s['excluded_pairs']}")


def cmd_analyse_dev(a):
    from hp.analysis import report

    cfg, rd = _cfg(a)
    report.analyse_dev(cfg, rd)
    print((rd / "dev_report.txt").read_text())


def cmd_freeze(a):
    rec = S.freeze(a.config, ["thresholds.json", "primary_choice.json"])
    print(f"frozen: config {rec['config_sha256']}, code {rec['code_sha256']}")
    for k, v in rec["artefacts"].items():
        print(f"  {k}: {v}")


def cmd_confirm(a):
    from hp.analysis import report

    cfg, rd = _cfg(a)
    if cfg["mode"] == "rehearsal":
        raise SystemExit("confirm is refused in rehearsal mode: a rehearsal never opens "
                         "the test split (the synthetic selftest exercises confirm)")
    report.confirm(cfg, rd)
    print((rd / "test_report.txt").read_text())


def cmd_pin(a):
    """Read the pins from the serving host: open weights from Ollama, the Vul4J image
    digest from Docker. Facts, never typed by hand."""
    from hp import pins

    got, digest = pins.run(a.config, write=a.write, vul4j=not a.no_vul4j)
    for ref, v in got.items():
        print(f"{ref}: {v['weights_sha']}  {v['precision']}  {v['serving_stack']}")
    if digest:
        print(f"vul4j image: {digest[0]} ({digest[1]})")
    print("written to " + a.config if a.write else "(dry run; add --write to put these in the config)")


def cmd_vul4j_check(a):
    """Smoke test of the pinned Vul4J image on one CVE: checkout, metadata, build
    both versions, one full test run each. Writes nothing to the study logs."""
    import time

    from hp.bank import vul4j

    import pathlib

    path = pathlib.Path(a.config).resolve()
    cfg = S.parse_jsonc(path.read_text())   # model pins are irrelevant here
    cfg["_root"] = path.parent
    if cfg["vul4j"].get("runner") != "container" or "TO_PIN" in str(cfg["vul4j"].get("image_digest")):
        raise SystemExit("vul4j-check needs vul4j.runner 'container' and a pinned image_digest "
                         "(python study.py pin CONFIG --write)")
    cve = a.cve
    with vul4j.runner_for(cfg) as r:
        prov = r.provenance(cfg["vul4j"].get("source_commit"))
        print(f"image: {r.image}  /vul4j HEAD {prov['head']}  "
              f"built from {cfg['vul4j'].get('source_commit')}: {prov['commit_ok']}  "
              f"warm-up ran: {prov['warmup_ran']}")
        if prov["warmup_failed"]:
            print(f"  the image build could not reproduce: {', '.join(prov['warmup_failed'])}")
        t0 = time.time()
        meta = r.metadata(cve)
        print(f"{cve}: cluster {meta['cluster']}, PoV {meta['pov_tests']}")
        print(f"  human files: {r.human_files(cve)}")
        print(f"  PoV test files: {r.pov_test_files(cve)}")
        print(f"  human patch: {len(r.human_patch(cve).splitlines())} diff lines")
        ok = True
        for version, want in (("vulnerable", "fail"), ("fixed", "pass")):
            t1 = time.time()
            h = r.prepare(cve, version)
            build_s = time.time() - t1
            try:
                run = r.run_tests(h, scope="full")
            finally:
                r.release(h)
            if not run.completed:
                print(f"  {version}: test run did not complete: {run.error}")
                ok = False
                continue
            outs = {t: run.outcome(t) for t in meta["pov_tests"]}
            good = all((o in ("fail", "error")) if want == "fail" else o == "pass" for o in outs.values())
            ok = ok and good and bool(outs)
            print(f"  {version}: build {build_s:.0f} s, tests {run.wall_s:.0f} s, "
                  f"{len(run.results)} tests, PoV {outs} -> {'as expected' if good else 'UNEXPECTED'}")
            for t in meta["pov_tests"]:
                if run.signature(t):
                    print(f"    signature {t}: {run.signature(t)}")
        print(f"  total {time.time() - t0:.0f} s: {'OK' if ok else 'PROBLEM'}")
    if not ok:
        raise SystemExit(1)


def cmd_selftest(a):
    import pathlib
    import shutil
    import tempfile

    from hp import study_config
    from hp.analysis import report
    from hp.bank import classify, generate, reproduce, select, sibling, vul4j
    from hp.review import dispatch

    root = pathlib.Path(__file__).resolve().parent
    d = pathlib.Path(a.dir or tempfile.mkdtemp(prefix="study-selftest-"))
    d.mkdir(parents=True, exist_ok=True)
    for name in ("study.synthetic.jsonc", "study.py"):
        shutil.copy(root / name, d / name)
    for name in ("prompts", "hp"):
        shutil.copytree(root / name, d / name, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__"))
    (d / "docs" / "spec").mkdir(parents=True, exist_ok=True)
    shutil.copy(root / "docs" / "spec" / "proposed_split.json", d / "docs" / "spec")
    cfg_path = d / "study.synthetic.jsonc"
    if a.full:
        text = cfg_path.read_text().replace(
            '"cve_limit": {"development": 8, "test": 12}', '"cve_limit": null')
        cfg_path.write_text(text)
    cfg = study_config.load(cfg_path)
    rd = study_config.runs_dir(cfg)
    rd.mkdir(parents=True, exist_ok=True)
    runner = vul4j.runner_for(cfg)
    reproduce.run(cfg, runner, rd)
    for split_name in ("development", "test"):
        if split_name == "test":
            report.analyse_dev(cfg, rd)
            study_config.freeze(cfg_path, ["thresholds.json", "primary_choice.json"])
            cfg = study_config.load(cfg_path)
            runner = vul4j.runner_for(cfg)
        generate.run(cfg, runner, split_name, rd / logs.FILES["attempts"])
        classify.run(cfg, runner, split_name, rd)
        select.run(cfg, split_name, rd)
        sibling.run(cfg, runner, split_name, rd)
        dispatch.run(cfg, runner, split_name, rd, expb=(split_name == "development"))
    report.confirm(cfg, rd)
    print((rd / "dev_report.txt").read_text())
    print((rd / "test_report.txt").read_text())
    print(f"self-test directory: {d}")


def cmd_audit_logs(a):
    cfg, rd = _cfg(a)
    for fname, counts in logs.audit(rd).items():
        print(f"{fname:<20} {counts}")
    print("every row has every required field")


COMMANDS = {
    "validate": cmd_validate,
    "timing-pilot": cmd_timing_pilot,
    "reproduce": cmd_reproduce,
    "generate": cmd_generate,
    "classify": cmd_classify,
    "select": cmd_select,
    "sibling": cmd_sibling,
    "bank": cmd_bank,
    "review": cmd_review,
    "analyse-dev": cmd_analyse_dev,
    "freeze": cmd_freeze,
    "confirm": cmd_confirm,
    "selftest": cmd_selftest,
    "audit-logs": cmd_audit_logs,
    "pin": cmd_pin,
    "vul4j-check": cmd_vul4j_check,
}


def parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        p = sub.add_parser(name)
        if name == "selftest":
            p.add_argument("--full", action="store_true", help="every CVE of the split")
            p.add_argument("--dir", default=None, help="where to run (default: a new temp dir)")
            continue
        p.add_argument("config")
        if name in ("generate", "classify", "select", "sibling", "bank", "review"):
            p.add_argument("--split", choices=("development", "test"), required=True)
        if name == "review":
            p.add_argument("--blocks", default="core,extension")
            p.add_argument("--expb", action="store_true", help="also Experiment B (development only)")
        if name == "reproduce":
            p.add_argument("--cves", default=None, help="comma-separated subset")
        if name in ("reproduce", "classify"):
            p.add_argument("--jobs", type=int, default=1,
                           help="CVEs / attempts processed at once, each in its own containers")
        if name == "pin":
            p.add_argument("--write", action="store_true", help="write the pins into the config")
            p.add_argument("--no-vul4j", action="store_true", help="open weights only")
        if name == "vul4j-check":
            p.add_argument("--cve", default="VUL4J-12", help="one CVE (default: a small one)")
        if name == "timing-pilot":
            p.add_argument("--cves", required=True, help="comma-separated CVE ids")
            p.add_argument("--runs", type=int, default=3)
            p.add_argument("--scope", choices=S.SUITE_SCOPES, default=None)
    return ap


def main(argv=None):
    from hp.bank.split import SplitLockError

    a = parser().parse_args(argv)
    try:
        COMMANDS[a.command](a)
    except S.ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except SplitLockError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
