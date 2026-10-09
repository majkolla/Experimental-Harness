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
    runner = vul4j.runner_for(cfg)
    from hp.bank.split import load_split

    cves = [c.strip() for c in a.cves.split(",") if c.strip()]
    known = load_split(cfg).split_of
    unknown = [c for c in cves if c not in known]
    if unknown:
        raise SystemExit(f"not in the active split: {unknown} (synthetic runs use a subset)")
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
    rows = reproduce.run(cfg, vul4j.runner_for(cfg), rd,
                         cves=a.cves.split(",") if a.cves else None)
    print(f"reproduced {len(rows)} CVEs: {dict(Counter(r['status'] for r in rows))}")


def cmd_generate(a):
    from hp.bank import generate, vul4j

    cfg, rd = _cfg(a)
    print(generate.run(cfg, vul4j.runner_for(cfg), a.split, rd / logs.FILES["attempts"]))


def cmd_classify(a):
    from collections import Counter

    from hp.bank import classify, vul4j

    cfg, rd = _cfg(a)
    rows = classify.run(cfg, vul4j.runner_for(cfg), a.split, rd)
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
    rows = sibling.run(cfg, vul4j.runner_for(cfg), a.split, rd)
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
    s = dispatch.run(cfg, vul4j.runner_for(cfg), a.split, rd, blocks=blocks, expb=a.expb)
    print({k: v for k, v in s.items() if k != "excluded_pairs"})
    if s["excluded_pairs"]:
        print(f"excluded pairs (V and F together): {s['excluded_pairs']}")


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
}


def parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        p = sub.add_parser(name)
        p.add_argument("config")
        if name in ("generate", "classify", "select", "sibling", "bank", "review"):
            p.add_argument("--split", choices=("development", "test"), required=True)
        if name == "review":
            p.add_argument("--blocks", default="core,extension")
            p.add_argument("--expb", action="store_true", help="also Experiment B (development only)")
        if name == "reproduce":
            p.add_argument("--cves", default=None, help="comma-separated subset")
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
