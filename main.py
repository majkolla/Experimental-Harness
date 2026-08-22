#!/usr/bin/env python3
"""Run (or resume) an experiment.

    python main.py experiment.json --dry-run     # cost + balance, spends nothing
    python main.py experiment.json               # run / resume
    python main.py experiment.json --limit 24    # pilot slice

Resume is safe and idempotent: only calls that reached a schema-valid verdict
are skipped. Failed attempts stay in the log as evidence and are retried.
"""

import argparse
import sys

from hp import runner


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("config", nargs="?", default="experiment.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate config, build and check the design, print cost, exit")
    ap.add_argument("--limit", type=int, default=None,
                    help="dispatch at most N calls this invocation")
    a = ap.parse_args(argv)
    runner.run(a.config, dry_run=a.dry_run, limit=a.limit)


if __name__ == "__main__":
    sys.exit(main())
