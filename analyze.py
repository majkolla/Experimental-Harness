#!/usr/bin/env python3
"""Analyse a frozen log.

    python analyze.py experiment.json
    python analyze.py experiment.json --json runs/pilot-01.analysis.json
    python analyze.py experiment.json --abstain-as-approval   # sensitivity coding

The gate rule lives in the config and is applied here, in analysis, never in
the harness: a reviewer told "two of three merges this" is answering a
different question.
"""

import sys

from hp import report

if __name__ == "__main__":
    report.main()
    sys.exit(0)
