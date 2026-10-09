"""The study's logs: append-only JSONL, one file per stage, and their row schemas.

Every number the study reports is recomputed from these files (plus the
config and the registered split). Nothing ever rewrites a line: a later row for
the same key supersedes an earlier one (a resumed call, a re-ingested
sibling), and readers take the last.

| file                | one row per                                   | spec            |
|---------------------|-----------------------------------------------|-----------------|
| reproduction.jsonl  | CVE (Stage 1)                                 | §7, Q18         |
| attempts.jsonl      | generation call attempt, then classification  | §8, §18.3       |
| selection.jsonl     | selected (CVE, generator) cell                | §10, Q18        |
| siblings.jsonl      | twin F of a selected V, or the stopping point | §9, Q18         |
| inputs.jsonl        | built review input (e0 or e0 + packet)        | §11.1, §13      |
| reviews.jsonl       | review call attempt                           | §11, §18.3      |
| freeze.json         | the freeze record (not JSONL)                 | §19, Q18        |

`inputs.jsonl` goes beyond the Q18 list: it is what records a pair that was
not reviewed because its diff exceeds the input cap (`review_input_overflow`),
so that exclusion is recomputable too.

Section 18.3 fields and where they live:

* attempts.jsonl holds two row kinds joined on `attempt_id`: `generation`
  (attempt_id, cve, cluster, generator, snapshot, prompt_sha, temperature,
  seed, diff_sha, tokens, cost, plus the call's status and attempt counter
  `call_attempt`) and `classification` (class, rerun_results,
  signature_match, similarity_to_human, plus reason, scope, patch size).
* reviews.jsonl: every 18.3 field; `latency` is logged as `latency_s`,
  `verdict` is the reviewer's verdict string, `attempt` the operational retry
  counter. Extension fields (`weights_sha`, `precision`, `serving_stack`,
  `gpu_seconds`, `cost_sensitivity`) are present on every row and null for
  commercial models.
* `seed` is the derived per-call seed of the harness (retry jitter,
  synthetic draws); providers' own sampling is not seeded.
"""

import json
import pathlib
import sys
import threading

FILES = {
    "reproduction": "reproduction.jsonl",
    "attempts": "attempts.jsonl",
    "selection": "selection.jsonl",
    "siblings": "siblings.jsonl",
    "inputs": "inputs.jsonl",
    "reviews": "reviews.jsonl",
}

#: Fields every row of a kind must carry (value may be null). Section 18.3
#: fields first, then the fields added by v1.3 / SPEC_ANSWERS.
REQUIRED = {
    "reproduction": (
        "kind", "cve", "cluster", "split", "status", "reason", "pov_tests", "signature",
        "ordinary_tests", "flaky_tests", "excluded_tests", "runs", "scope", "runner",
    ),
    "generation": (
        # section 18.3
        "attempt_id", "cve", "cluster", "generator", "snapshot", "prompt_sha", "temperature",
        "seed", "diff_sha", "tokens", "cost",
        # added
        "kind", "split", "block", "model", "served_model", "input_sha", "top_p", "status",
        "call_attempt", "reason", "diff_text", "latency_s",
        "weights_sha", "precision", "serving_stack", "gpu_seconds", "cost_sensitivity",
    ),
    "classification": (
        # section 18.3
        "attempt_id", "cve", "cluster", "generator", "class", "rerun_results",
        "signature_match", "similarity_to_human",
        # added
        "kind", "split", "block", "reason", "scope", "diff_sha", "diff_changed_lines", "wall_s",
    ),
    "selection": (
        "kind", "pair_id", "cve", "cluster", "split", "generator", "block", "attempt_id",
        "diff_sha", "n_near_miss", "n_distinct", "inclusion_prob", "correction_order",
        "cwe", "seed",
    ),
    "sibling": (
        "kind", "pair_id", "cve", "cluster", "split", "generator", "block", "method",
        "status", "f_diff_sha", "f_diff_text", "vf_changed_lines", "added_comment_lines",
        "rubric_flags", "validation", "correction_order",
    ),
    "sibling_stop": ("kind", "split", "stopped_at_order", "pairs_corrected"),
    "review_input": (
        "kind", "candidate_id", "pair_id", "state", "cve", "split", "packet", "status",
        "input_sha", "proxy_tokens", "truncated_context", "context_method",
        "allowed_project_tokens",
    ),
    "review": (
        # section 18.3
        "call_id", "candidate_id", "state", "cve", "cluster", "generator", "reviewer",
        "snapshot", "trial", "input_sha", "prompt_sha", "status", "attempt", "verdict",
        "risk", "tokens", "latency_s", "cost",
        # added (SPEC_ANSWERS Q4, Q18, extension)
        "kind", "pair_id", "split", "block", "packet", "model", "served_model", "reason",
        "justification_words", "weights_sha", "precision", "serving_stack",
        "gpu_seconds", "cost_sensitivity",
    ),
}

EXTENSION_FIELDS = ("weights_sha", "precision", "serving_stack", "gpu_seconds", "cost_sensitivity")

_LOCK = threading.Lock()


class LogSchemaError(ValueError):
    pass


def path(runs_dir, name):
    return pathlib.Path(runs_dir) / FILES[name]


def check_row(row):
    kind = row.get("kind")
    if kind not in REQUIRED:
        raise LogSchemaError(f"row kind {kind!r} unknown")
    missing = [f for f in REQUIRED[kind] if f not in row]
    if missing:
        raise LogSchemaError(f"{kind} row missing fields: {missing}")
    return row


def append(log_path, rows):
    """Append rows (validated) to a JSONL file, flushing once. Never rewrites."""
    rows = [check_row(r) for r in rows]
    p = pathlib.Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with open(p, "a") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True, default=str) + "\n")
            fh.flush()


def read(log_path):
    """Yield rows, tolerating a truncated final line from a killed run."""
    p = pathlib.Path(log_path)
    if not p.exists():
        return
    with open(p) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"warning: {p}:{i} is not valid JSON, skipping", file=sys.stderr)


def latest(rows, key):
    """Last row per key (a later row supersedes an earlier one)."""
    out = {}
    for r in rows:
        out[r[key] if isinstance(key, str) else key(r)] = r
    return out


def audit(runs_dir):
    """Validate every row of every log. Returns {file: {kind: rows}}; raises on a bad row."""
    out = {}
    for name, fname in FILES.items():
        counts = {}
        for i, r in enumerate(read(pathlib.Path(runs_dir) / fname), 1):
            try:
                check_row(r)
            except LogSchemaError as exc:
                raise LogSchemaError(f"{fname}:{i}: {exc}")
            counts[r["kind"]] = counts.get(r["kind"], 0) + 1
        out[fname] = counts
    return out

