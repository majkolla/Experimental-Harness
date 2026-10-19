#!/usr/bin/env python3
"""Build pilot items from Vul4J fix commits (needs internet access to GitHub).

For each CVE, takes the human fix commit. From every modified main-source Java
file it cuts the changed lines plus `--context` lines around them, once from
the file before the fix (the "vulnerable" item) and once after it (the "safe"
item). Test files are left out, file paths are reduced to the file name, and
CVE ids in the code are masked.

Only DEVELOPMENT CVEs of the registered split are used by default, so the
confirmatory test set stays untouched. --outside-split adds Vul4J CVEs that are
in neither split. Test-split CVEs are never used.

    python build_items.py                    # development CVEs -> items.jsonl
    python build_items.py --outside-split    # more items; set GITHUB_TOKEN (60 API calls/hour without)
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DATASET_URL = "https://raw.githubusercontent.com/tuhh-softsec/vul4j/HEAD/dataset/vul4j_dataset.csv"
DEFAULT_SPLIT = Path(__file__).resolve().parents[1] / "docs" / "spec" / "proposed_split.json"
CACHE = Path(__file__).resolve().parent / ".cache"   # GitHub responses, so reruns cost no API calls
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


class RateLimited(RuntimeError):
    pass


def get(url, api=False):
    cached = CACHE / hashlib.sha256(url.encode()).hexdigest()
    if cached.exists():
        return cached.read_text(encoding="utf-8")
    req = urllib.request.Request(url, headers={"User-Agent": "pilot-build-items"})
    if api:
        req.add_header("Accept", "application/vnd.github+json")
        if os.environ.get("GITHUB_TOKEN"):
            req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if api and e.code in (403, 429):
            reset = e.headers.get("X-RateLimit-Reset")
            when = f" (resets in {max(0, int(reset) - int(time.time())) // 60} min)" if reset else ""
            raise RateLimited(f"GitHub API rate limit reached{when}; wait, or set GITHUB_TOKEN") from e
        raise
    CACHE.mkdir(exist_ok=True)
    cached.write_text(text, encoding="utf-8")
    return text


def is_test(path):
    p = "/" + path.lower()
    return "/test/" in p or "/tests/" in p


def spans(patch, side, n_lines, context):
    """Line ranges (1-based, inclusive) around each hunk on one side, merged when they touch."""
    out = []
    for m in HUNK.finditer(patch):
        start, length = (m.group(1), m.group(2)) if side == "old" else (m.group(3), m.group(4))
        start, length = int(start), int(length or 1)
        lo, hi = max(1, start - context), min(n_lines, start + max(length, 1) - 1 + context)
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def cut(text, ranges):
    lines = text.splitlines()
    return "\n    // ...\n".join("\n".join(lines[lo - 1:hi]) for lo, hi in ranges)


def mask(code):
    return re.sub(r"CVE-\d{4}-\d{4,}", "CVE-XXXX-XXXX", code)


def build(row, context, max_lines):
    """(vulnerable code, safe code, info) or raises ValueError with the reason to skip."""
    url = row["human_patch"]
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]+)", url)
    c = re.match(r"https://github\.com/([^/]+)/([^/]+)/compare/([0-9a-fA-F]+)\.\.\.?([0-9a-fA-F]+)", url)
    if m:      # a single fix commit
        owner, repo, sha = m.groups()
        commit = json.loads(get(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}", api=True))
        before, after = commit["parents"][0]["sha"], commit["sha"]
    elif c:    # a range of commits
        owner, repo, base, head = c.groups()
        commit = json.loads(get(f"https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}", api=True))
        before, after = commit["base_commit"]["sha"], commit["commits"][-1]["sha"]
    else:
        raise ValueError(f"unexpected fix URL {url}")
    src = [f for f in commit.get("files", []) if f["filename"].endswith(".java") and not is_test(f["filename"])]
    modified = [f for f in src if f["status"] == "modified"]
    if not modified:
        raise ValueError("no modified main-source Java file in the fix")
    if any("patch" not in f for f in modified):
        raise ValueError("diff too large for the GitHub API")
    raw = "https://raw.githubusercontent.com/{}/{}/{}/{}"
    vul, safe = [], []
    for f in modified:
        old = get(raw.format(owner, repo, before, f["filename"]))
        new = get(raw.format(owner, repo, after, f["filename"]))
        name = "// File: " + f["filename"].rsplit("/", 1)[-1]
        vul.append(name + "\n" + cut(old, spans(f["patch"], "old", len(old.splitlines()), context)))
        safe.append(name + "\n" + cut(new, spans(f["patch"], "new", len(new.splitlines()), context)))
    vul, safe = mask("\n\n".join(vul)), mask("\n\n".join(safe))
    n = max(len(vul.splitlines()), len(safe.splitlines()))
    if n > max_lines:
        raise ValueError(f"{n} lines, more than --max-lines {max_lines}")
    info = {"files": [f["filename"] for f in modified],
            "files_added_by_fix": [f["filename"] for f in src if f["status"] == "added"],
            "lines": n, "fix_commit": f"{owner}/{repo}@{after}"}
    return vul, safe, info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", default=str(DEFAULT_SPLIT), help="registered split (proposed_split.json)")
    ap.add_argument("--dataset", default=DATASET_URL, help="Vul4J dataset CSV: URL or local path")
    ap.add_argument("--outside-split", action="store_true", help="also use Vul4J CVEs in neither split")
    ap.add_argument("--cves", help="comma-separated subset (test-split CVEs are refused)")
    ap.add_argument("--context", type=int, default=25, help="lines kept around each change [25]")
    ap.add_argument("--max-lines", type=int, default=400, help="skip CVEs whose code is longer [400]")
    ap.add_argument("--out", default="items.jsonl")
    args = ap.parse_args()

    split = json.loads(Path(args.split).read_text(encoding="utf-8"))
    merges = split.get("lineage_merges", {})
    dev = {c: cl for cl, cves in split["development"].items() for c in cves}
    test = {c for cves in split["test"].values() for c in cves}
    text = get(args.dataset) if args.dataset.startswith("http") else Path(args.dataset).read_text(encoding="utf-8")
    rows = {r["vul_id"]: r for r in csv.DictReader(io.StringIO(text))}

    chosen = {c: (cl, "development") for c, cl in dev.items()}
    if args.outside_split:
        for c, r in rows.items():
            if c not in dev and c not in test:
                chosen[c] = (merges.get(r["repo_slug"], r["repo_slug"]), "outside_split")
    if args.cves:
        wanted = [c.strip() for c in args.cves.split(",") if c.strip()]
        refused = [c for c in wanted if c in test]
        if refused:
            sys.exit(f"refused: {refused} are in the locked test split")
        chosen = {c: chosen.get(c, (rows[c]["repo_slug"], "outside_split")) for c in wanted if c in rows}

    items, skipped, seen = [], {}, {}
    for cve in sorted(chosen, key=lambda c: int(c.split("-")[1])):
        group, origin = chosen[cve]
        fix = rows[cve]["human_patch"]
        if fix in seen:  # two CVEs with one fix would be the same item twice
            skipped[cve] = f"same fix as {seen[fix]}"
            print(f"  skip {cve}: {skipped[cve]}")
            continue
        seen[fix] = cve
        try:
            vul, safe, info = build(rows[cve], args.context, args.max_lines)
        except RateLimited as e:
            sys.exit(f"stopped at {cve}: {e}. {args.out} was not written; "
                     "rerun later (answers so far are cached).")
        except (ValueError, KeyError, urllib.error.URLError) as e:
            skipped[cve] = str(e)
            print(f"  skip {cve}: {e}")
            continue
        for label, code in (("vulnerable", vul), ("safe", safe)):
            items.append({"id": f"{cve}:{label}", "pair": cve, "group": group, "label": label,
                          "cwe": rows[cve]["cwe_id"], "origin": origin, **info, "code": code})
        print(f"  {cve:<10} {group:<40} {info['lines']:>4} lines  {rows[cve]['cwe_id']}")

    with open(args.out, "w", encoding="utf-8") as fh:
        for it in items:
            fh.write(json.dumps(it) + "\n")
    pairs = len(items) // 2
    groups = len({it["group"] for it in items})
    print(f"\n{pairs} CVEs ({len(items)} items) in {groups} repositories -> {args.out}; skipped {len(skipped)}")


if __name__ == "__main__":
    main()
