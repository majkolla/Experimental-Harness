 
import collections
import json
import pathlib
import re
import sys
 
K, N = 2, 3  # gate rule lives here, in analysis, not in the harness
 
 
def parse_verdict(record):
    if record["status"] != "ok" or not record["response"]:
        return None
    match = re.search(r"\{.*\}", record["response"], re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))["merge_verdict"]
    except (json.JSONDecodeError, KeyError):
        return None
 
 
def main(log_path):
    records = [json.loads(l) for l in pathlib.Path(log_path).open() if l.strip()]
 
    panels = collections.defaultdict(dict)
    for r in records:
        key = (r["task"], r["panel"], r["replicate"])
        panels[key][r["seat"]] = parse_verdict(r)
 
    gates = {}
    for key, seats in panels.items():
        votes = [seats.get(s) for s in range(N)]
        if any(v is None for v in votes):
            gates[key] = None  # incomplete panel is not a rejection
        else:
            gates[key] = sum(v == "approve" for v in votes) >= K
 
    by_panel = collections.defaultdict(list)
    for (task, panel, rep), gate in gates.items():
        by_panel[panel].append(gate)
 
    print(f"{len(records)} calls, {len(panels)} panels\n")
    print(f"{'panel':<6} {'complete':>9} {'incomplete':>11} {'R_2/3':>7}")
    for panel, gs in sorted(by_panel.items()):
        good = [g for g in gs if g is not None]
        rate = f"{sum(good) / len(good):.3f}" if good else "n/a"
        print(f"{panel:<6} {len(good):>9} {len(gs) - len(good):>11} {rate:>7}")
 
 
if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "runs/pilot-01.jsonl")
 