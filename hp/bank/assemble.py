"""The bank of (V, F) pairs, rebuilt from the logs.

A pair is in the bank of a split if it was selected (selection.jsonl) and its
twin is valid (latest siblings.jsonl row). Everything a later stage needs is
read from the logs here, so the bank itself never has to be stored.
"""

from .. import logs
from . import difftools
from .select import candidate_id


def pairs(runs_dir, split_name, block=None):
    sel = [r for r in logs.read(runs_dir / logs.FILES["selection"]) if r.get("split") == split_name]
    sib = logs.latest((r for r in logs.read(runs_dir / logs.FILES["siblings"])
                       if r.get("kind") == "sibling"), "pair_id")
    rows = list(logs.read(runs_dir / logs.FILES["attempts"]))
    gens = logs.latest((r for r in rows if r["kind"] == "generation"), "attempt_id")
    cls = logs.latest((r for r in rows if r["kind"] == "classification"), "attempt_id")
    out = []
    for s in sorted(sel, key=lambda r: r["correction_order"]):
        f = sib.get(s["pair_id"])
        if not f or f["status"] != "valid":
            continue
        if block and s["block"] != block:
            continue
        v_diff = gens[s["attempt_id"]]["diff_text"]
        c = cls.get(s["attempt_id"], {})
        out.append({
            "pair_id": s["pair_id"], "cve": s["cve"], "cluster": s["cluster"],
            "split": s["split"], "generator": s["generator"], "block": s["block"],
            "cwe": s.get("cwe"), "attempt_id": s["attempt_id"],
            "v_diff": v_diff, "f_diff": f["f_diff_text"],
            "cand": {"V": candidate_id(s["pair_id"], "V"), "F": candidate_id(s["pair_id"], "F")},
            "similarity_to_human": c.get("similarity_to_human"),
            "patch_size": c.get("diff_changed_lines") or difftools.diff_size(v_diff),
            "vf_changed_lines": f.get("vf_changed_lines"),
            "method": f.get("method"),
        })
    return out
