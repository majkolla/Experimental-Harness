"""Stage 4 selection (section 10) and the seeded correction order (section 9).

* Near-misses are deduplicated within each (CVE, generator) cell after
  whitespace normalisation.
* One distinct near-miss per cell is drawn uniformly with a seed derived from
  (global seed, CVE, generator); its inclusion probability 1/k is recorded.
* The correction order (who gets a twin first) is fixed by seed before any
  review: core cells first, then extension cells, each block shuffled by its
  own derived seed. The stopping point is logged by the sibling stage.
* `select_pairs` has no parameter through which review outcomes could arrive:
  selection is a function of the classified attempts and the seed only.
"""

import hashlib
import random

from .. import study_config as S
from . import difftools


def pair_id_for(cve, generator, attempt_id):
    """Opaque pair id: carries no generator letter, CVE id or project name."""
    return "pair-" + hashlib.sha256(f"{cve}|{generator}|{attempt_id}".encode()).hexdigest()[:16]


def candidate_id(pair_id, state):
    return "cand-" + hashlib.sha256(f"{pair_id}|{state}".encode()).hexdigest()[:16]


def select_pairs(near_misses, seed, cwe_of=None):
    """near_misses: generation rows (with diff_text) of attempts classed near_miss.

    Returns one selection row per (CVE, generator) cell that has a near-miss.
    """
    cells = {}
    for r in near_misses:
        cells.setdefault((r["cve"], r["generator"]), []).append(r)
    rows = []
    for (cve, g), items in sorted(cells.items()):
        groups = {}
        for r in sorted(items, key=lambda r: r["attempt_id"]):
            groups.setdefault(difftools.norm_sha(r["diff_text"]), []).append(r)
        keys = sorted(groups)
        rng = random.Random(f"{seed}|select|{cve}|{g}")
        pick = keys[rng.randrange(len(keys))]
        chosen = groups[pick][0]
        rows.append({
            "kind": "selection",
            "pair_id": pair_id_for(cve, g, chosen["attempt_id"]),
            "cve": cve, "cluster": chosen["cluster"], "split": chosen["split"],
            "generator": g, "block": "core" if g in S.CORE_GENERATORS else "extension",
            "attempt_id": chosen["attempt_id"], "diff_sha": chosen["diff_sha"],
            "n_near_miss": len(items), "n_distinct": len(keys),
            "inclusion_prob": 1.0 / len(keys),
            "dedup_groups": {k: [r["attempt_id"] for r in v] for k, v in groups.items()},
            "correction_order": None, "cwe": (cwe_of or {}).get(cve), "seed": seed,
        })
    order = []
    for block in ("core", "extension"):
        ids = sorted(r["pair_id"] for r in rows if r["block"] == block)
        random.Random(f"{seed}|correction|{block}").shuffle(ids)
        order += ids
    rank = {pid: i for i, pid in enumerate(order)}
    for r in rows:
        r["correction_order"] = rank[r["pair_id"]]
    return sorted(rows, key=lambda r: r["correction_order"])


def run(cfg, split_name, runs_dir):
    """Select from the classified attempts of one split; append selection rows."""
    from .. import logs
    from .generate import advisory_for
    from .split import assert_accessible

    rows = list(logs.read(runs_dir / logs.FILES["attempts"]))
    cls = logs.latest((r for r in rows if r["kind"] == "classification"), "attempt_id")
    gens = logs.latest((r for r in rows if r["kind"] == "generation"), "attempt_id")
    nm = [gens[a] for a, c in cls.items() if c["class"] == "near_miss" and c["split"] == split_name]
    for r in nm:
        assert_accessible(cfg, r["cve"], "selection")
    already = {r["pair_id"] for r in logs.read(runs_dir / logs.FILES["selection"])
               if r.get("split") == split_name}
    cves = sorted({r["cve"] for r in nm})
    cwe = {c: advisory_for(cfg, c)["cwe"] for c in cves}
    sel = select_pairs(nm, cfg["seed"], cwe)
    if already:
        if already != {r["pair_id"] for r in sel}:
            raise RuntimeError(
                f"selection for {split_name} already logged and differs from a fresh "
                "selection; the attempts log changed after selection"
            )
        return sel
    logs.append(runs_dir / logs.FILES["selection"], sel)
    return sel
