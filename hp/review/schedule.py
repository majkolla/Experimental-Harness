"""The crossed review schedule x x r x j (sections 11.4, 12, 13).

Blocks
* `core`: pairs from generators A, B, C reviewed by A, B, C, a, b, c.
* `extension` (when enabled): the same core pairs reviewed by X, Y, Z, and the
  pairs from X, Y, Z reviewed by all nine reviewers. With
  `extension.paid_block_on_test = false`, the commercial reviewers on the
  extension pairs (generators X, Y, Z) run on development only (Q21, §12.7).
* `expB` (development only): reviewers a, b, c x three packets on the core
  pairs of 12 development CVEs drawn by seed.

Every call is a fresh stateless call; three trials per (candidate, reviewer).
The schedule is globally shuffled (seeded), and `panel_key` is the candidate
id, so the dispatcher never has two calls on one candidate in flight. Call ids
and seeds depend only on content, never on position, so the core calls are the
same set with and without the extension.
"""

import random

from .. import study_config as S

STATES = ("V", "F")


def reviewers_for(pair_block, generator, cfg, split_name):
    """(reviewer, block) for one pair."""
    ext = cfg["extension"]["enabled"]
    out = []
    if generator in S.CORE_GENERATORS:
        out += [(r, "core") for r in S.CORE_REVIEWERS]
        if ext:
            out += [(r, "extension") for r in S.OPEN_MODELS]
    elif ext:
        paid = split_name != "test" or cfg["extension"]["paid_block_on_test"]
        out += [(r, "extension") for r in S.ALL_MODELS
                if r in S.OPEN_MODELS or paid]
    return out


def _call(pair, state, reviewer, trial, block, packet=None):
    cand = pair["cand"][state]
    return {
        "call_id": f"rev|{cand}|{reviewer}|{packet or 'e0'}|t{trial}",
        "candidate_id": cand, "pair_id": pair["pair_id"], "state": state,
        "cve": pair["cve"], "cluster": pair["cluster"], "split": pair["split"],
        "generator": pair["generator"], "model_ref": reviewer, "reviewer": reviewer,
        "trial": trial, "packet": packet, "block": block, "panel_key": cand,
        "_context": {"cve": pair["cve"], "generator": pair["generator"], "state": state,
                     "pair_id": pair["pair_id"], "trial": trial, "candidate_id": cand,
                     "packet": packet},
    }


def expb_cves(cfg, dev_pairs):
    """12 development CVEs (seeded) among those with at least one core pair."""
    cves = sorted({p["cve"] for p in dev_pairs if p["generator"] in S.CORE_GENERATORS})
    n = min(cfg["experiment_b"]["n_cves"], len(cves))
    return sorted(random.Random(f"{cfg['seed']}|expB").sample(cves, n))


def build(cfg, pairs, split_name, blocks=("core", "extension"), expb=False):
    """Every review call for `pairs` (all of one split), globally shuffled."""
    trials = cfg["design"]["trials"]
    calls = []
    for p in pairs:
        for reviewer, block in reviewers_for(p["block"], p["generator"], cfg, split_name):
            if block not in blocks:
                continue
            for state in STATES:
                for j in range(1, trials + 1):
                    calls.append(_call(p, state, reviewer, j, block))
    if expb:
        if split_name != "development":
            raise ValueError("Experiment B runs on development data only (section 13)")
        chosen = set(expb_cves(cfg, pairs))
        for p in pairs:
            if p["cve"] not in chosen or p["generator"] not in S.CORE_GENERATORS:
                continue
            for reviewer in cfg["experiment_b"]["reviewers"]:
                for packet in cfg["experiment_b"]["packets"]:
                    for state in STATES:
                        for j in range(1, trials + 1):
                            calls.append(_call(p, state, reviewer, j, "expB", packet))
    calls.sort(key=lambda c: c["call_id"])
    random.Random(f"{cfg['seed']}|review|{split_name}|{'+'.join(sorted(blocks))}|{expb}").shuffle(calls)
    for i, c in enumerate(calls):
        c["dispatch_index"] = i
    return calls
