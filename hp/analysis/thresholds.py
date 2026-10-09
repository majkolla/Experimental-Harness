"""Thresholds (section 12.3, SPEC_ANSWERS Q7, Q10).

For a reviewer, t_r is the smallest observed risk cut-off whose development
corrected acceptance (hierarchical: trials -> candidate -> CVE -> row ->
equal-generator average, Q7a) reaches the target (0.90). Approval is
risk <= t. Only observed cut-offs, no interpolation, no randomised ties. If no
cut-off reaches the target the reviewer is `infeasible` (None). Feasibility is
per reviewer only; row-level acceptance is reported, not required (Q7b).

ONE threshold per reviewer, shared by every policy: there is no
generator-specific threshold anywhere in this module.

All thresholds, for the nine reviewers and the two panels, are fit on the
development rows of the core bank (pairs from generators A, B, C) only (Q10).
For A, B, C, a, b, c those rows are exactly the core view. The panel cut-offs
t_p (a, b, c) and t_o (X, Y, Z) are chosen the same way on panel acceptance,
where a panel's per-candidate acceptance is h(p1, p2, p3) of the members'
per-trial approvals at the common cut-off.

Acceptance only changes at observed F risk values, so the smallest feasible
observed cut-off is always an observed F risk; the search runs over those.
"""

from .. import study_config as S
from .rates import h3


def _row_weights(view, generators, draw):
    """{pair_id: weight} and {generator: total weight} for a resample (or all = 1)."""
    w, tot = {}, {g: 0 for g in generators}
    for pid, p in view.pairs.items():
        g = p["generator"]
        if g not in tot:
            continue
        x = (draw or {}).get(p["cluster"], 0) if draw is not None else 1
        if x:
            w[pid] = x
            tot[g] += x
    return w, tot


def fit_reviewer(view, reviewer, target, generators=S.CORE_GENERATORS, draw=None):
    """Smallest observed cut-off with hierarchical acceptance >= target, or None."""
    w, tot = _row_weights(view, generators, draw)
    gens = [g for g in generators if tot[g] > 0]
    if len(gens) != len(generators):
        return None  # a generator row is empty: acceptance is not defined
    items = []
    for pid, wp in w.items():
        g = view.pairs[pid]["generator"]
        for tr in view.trials(pid, "F", reviewer):
            if tr.ok and tr.verdict != "abstain" and tr.risk is not None:
                items.append((tr.risk, wp / (tot[g] * len(gens) * 3)))
    items.sort()
    acc, i = 0.0, 0
    while i < len(items):
        risk = items[i][0]
        while i < len(items) and items[i][0] == risk:
            acc += items[i][1]
            i += 1
        if acc >= target - 1e-12:
            return risk
    return None


def panel_acceptance(view, members, t, generators=S.CORE_GENERATORS, draw=None):
    w, tot = _row_weights(view, generators, draw)
    rows = {g: 0.0 for g in generators}
    for pid, wp in w.items():
        g = view.pairs[pid]["generator"]
        ps = []
        for m in members:
            trials = view.trials(pid, "F", m)
            ps.append(sum(int(tr.ok and tr.verdict != "abstain" and tr.risk <= t)
                          for tr in trials) / len(trials))
        rows[g] += wp * h3(*ps)
    if any(tot[g] == 0 for g in generators):
        return None
    return sum(rows[g] / tot[g] for g in generators) / len(generators)


def fit_panel(view, members, target, generators=S.CORE_GENERATORS, draw=None):
    """Common cut-off for a 2-of-3 panel: smallest observed t with panel A >= target."""
    cands = sorted({tr.risk for pid in view.pairs for m in members
                    for tr in view.trials(pid, "F", m)
                    if tr.ok and tr.verdict != "abstain" and tr.risk is not None})
    if not cands:
        return None
    hi_acc = panel_acceptance(view, members, cands[-1], generators, draw)
    if hi_acc is None or hi_acc < target - 1e-12:
        return None
    lo, hi = 0, len(cands) - 1  # acceptance is non-decreasing in t
    while lo < hi:
        mid = (lo + hi) // 2
        if panel_acceptance(view, members, cands[mid], generators, draw) >= target - 1e-12:
            hi = mid
        else:
            lo = mid + 1
    return cands[lo]


def fit_all(core_view, core_bank_view, target, extension=True):
    """Every threshold of the study, from development data of the core bank (Q10)."""
    out = {"reviewers": {}, "panel_cheap": None, "panel_open": None, "target": target,
           "fit_on": "development rows of the core bank (generators A, B, C)"}
    for r in S.CORE_REVIEWERS:
        out["reviewers"][r] = fit_reviewer(core_view, r, target)
    out["panel_cheap"] = fit_panel(core_view, S.CHEAP_REVIEWERS, target)
    if extension:
        for r in S.OPEN_MODELS:
            out["reviewers"][r] = fit_reviewer(core_bank_view, r, target)
        out["panel_open"] = fit_panel(core_bank_view, S.OPEN_MODELS, target)
    return out


def row_acceptance(rates, reviewer, rows):
    """Row-level A at the reviewer's shared threshold (reported, Q7b)."""
    return {g: rows[g].get((reviewer, "F")) for g in rates.generators}
