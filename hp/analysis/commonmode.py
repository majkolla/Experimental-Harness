"""Common mode for a three-reviewer panel (RQ3; sections 4.4, 4.5, 14.6).

For the cheap panel a/b/c at t_p (primary), the strong panel A/B/C at each
member's own threshold (descriptive) and the open panel X/Y/Z at t_o
(extension), on the vulnerable candidates V.

Per candidate x, each member has three trials. The panel quantities are
estimated, as the primary estimate (SPEC_ANSWERS Q7d), by averaging over all
36 = 3! x 3! trial matchings, which per candidate equals the plug-in products
of the members' per-trial means: q_jk(x) = p_j(x) p_k(x), t(x) = p1 p2 p3,
gate R2(x) = h(p(x)). Aggregated hierarchically (candidate -> CVE -> row ->
equal-generator average):

* p_j, q (mean pairwise co-approval), t, R2 = 3q - 2t, R3 = t;
* **benchmark-level gap** (primary reference, Q6): R2 - h(p1, p2, p3) of the
  aggregated marginals; dq = q - mean_jk(p_j p_k), dt = t - p1 p2 p3,
  d_gate_2of3 = 3 dq - 2 dt (= the benchmark gap), d_gate_3of3 = dt, and
  dt/dq with its shape (concentrated if dt/dq > 3/2: the 2-of-3 rate then
  understates a common cause that fools everyone at once);
* **within-patch gap**, a DESIGN CHECK WITH EXPECTATION 0 (Q5): the identity
  matching (trial j with trial j) minus the plug-in reference h(p(x)). Each
  trial is a separate stateless call and nothing links trial j across
  reviewers, so this is a permutation statistic: the mean over the 36
  matchings is exactly the plug-in reference. Reported with the distinct-
  trial recombination version (`estimators.recomb_*`) next to it.

Shared difficulty, which the legacy Experiment 1 analysis conditioned away as
a nuisance (`report.naive_pooled_reference`), is the phenomenon here: the
benchmark gap is exactly what shared difficulty across patches produces
(Eckhardt and Lee 1985).

RQ3 then describes what drives the benchmark gap: by generator, weakness
class (CWE), similarity stratum and patch-size stratum (Q5).
"""

import itertools

from .. import estimators as E
from .data import TRIALS, approve
from .rates import h3

MATCHINGS = [(s, t) for s in itertools.permutations(range(3)) for t in itertools.permutations(range(3))]


def candidate_stats(trial_approvals):
    """trial_approvals: 3 members x 3 trials of 0/1. Per-candidate quantities."""
    a = trial_approvals
    ps = [sum(x) / 3.0 for x in a]
    q = {(0, 1): ps[0] * ps[1], (0, 2): ps[0] * ps[2], (1, 2): ps[1] * ps[2]}
    t = ps[0] * ps[1] * ps[2]
    identity = [tuple(a[m][j] for m in range(3)) for j in range(3)]
    q_id = E.pairwise(identity)
    t_id = E.joint_all(identity)
    g_id = E.gate_risk(identity, 2)
    g_rec = E.recomb_gate_risk(identity, 2)
    q_rec = E.recomb_pairwise(identity)
    t_rec = E.recomb_joint_all(identity)
    match = [sum(a[0][j] + a[1][s[j]] + a[2][u[j]] >= 2 for j in range(3)) / 3.0 for s, u in MATCHINGS]
    unan = [sum(a[0][j] and a[1][s[j]] and a[2][u[j]] for j in range(3)) / 3.0 for s, u in MATCHINGS]
    return {
        "p": ps, "q": q, "t": t, "R2": h3(*ps), "R3": t,
        "R2_identity": g_id, "R3_identity": t_id, "q_identity": q_id,
        "R2_recomb": g_rec, "q_recomb": q_rec, "t_recomb": t_rec,
        "R2_matchings": match, "R3_matchings": unan,
    }


def _hier_mean(values_by_pair, pairs, generators):
    """Equal-generator average of row means (one pair per CVE)."""
    rows = {}
    for pid, v in values_by_pair.items():
        g = pairs[pid]["generator"]
        rows.setdefault(g, []).append(v)
    gens = [g for g in generators if rows.get(g)]
    if not gens:
        return None
    return sum(sum(rows[g]) / len(rows[g]) for g in gens) / len(gens)


def panel_common_mode(view, members, thresholds, generators, coding="primary", pair_filter=None):
    """All RQ3 quantities for one panel. `thresholds` = {member: cut-off}."""
    per = {}
    for pid, p in view.pairs.items():
        if p["generator"] not in generators or (pair_filter and not pair_filter(p)):
            continue
        trials = [view.trials(pid, "V", m) for m in members]
        if any(all(x.status == "missing" for x in ts) for ts in trials):
            continue
        a = [[approve(x, thresholds[m], coding, "V") for x in ts] for m, ts in zip(members, trials)]
        per[pid] = candidate_stats(a)
    if not per:
        return None
    pairs = view.pairs

    def agg(fn):
        return _hier_mean({pid: fn(s) for pid, s in per.items()}, pairs, generators)

    p = [agg(lambda s, j=j: s["p"][j]) for j in range(3)]
    q = {k: agg(lambda s, k=k: s["q"][k]) for k in [(0, 1), (0, 2), (1, 2)]}
    t = agg(lambda s: s["t"])
    q_bar = sum(q.values()) / 3
    R2 = agg(lambda s: s["R2"])
    ref_q = {k: p[k[0]] * p[k[1]] for k in q}
    dq = sum(q[k] - ref_q[k] for k in q) / 3
    dt = t - p[0] * p[1] * p[2]
    h_bar = h3(*p)
    ratio = dt / dq if abs(dq) > 1e-9 else None
    R2_id = agg(lambda s: s["R2_identity"])
    R2_rec = agg(lambda s: s["R2_recomb"] if s["R2_recomb"] is not None else s["R2"])
    q_id = sum(agg(lambda s, k=k: s["q_identity"][k]) for k in q) / 3
    t_id = agg(lambda s: s["R3_identity"])
    matchings = [agg(lambda s, i=i: s["R2_matchings"][i]) for i in range(len(MATCHINGS))]
    return {
        "members": list(members),
        "thresholds": {m: thresholds[m] for m in members},
        "candidates": len(per),
        "p": p, "q": {f"{members[a]}{members[b]}": v for (a, b), v in q.items()},
        "q_bar": q_bar, "t": t, "R2": R2, "R3": t,
        "identity_residual": abs(R2 - (3 * q_bar - 2 * t)),
        "benchmark": {
            "h_of_pbar": h_bar, "gap": R2 - h_bar, "dq": dq, "dt": dt,
            "d_gate_2of3": 3 * dq - 2 * dt, "d_gate_3of3": dt, "dt_over_dq": ratio,
            "shape": None if ratio is None else ("concentrated" if ratio > 1.5 else "diffuse"),
        },
        "within_patch_design_check": {
            "note": "expectation 0 by construction (trials are exchangeable, separate calls)",
            "plugin_gap": R2_id - R2, "recombination_gap": R2_id - R2_rec,
            "dq": q_id - q_bar, "dt": t_id - t,
        },
        "identity_matching": {"R2": R2_id, "R3": t_id},
        "matchings_36": {"min": min(matchings), "max": max(matchings),
                         "mean": sum(matchings) / len(matchings)},
    }


def strata(values, k=3):
    """Tercile cut points of a list of numbers (None removed)."""
    v = sorted(x for x in values if x is not None)
    if len(v) < k:
        return None
    return [v[int(len(v) * i / k)] for i in range(1, k)]


def drivers(view, members, thresholds, generators, coding="primary"):
    """Benchmark gap broken down by generator, weakness class, similarity and patch size."""
    out = {"by_generator": {}, "by_cwe": {}, "by_similarity": {}, "by_patch_size": {}}
    for g in generators:
        r = panel_common_mode(view, members, thresholds, [g], coding)
        out["by_generator"][g] = r and r["benchmark"]["gap"]
    for cwe in sorted({p["cwe"] for p in view.pairs.values() if p.get("cwe")}):
        r = panel_common_mode(view, members, thresholds, generators, coding,
                              pair_filter=lambda p, c=cwe: p.get("cwe") == c)
        out["by_cwe"][cwe] = r and r["benchmark"]["gap"]
    for field, key in (("similarity", "by_similarity"), ("patch_size", "by_patch_size")):
        cuts = strata([p.get(field) for p in view.pairs.values()])
        if not cuts:
            continue
        def band(x, cuts=cuts):
            return sum(x >= c for c in cuts)
        for b in range(len(cuts) + 1):
            r = panel_common_mode(view, members, thresholds, generators, coding,
                                  pair_filter=lambda p, b=b, f=field: p.get(f) is not None and band(p[f]) == b)
            out[key][f"tercile_{b + 1}"] = r and r["benchmark"]["gap"]
    return out
