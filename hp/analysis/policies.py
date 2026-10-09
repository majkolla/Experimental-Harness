"""Policies (section 12.2): Fixed, Generator-aware, Exclusion; strong*, cheap*, panels.

All on the core table only. "Best" = lowest development U at the reviewer's
(shared) threshold among feasible reviewers. Ties are broken by lower measured
cost per call, then by the fixed model-ID order (ASCII order of the model
references: A < B < C < X < Y < Z < a < b < c; PLAN.md section 10 item 7).

* Fixed: r* for every generator (pool: the six core reviewers).
* Generator-aware: r(g) = the best reviewer for g's patches (row-level U at
  the reviewer's shared threshold); it may be g itself.
* Exclusion: for g, the best globally ranked reviewer with fam(r) != fam(g).
  It equals Fixed in every row except fam(r*)'s (section 4.8).
* strong* (best of A, B, C), cheap* (best of a, b, c); the cheap panel a/b/c
  at t_p and the open panel X/Y/Z at t_o.
"""

from .. import study_config as S


def rank_key(u, cost, ref):
    return (u, cost if cost is not None else float("inf"), ref)


def ranking(rates, rows, thresholds, pool):
    """Feasible reviewers of `pool`, best first, by overall U then cost then id."""
    out = []
    for r in pool:
        if thresholds.get(r) is None:
            continue
        u = rates.overall((r, "V"), rows)
        if u is None:
            continue
        out.append((rank_key(u, rates.overall(("cost", r), rows), r), r))
    return [r for _, r in sorted(out)]


def select(rates, rows, thresholds):
    """Fit every policy's identities on (development) rates. Returns a dict."""
    rank = ranking(rates, rows, thresholds, S.CORE_REVIEWERS)
    if not rank:
        return {"feasible": [], "r_star": None}
    r_star = rank[0]
    ga = {}
    for g in rates.generators:
        best = []
        for r in rank:
            u = rows[g].get((r, "V"))
            if u is not None:
                best.append((rank_key(u, rates.overall(("cost", r), rows), r), r))
        ga[g] = min(best)[1] if best else None
    excl = {g: next((r for r in rank if S.FAMILY[r] != S.FAMILY[g]), None) for g in rates.generators}
    strong = [r for r in rank if r in S.CORE_GENERATORS]
    cheap = [r for r in rank if r in S.CHEAP_REVIEWERS]
    g_star = next((g for g in rates.generators if S.FAMILY[g] == S.FAMILY[r_star]), None)
    return {
        "feasible": rank,
        "ranking": rank,
        "r_star": r_star,
        "fixed": {g: r_star for g in rates.generators},
        "generator_aware": ga,
        "exclusion": excl,
        "exclusion_generator": g_star,  # the one row where Exclusion differs from Fixed
        "strong_star": strong[0] if strong else None,
        "cheap_star": cheap[0] if cheap else None,
    }


def mapping(choice, policy, generators):
    """{generator: unit} for a named policy."""
    if policy in ("fixed", "generator_aware", "exclusion"):
        return dict(choice[policy])
    if policy == "strong_star":
        return {g: choice["strong_star"] for g in generators}
    if policy == "cheap_star":
        return {g: choice["cheap_star"] for g in generators}
    if policy in ("panel_cheap", "panel_open", "panel_cheap#identity", "panel_open#identity"):
        return {g: policy for g in generators}
    raise ValueError(policy)
