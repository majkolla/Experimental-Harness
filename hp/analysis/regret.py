"""Which routing contrast is primary: the regret rule (section 12.4).

Fixed before any test outcome, on development data:
1. Fit every threshold and every policy identity on all development data.
2. In `bootstrap.regret_draws` (2,000) project-cluster resamples of
   development, refit every core reviewer's threshold, then for each selected
   identity compute regret_b = U_b(selected) - min over eligible r of U_b(r).
   Eligible = feasible in that resample. An infeasible or unevaluable
   selection counts as a failure.
3. An identity is stable if regret_b <= delta (0.05) in >= 80% of resamples.
4. Fixed and all three Generator-aware routes stable: primary = Generator-aware
   vs Fixed. Otherwise Fixed and the Exclusion replacement stable: primary =
   Exclusion vs Fixed. Otherwise RQ1 is exploratory.

Generator-aware routes are judged on their row (g's patches); Fixed and the
Exclusion replacement on overall U (the Exclusion replacement against the
eligible reviewers outside fam(g*)). The result is written to a frozen
artefact (`primary_choice.json`) by `analysis.report.analyse_dev`.

Also here: the development feasibility simulation (section 15.6) used for
projected interval half-widths and for promotion condition (iii) of RQ2o.
"""

import collections
import random

from .. import study_config as S
from .rates import Rates
from .thresholds import fit_reviewer


def draw_clusters(rng, clusters, k=None):
    """Resample k (default: all) clusters with replacement -> {cluster: multiplicity}."""
    k = len(clusters) if k is None else k
    return collections.Counter(clusters[rng.randrange(len(clusters))] for _ in range(k))


def regret_rule(view, choice, target, draws, delta, share, seed):
    clusters = view.clusters()
    rng = random.Random(f"{seed}|regret")
    ids = ["fixed"] + [f"generator_aware:{g}" for g in S.CORE_GENERATORS]
    g_star = choice.get("exclusion_generator")
    if g_star:
        ids.append(f"exclusion:{g_star}")
    regrets = {i: [] for i in ids}
    keys = [(r, "V") for r in S.CORE_REVIEWERS]
    for _ in range(draws):
        draw = draw_clusters(rng, clusters)
        thr = {r: fit_reviewer(view, r, target, draw=draw) for r in S.CORE_REVIEWERS}
        rates = Rates(view, thr, reviewers=S.CORE_REVIEWERS)
        rows = rates.rows(keys, draw)
        u = {r: rates.overall((r, "V"), rows) for r in S.CORE_REVIEWERS}
        elig = [r for r in S.CORE_REVIEWERS if thr[r] is not None and u[r] is not None]

        def reg(sel, pool, value):
            pool = [r for r in pool if value(r) is not None]
            if sel not in pool or not pool:
                return None  # infeasible or unevaluable: a failure
            return value(sel) - min(value(r) for r in pool)

        regrets["fixed"].append(reg(choice["r_star"], elig, lambda r: u[r]))
        for g in S.CORE_GENERATORS:
            regrets[f"generator_aware:{g}"].append(
                reg(choice["generator_aware"].get(g), elig,
                    lambda r, g=g: rows.get(g, {}).get((r, "V"))))
        if g_star:
            pool = [r for r in elig if S.FAMILY[r] != S.FAMILY[g_star]]
            regrets[f"exclusion:{g_star}"].append(
                reg(choice["exclusion"][g_star], pool, lambda r: u[r]))

    stability = {}
    for i, vals in regrets.items():
        ok = sum(1 for v in vals if v is not None and v <= delta + 1e-12)
        stability[i] = {"share_within_delta": ok / draws, "stable": ok / draws >= share,
                        "failures": sum(1 for v in vals if v is None)}
    fixed_ok = stability["fixed"]["stable"]
    ga_ok = all(stability[f"generator_aware:{g}"]["stable"] for g in S.CORE_GENERATORS)
    ex_ok = bool(g_star) and stability[f"exclusion:{g_star}"]["stable"]
    if fixed_ok and ga_ok:
        primary = "generator_aware"
    elif fixed_ok and ex_ok:
        primary = "exclusion"
    else:
        primary = "exploratory"
    return {"primary": primary, "stability": stability, "draws": draws, "delta": delta,
            "share": share, "seed_label": f"{seed}|regret", "clusters": clusters}


def projected_half_widths(rates, contrasts, k, draws, seed, label):
    """Section 15.6: resample development clusters up to k (the test cluster count)
    and report the half-width of the two-sided 95% percentile interval of each
    contrast. `contrasts` = {name: fn(rows) -> value}."""
    rng = random.Random(f"{seed}|feasibility|{label}")
    clusters = rates.clusters
    keys = rates.keys()
    vals = {n: [] for n in contrasts}
    for _ in range(draws):
        draw = draw_clusters(rng, clusters, k)
        rows = rates.rows(keys, draw)
        for n, fn in contrasts.items():
            v = fn(rows)
            if v is not None:
                vals[n].append(v)
    out = {}
    for n, v in vals.items():
        if len(v) < 2:
            out[n] = None
            continue
        v.sort()
        lo = v[int(0.025 * (len(v) - 1))]
        hi = v[int(0.975 * (len(v) - 1))]
        out[n] = {"half_width": (hi - lo) / 2, "draws": len(v), "k_clusters": k}
    return out
