"""Two-stage aggregation, cluster bootstrap, contrasts, Holm.

The inferential n is the number of independent clusters, not the number of
calls. With 60 tasks x 4 panels x 2 regimes x 24 replicates x 3 reviewers there
are ~34,000 reviewer calls and 60 clusters; a call-wise standard error is about
sqrt(560) ~ 24 times too small. So:

* aggregation is two-stage -- average within task, then across tasks with equal
  weight. Pooling call-level outcomes instead weights each task by how many of
  its panels completed, which reintroduces the missingness bias and imports the
  task-heterogeneity artefact.
* every interval comes from a bootstrap that resamples whole *clusters* with all
  siblings, configurations, seats and replicates intact. Sibling patches of one
  CVE are not independent draws.

Per-task cell statistics are computed once; the bootstrap only re-averages
them. That is what makes 2000 draws over six statistics a two-second operation
and therefore something that actually gets explored.
"""

import collections
import random

from . import estimators

SCALARS = (
    "p_bar",
    "R_obs",
    "R_recomb",
    "R_plugin",
    "R_unan_obs",
    "R_unan_recomb",
    "D",
    "D_unan",
    "dq",
    "dt",
    "t",
    "t_recomb",
)


def per_task_stats(cells, k):
    """{(panel, regime): {task: cell_stats}} and the task -> cluster map."""
    out = collections.defaultdict(dict)
    clusters = {}
    for (task, panel, regime), cell in cells.items():
        if not cell["trials"]:
            continue
        st = estimators.cell_stats(cell["trials"], k, cell["homogeneous"])
        if st is None:
            continue
        out[(panel, regime)][task] = st
        clusters[task] = cell["cluster"]
    return dict(out), clusters


def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def aggregate(per_task, task_subset=None):
    """Stage two: equal-weight mean over tasks, per (panel, regime)."""
    agg = {}
    for key, by_task in per_task.items():
        tasks = list(by_task) if task_subset is None else [
            t for t in task_subset if t in by_task
        ]
        if not tasks:
            continue
        agg[key] = {
            field: _mean([by_task[t][field] for t in tasks]) for field in SCALARS
        }
        agg[key]["n_tasks"] = len(set(tasks))
    return agg


# ---------------------------------------------------------------------------
# contrasts
# ---------------------------------------------------------------------------


def contrast_regime(agg, field, panels=None):
    """shared - diverse, averaged over panel templates.

    The same task population is evaluated in both arms, so stable task
    difficulty cancels from the contrast by construction rather than by
    adjustment.
    """
    panels = panels or sorted({p for p, _ in agg})
    diffs = []
    for p in panels:
        a, b = agg.get((p, "shared")), agg.get((p, "diverse"))
        if a and b and a[field] is not None and b[field] is not None:
            diffs.append(a[field] - b[field])
    return _mean(diffs)


def contrast_composition(agg, field, hetero="ABC", homo=("AAA", "BBB", "CCC"),
                         regime="diverse"):
    """ABC minus the equal-weight homogeneous mixture.

    Stated against (R_AAA + R_BBB + R_CCC)/3 rather than against a single chosen
    homogeneous panel: a randomly drawn seat then has the same marginal model
    distribution in ABC and in the mixture, so the contrast comes much closer to
    holding capability fixed while varying only coupling. It does not make
    families exchangeable -- model identity still bundles capability, training
    data and tuning -- so the claim stays operational: these panel templates,
    not diversity per se.
    """
    h = agg.get((hetero, regime))
    mix = [agg[(p, regime)][field] for p in homo if (p, regime) in agg]
    if not h or h[field] is None or not mix:
        return None
    return h[field] - _mean(mix)


CONFIRMATORY = {
    # name: (function(agg) -> estimate, direction)
    "H1_regime_R_obs": (lambda a: contrast_regime(a, "R_obs"), "greater"),
    "H2_composition_R_obs": (lambda a: contrast_composition(a, "R_obs"), "less"),
    "H3_regime_D": (lambda a: contrast_regime(a, "D"), "greater"),
}

EXPLORATORY = {
    "regime_R_unan_obs": (lambda a: contrast_regime(a, "R_unan_obs"), "greater"),
    "regime_D_unan": (lambda a: contrast_regime(a, "D_unan"), "greater"),
    "regime_dq": (lambda a: contrast_regime(a, "dq"), "greater"),
    "regime_p_bar": (lambda a: contrast_regime(a, "p_bar"), "greater"),
}


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


def cluster_bootstrap(per_task, clusters, statistics, draws=2000, seed=7,
                      alpha=0.05):
    """Resample clusters with replacement; recompute every statistic per draw."""
    by_cluster = collections.defaultdict(list)
    for task, cl in clusters.items():
        by_cluster[cl].append(task)
    cluster_ids = sorted(by_cluster)

    point = {name: fn(aggregate(per_task)) for name, (fn, _) in statistics.items()}
    dists = {name: [] for name in statistics}

    rng = random.Random(seed)
    for _ in range(draws):
        drawn = [cluster_ids[rng.randrange(len(cluster_ids))] for _ in cluster_ids]
        subset = [t for cl in drawn for t in by_cluster[cl]]
        agg = aggregate(per_task, subset)
        for name, (fn, _) in statistics.items():
            try:
                dists[name].append(fn(agg))
            except (KeyError, TypeError, ZeroDivisionError):
                dists[name].append(None)

    out = {}
    for name, (_, direction) in statistics.items():
        vals = sorted(v for v in dists[name] if v is not None)
        if not vals or point[name] is None:
            out[name] = {"estimate": point[name], "ci": None, "p": None, "draws": 0}
            continue
        lo = vals[int(alpha / 2 * (len(vals) - 1))]
        hi = vals[int((1 - alpha / 2) * (len(vals) - 1))]
        if direction == "greater":
            p = (1 + sum(v <= 0 for v in vals)) / (len(vals) + 1)
        elif direction == "less":
            p = (1 + sum(v >= 0 for v in vals)) / (len(vals) + 1)
        else:
            side = min(sum(v <= 0 for v in vals), sum(v >= 0 for v in vals))
            p = min(1.0, 2 * (1 + side) / (len(vals) + 1))
        out[name] = {
            "estimate": point[name],
            "ci": (lo, hi),
            "p": p,
            "draws": len(vals),
            "direction": direction,
        }
    return out


def holm(pvalues):
    """Holm-Bonferroni. Applied across exactly the three confirmatory tests.

    Everything CWE- or model-specific stays exploratory and is labelled so;
    correcting across an open-ended family would be either dishonest or useless.
    """
    items = sorted(
        ((k, v) for k, v in pvalues.items() if v is not None), key=lambda kv: kv[1]
    )
    m = len(items)
    out, running = {}, 0.0
    for i, (name, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[name] = running
    for name, p in pvalues.items():
        out.setdefault(name, None)
    return out


def saturation_check(agg, lo=0.05, hi=0.95):
    """The pilot's actual job: is the gate able to move at all?

    Near 0 or near 1 the gate saturates and no dependence effect of any size is
    detectable, so a pilot that lands there says nothing about the phenomenon --
    it says the apparatus needs different tasks. Check before freezing.
    """
    problems = []
    for (panel, regime), row in sorted(agg.items()):
        p = row.get("p_bar")
        if p is None:
            continue
        if p < lo or p > hi:
            problems.append(
                f"{panel}/{regime}: p_bar={p:.3f} outside [{lo}, {hi}] -- gate saturated"
            )
    return problems
