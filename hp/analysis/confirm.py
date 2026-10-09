"""Confirmatory analysis on the test set (sections 15.2-15.4, SPEC_ANSWERS Q8, Q9).

Runs only when the study is frozen and every frozen hash still matches. Uses
the frozen thresholds and the frozen primary choice; nothing is refit on test.

* Project-cluster bootstrap: `bootstrap.confirm_draws` (10,000) resamples of
  the clusters with at least one evaluable core pair, derived from core rows
  only (Q9). Policies are compared on the same resample (paired).
* Reported: two-sided 95% percentile intervals.
* Decisions (Q8): one-sided bootstrap p-values per component,
  (1 + #draws on the wrong side) / (B + 1); a hypothesis p-value is the
  maximum over its components (intersection-union); Holm (`bootstrap.holm`,
  the legacy function) over {RQ1, RQ2}, or {RQ1, RQ2, RQ2o} when RQ2o was
  promoted, at familywise one-sided alpha 0.025 (two-sided 0.05), with
  Holm-adjusted one-sided bounds. RQ1 practical equivalence is reported
  outside the Holm family.

  | hypothesis | components (wrong side counted)                                 |
  |------------|-----------------------------------------------------------------|
  | RQ1        | Δ1 = U(sel) - U(fix) < 0;  Δ1A = A(sel) - A(fix) > -ni_accept   |
  | RQ2        | cost ratio < 1;  Δ2U < +ni_unsafe;  Δ2A > -ni_accept            |
  | RQ2o       | as RQ2 with the open panel X/Y/Z at t_o (provisional margins)  |

  Anything not rejected is "insufficient precision", never "no effect".

`fixed_sequence` mode (provisional, PLAN.md section 10 item 3): Holm over
{RQ1, RQ2}; RQ2o can be rejected only if RQ2 is, adjusted p = max(adj p RQ2, p RQ2o).
"""

import math
import random

from .. import bootstrap as legacy_bootstrap
from .. import study_config as S
from .policies import mapping
from .rates import Rates
from .regret import draw_clusters


INF = float("inf")


def _k(alpha, n):
    return int(math.floor(alpha * (n + 1) + 1e-9))


def lower_bound(vals, alpha):
    """One-sided lower bound at level alpha, consistent with the p-value rule:
    bound > b  <=>  (1 + #{v <= b}) / (B + 1) <= alpha. A draw with no value
    (None) counts against the claim. None if unbounded."""
    w = sorted(-INF if v is None else v for v in vals)
    k = _k(alpha, len(w))
    return w[k - 1] if k >= 1 and w and w[k - 1] != -INF else None


def upper_bound(vals, alpha):
    """One-sided upper bound at level alpha: bound < b <=> (1 + #{v >= b}) / (B + 1) <= alpha."""
    w = sorted(INF if v is None else v for v in vals)
    k = _k(alpha, len(w))
    return w[len(w) - k] if k >= 1 and w and w[len(w) - k] != INF else None


def _pct(vals, q):
    """Two-sided percentile end: q < 0.5 a lower bound, q > 0.5 an upper bound."""
    return lower_bound(vals, q) if q < 0.5 else upper_bound(vals, 1 - q)


def _p_wrong(vals, wrong):
    """(1 + #draws on the wrong side) / (B + 1); a draw with no value is on the wrong side."""
    return (1 + sum(1 for v in vals if v is None or wrong(v))) / (len(vals) + 1)


def contrasts(choice, primary, extension_open=False, core=True):
    """{name: (fn(rates, rows) -> value)} for every quantity bootstrapped."""
    def pol(name, state):
        return lambda R, rows: R.policy(mapping(choice, name, R.generators), state, rows)

    def diff(a, b):
        return lambda R, rows: (None if a(R, rows) is None or b(R, rows) is None
                                else a(R, rows) - b(R, rows))

    def ratio(a, b):
        return lambda R, rows: (None if not b(R, rows) or a(R, rows) is None
                                else a(R, rows) / b(R, rows))

    def cost(unit_name):
        return lambda R, rows: _cost(R, rows, choice, unit_name)

    out = {}
    if extension_open:
        out["delta2o_U"] = diff(pol("panel_open", "V"), pol("strong_star", "V"))
        out["delta2o_A"] = diff(pol("panel_open", "F"), pol("strong_star", "F"))
        out["cost_ratio_o"] = ratio(cost("panel_open"), cost("strong_star"))
        out["U_panel_open"] = pol("panel_open", "V")
        out["A_panel_open"] = pol("panel_open", "F")
    if not core:
        return out
    if primary in ("generator_aware", "exclusion"):
        out["delta1_U"] = diff(pol(primary, "V"), pol("fixed", "V"))
        out["delta1_A"] = diff(pol(primary, "F"), pol("fixed", "F"))
        for g in S.CORE_GENERATORS:
            out[f"delta1_U_row_{g}"] = (lambda R, rows, g=g: None if (
                rows[g].get((choice[primary][g], "V")) is None or rows[g].get((choice["r_star"], "V")) is None)
                else rows[g][(choice[primary][g], "V")] - rows[g][(choice["r_star"], "V")])
    out["delta2_U"] = diff(pol("panel_cheap", "V"), pol("strong_star", "V"))
    out["delta2_A"] = diff(pol("panel_cheap", "F"), pol("strong_star", "F"))
    out["cost_ratio"] = ratio(cost("panel_cheap"), cost("strong_star"))
    out["delta2_U_cheap_single"] = diff(pol("panel_cheap", "V"), pol("cheap_star", "V"))
    out["delta2_U_identity_matching"] = diff(pol("panel_cheap#identity", "V"), pol("strong_star", "V"))
    for name in ("fixed", "strong_star", "cheap_star", "panel_cheap"):
        out[f"U_{name}"] = pol(name, "V")
        out[f"A_{name}"] = pol(name, "F")
    if primary in ("generator_aware", "exclusion"):
        out[f"U_{primary}"] = pol(primary, "V")
        out[f"A_{primary}"] = pol(primary, "F")
    return out


def _cost(R, rows, choice, unit_name):
    unit = choice.get(unit_name) if unit_name in ("strong_star", "cheap_star") else unit_name
    return R.overall(("cost", unit), rows)


HYPOTHESES = {
    "RQ1": [("delta1_U", "upper", 0.0), ("delta1_A", "lower", "-ni_accept")],
    "RQ2": [("cost_ratio", "upper", 1.0), ("delta2_U", "upper", "+ni_unsafe"),
            ("delta2_A", "lower", "-ni_accept")],
    "RQ2o": [("cost_ratio_o", "upper", 1.0), ("delta2o_U", "upper", "+ni_unsafe"),
             ("delta2o_A", "lower", "-ni_accept")],
}


def _bound(spec, margins):
    if isinstance(spec, (int, float)):
        return float(spec)
    sign = -1.0 if spec.startswith("-") else 1.0
    return sign * margins[spec[1:]]


def bootstrap(rates, fns, draws, seed, label):
    """Point estimates and resampled values of every contrast (paired resamples)."""
    keys = rates.keys()
    rows0 = rates.rows(keys)
    point = {n: fn(rates, rows0) for n, fn in fns.items()}
    dist = {n: [] for n in fns}
    rng = random.Random(f"{seed}|{label}")
    for _ in range(draws):
        draw = draw_clusters(rng, rates.clusters)
        rows = rates.rows(keys, draw)
        for n, fn in fns.items():
            dist[n].append(fn(rates, rows))  # None (undefined in this resample) is kept
    return point, dist


def summarise(point, dist, alpha2=0.05):
    out = {}
    for n, v in dist.items():
        undefined = sum(1 for x in v if x is None)
        if not v or point.get(n) is None or undefined == len(v):
            out[n] = {"estimate": point.get(n), "ci95": None, "draws": len(v),
                      "undefined_draws": undefined}
            continue
        out[n] = {"estimate": point[n], "ci95": [_pct(v, alpha2 / 2), _pct(v, 1 - alpha2 / 2)],
                  "draws": len(v), "undefined_draws": undefined}
    return out


def decide(point, dist, family, margins, alpha, mode, sesoi):
    """p-values, Holm, decisions and Holm-adjusted bounds."""
    comp, hyp_p = {}, {}
    for h in family:
        ps = []
        for name, side, spec in HYPOTHESES[h]:
            b = _bound(spec, margins)
            v = dist.get(name) or []
            if not v or point.get(name) is None:
                p = 1.0
            elif side == "upper":
                p = _p_wrong(v, lambda x, b=b: x >= b)
            else:
                p = _p_wrong(v, lambda x, b=b: x <= b)
            comp[f"{h}:{name}"] = {"bound": b, "side": side, "p_one_sided": p}
            ps.append(p)
        hyp_p[h] = max(ps)
    holm_family = [h for h in family if not (h == "RQ2o" and mode == "fixed_sequence")]
    adj = legacy_bootstrap.holm({h: hyp_p[h] for h in holm_family})
    if "RQ2o" in family and mode == "fixed_sequence":
        adj["RQ2o"] = max(adj.get("RQ2", 1.0), hyp_p["RQ2o"])
    order = sorted(holm_family, key=lambda h: hyp_p[h])
    levels = {h: alpha / (len(holm_family) - i) for i, h in enumerate(order)}
    if "RQ2o" in family and mode == "fixed_sequence":
        levels["RQ2o"] = levels.get("RQ2", alpha)
    decisions = {}
    for h in family:
        rejected = adj[h] <= alpha + 1e-12
        bounds = {}
        for name, side, spec in HYPOTHESES[h]:
            v = dist.get(name) or []
            if v:
                lv = levels[h]
                bounds[name] = upper_bound(v, lv) if side == "upper" else lower_bound(v, lv)
        decisions[h] = {"p": hyp_p[h], "p_holm": adj[h], "level": levels[h],
                        "holm_adjusted_bounds": bounds,
                        "decision": _label(h, rejected, point, dist, margins, levels[h])}
    if "RQ1" in family:
        v = dist.get("delta1_U") or []
        if v:
            lo, hi = _pct(v, 0.025), _pct(v, 0.975)
            decisions["RQ1"]["practical_equivalence"] = bool(
                lo is not None and hi is not None and -sesoi < lo and hi < sesoi)
    return {"components": comp, "hypotheses": decisions}


def _label(h, rejected, point, dist, margins, level):
    if not rejected:
        return "insufficient precision"
    if h == "RQ1":
        return "improvement"
    key = "delta2_U" if h == "RQ2" else "delta2o_U"
    v = dist.get(key) or []
    safer = bool(v) and _p_wrong(v, lambda x: x >= 0) <= level + 1e-12
    return "cheaper and safer" if safer else "cheaper and non-inferior"


def family(primary, promoted, mode):
    fam = []
    if primary in ("generator_aware", "exclusion"):
        fam.append("RQ1")
    fam.append("RQ2")
    if promoted or mode == "fixed_sequence":
        fam.append("RQ2o")
    return fam


def make_rates(view, thresholds, coding="primary", panels=("panel_cheap",)):
    thr = dict(thresholds["reviewers"])
    pan = {}
    if "panel_cheap" in panels and thresholds.get("panel_cheap") is not None:
        pan["panel_cheap"] = (list(S.CHEAP_REVIEWERS), thresholds["panel_cheap"])
    if "panel_open" in panels and thresholds.get("panel_open") is not None:
        pan["panel_open"] = (list(S.OPEN_MODELS), thresholds["panel_open"])
    return Rates(view, thr, coding=coding, panels=pan, generators=list(S.CORE_GENERATORS))
