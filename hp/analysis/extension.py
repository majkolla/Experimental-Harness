"""Extension analyses (SPEC_ANSWERS Q21; sections 12.6, 12.7, 14.3b, 14.4, 14.7, 14.8, 15.7).

None of this is read by the core analysis; each analysis here has its own
bootstrap frame and random stream (Q9), so the core estimates are identical
with and without extension rows in the logs.

* RQ2o: the fixed X/Y/Z 2-of-3 panel at t_o against strong* on the core bank
  (computed in `confirm`, inputs prepared here).
* Promotion (section 15.7, development data): (i) t_o attainable;
  (ii) Δ2U_o < +0.05 and Δ2A_o > -0.05; (iii) projected half-width of Δ2U_o
  (section 15.6 feasibility simulation, up to the test cluster count) <= 0.10.
  With `rq2o_mode = promotion_rule` RQ2o joins the Holm family only if all
  three hold; with `fixed_sequence` it is always tested, after RQ2.
* D_diag for the open block: rows and columns X, Y, Z, on U, A and C, on the
  probability and the logit scale (the core blocks are core estimates).
* Δ6 (RQ6, section 14.8): for each of the nine reviewers, rows with
  fam(g) != fam(r) only; mean over open generators minus mean over commercial
  generators; equal reviewer weight. Development-only when
  `paid_block_on_test` is false (section 12.7).
* Pipeline risk (section 14.7), split commercial {A, B, C} / open {X, Y, Z}.
"""

import random

from .. import study_config as S
from .confirm import _pct, make_rates
from .rates import Rates, d_diag
from .regret import draw_clusters, projected_half_widths


def decide_promotion(t_o, d_u, d_a, half_width, pr):
    """Section 15.7: promoted only if (i) and (ii) and (iii) all hold."""
    cond = {
        "i_t_o_attainable": t_o is not None,
        "ii_dev_margins": d_u is not None and d_a is not None
        and d_u < pr["ni_unsafe"] and d_a > -pr["ni_accept"],
        "iii_half_width": half_width is not None and half_width <= pr["max_half_width"],
    }
    return cond, all(cond.values())


def promotion_check(bank_view, thresholds, choice, cfg, k_test_clusters):
    pr = cfg["extension"]["promotion"]
    t_o = thresholds.get("panel_open")
    out = {"mode": cfg["extension"]["rq2o_mode"], "t_o": t_o,
           "conditions": {"i_t_o_attainable": t_o is not None}}
    if t_o is None or choice.get("strong_star") is None:
        out["conditions"].update({"ii_dev_margins": False, "iii_half_width": False})
        out["promoted"] = False
        return out
    R = make_rates(bank_view, thresholds, panels=("panel_cheap", "panel_open"))
    rows = R.rows(R.keys())
    s = {g: choice["strong_star"] for g in R.generators}
    o = {g: "panel_open" for g in R.generators}
    d_u = R.policy(o, "V", rows) - R.policy(s, "V", rows)
    d_a = R.policy(o, "F", rows) - R.policy(s, "F", rows)
    hw = projected_half_widths(
        R, {"delta2o_U": lambda rows: (None if R.policy(o, "V", rows) is None or R.policy(s, "V", rows) is None
                                       else R.policy(o, "V", rows) - R.policy(s, "V", rows))},
        k_test_clusters, cfg["bootstrap"]["regret_draws"], cfg["seed"], "promotion")["delta2o_U"]
    out["dev_delta2o_U"], out["dev_delta2o_A"] = d_u, d_a
    out["projected_half_width"] = hw and hw["half_width"]
    out["conditions"], out["promoted"] = decide_promotion(
        t_o, d_u, d_a, out["projected_half_width"], pr)
    return out


def _delta6(R, rows, state, feasible=None):
    vals = []
    for r in S.ALL_MODELS:
        if feasible is not None and r not in feasible:
            continue  # an infeasible reviewer has no threshold: left out, listed
        op = [rows[g].get((r, state)) for g in S.OPEN_MODELS if S.FAMILY[g] != S.FAMILY[r]]
        co = [rows[g].get((r, state)) for g in S.CORE_GENERATORS if S.FAMILY[g] != S.FAMILY[r]]
        if not op or not co or any(v is None for v in op + co):
            continue
        vals.append(sum(op) / len(op) - sum(co) / len(co))
    return sum(vals) / len(vals) if vals else None


def delta6(all_view, thresholds, draws, seed, label):
    gens = [g for g in list(S.CORE_GENERATORS) + list(S.OPEN_MODELS) if g in all_view.generators]
    R = Rates(all_view, dict(thresholds["reviewers"]), generators=gens)
    keys = R.keys()
    rows0 = R.rows(keys)
    feasible = {r for r, t in thresholds["reviewers"].items() if t is not None}
    point = {"U": _delta6(R, rows0, "V", feasible), "A": _delta6(R, rows0, "F", feasible)}
    per_reviewer = {}
    for r in sorted(feasible):
        op = [rows0[g].get((r, "V")) for g in S.OPEN_MODELS if S.FAMILY[g] != S.FAMILY[r] and g in rows0]
        co = [rows0[g].get((r, "V")) for g in S.CORE_GENERATORS if S.FAMILY[g] != S.FAMILY[r] and g in rows0]
        if op and co and None not in op + co:
            per_reviewer[r] = sum(op) / len(op) - sum(co) / len(co)
    rng = random.Random(f"{seed}|{label}")
    dist = {"U": [], "A": []}
    for _ in range(draws):
        rows = R.rows(keys, draw_clusters(rng, R.clusters))
        for k, st in (("U", "V"), ("A", "F")):
            dist[k].append(_delta6(R, rows, st, feasible))
    ci = {k: ([_pct(v, 0.025), _pct(v, 0.975)] if any(x is not None for x in v) else None)
          for k, v in dist.items()}
    return {"estimate": point, "ci95": ci, "per_reviewer_U": per_reviewer,
            "infeasible_reviewers_left_out": sorted(set(S.ALL_MODELS) - feasible),
            "clusters": len(R.clusters), "draws": draws}


def diag_blocks(core_view, all_view, thresholds, extension=True):
    thr = dict(thresholds["reviewers"])
    Rc = Rates(core_view, thr, generators=list(S.CORE_GENERATORS))
    rows = Rc.rows(Rc.keys())
    out = {"strong_same_model": {}, "cheap_same_family": {}, "open_same_model": {}}
    def ok(cols):
        return all(thr.get(r) is not None for r in cols)

    for x, st in (("U", "V"), ("A", "F"), ("C", "C")):
        out["strong_same_model"][x] = d_diag(Rc, list(S.CORE_GENERATORS), list(S.CORE_GENERATORS), st, rows) \
            if ok(S.CORE_GENERATORS) or st == "C" else "undefined: an infeasible reviewer in the block"
        out["cheap_same_family"][x] = d_diag(Rc, list(S.CORE_GENERATORS), list(S.CHEAP_REVIEWERS), st, rows) \
            if ok(S.CHEAP_REVIEWERS) or st == "C" else "undefined: an infeasible reviewer in the block"
    if extension:
        Ro = Rates(all_view, thr, generators=list(S.OPEN_MODELS))
        rows_o = Ro.rows(Ro.keys())
        for x, st in (("U", "V"), ("A", "F"), ("C", "C")):
            out["open_same_model"][x] = d_diag(Ro, list(S.OPEN_MODELS), list(S.OPEN_MODELS), st, rows_o) \
                if ok(S.OPEN_MODELS) or st == "C" else "undefined: an infeasible reviewer in the block"
    return out


def unit_for(choice, policy, g):
    """The reviewer (or panel) a policy uses for generator g; None if undefined."""
    if policy == "fixed":
        return choice["r_star"]
    if policy == "generator_aware":
        return choice["generator_aware"].get(g)
    if policy == "exclusion":
        if g in choice["exclusion"]:
            return choice["exclusion"][g]
        return choice["r_star"] if S.FAMILY[choice["r_star"]] != S.FAMILY[g] else None
    if policy in ("strong_star", "cheap_star"):
        return choice[policy]
    return policy  # a panel


def pipeline_risk(view, thresholds, choice, near_misses, eligible_cves, generators, policies,
                  attempts_per_cell=10):
    """Section 14.7: mean over g of mean over eligible CVEs of (near-misses / k) x U.

    A CVE with near-misses but no U under the policy (no bank pair, or a pair
    whose reviews do not exist, e.g. a block that ran on development only)
    makes its generator row undefined: the row is not averaged as if that
    CVE contributed nothing. The count of such CVEs is reported."""
    pan = {}
    if thresholds.get("panel_cheap") is not None:
        pan["panel_cheap"] = (list(S.CHEAP_REVIEWERS), thresholds["panel_cheap"])
    if thresholds.get("panel_open") is not None and all(
            any(k[2] == m for k in view.obs) for m in S.OPEN_MODELS):
        pan["panel_open"] = (list(S.OPEN_MODELS), thresholds["panel_open"])
    R = Rates(view, dict(thresholds["reviewers"]), panels=pan, generators=list(generators))
    pair_of = {(p["cve"], p["generator"]): pid for pid, p in view.pairs.items()}
    out = {}
    for pol in policies:
        rows, excluded = [], 0
        for g in generators:
            unit = unit_for(choice, pol, g)
            if unit is None:
                continue
            vals = []
            for cve in eligible_cves:
                nm = near_misses.get((cve, g), 0)
                if nm == 0:
                    vals.append(0.0)
                    continue
                pid = pair_of.get((cve, g))
                u = R.items.get(pid, {}).get((unit, "V")) if pid else None
                if u is None:
                    excluded += 1
                    vals = None  # undefined row: do not average around the gap
                    break
                vals.append(nm / float(attempts_per_cell) * u)
            if vals:
                rows.append(sum(vals) / len(vals))
        out[pol] = {"risk_per_attempt": sum(rows) / len(rows) if len(rows) == len(generators) else None,
                    "cves_with_near_misses_but_no_U": excluded}
    return out
