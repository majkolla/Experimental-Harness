"""Development analysis, confirmatory analysis, and the report (sections 12-16).

`analyse_dev(cfg, runs_dir)` (development data only):
    thresholds for all nine reviewers and both panels (Q10), the policy
    identities, the regret rule and primary contrast (12.4), the RQ2o promotion
    check (15.7), feasibility half-widths (15.6), development rates labelled
    optimistic, Experiment B (RQ4), data quality. Writes the artefacts that
    are frozen: `thresholds.json`, `primary_choice.json`.

`confirm(cfg, runs_dir)` (test data; refuses unless frozen):
    re-derives the development artefacts from the logs and checks they equal
    the frozen files, then RQ1 / RQ2 (/ RQ2o) with Holm, RQ3 common mode, RQ5
    interaction contrasts, RQ6 (Δ6), pipeline risk, the section 15.5
    sensitivity analyses and data quality. Writes `test_report.json` and a
    text summary.

Every number comes from the logs (and the frozen artefacts, which are
themselves recomputed from the logs and compared). The report separates
`core` (never reads an extension row), `extension` and `inference` (the Holm
family, which includes RQ2o only when it was promoted on development data).
"""

import collections
import json

from .. import logs, study_config as S
from ..bank.split import SplitLockError, load_split
from . import commonmode as CM
from . import confirm as CF
from . import data as D
from . import expb as XB
from . import extension as EXT
from . import policies as POL
from . import regret as RG
from . import thresholds as T
from .rates import Rates


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, indent=1, default=_default) + "\n"


def _default(o):
    if isinstance(o, tuple):
        return list(o)
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(type(o))


def _keys_to_str(obj):
    if isinstance(obj, dict):
        return {("|".join(map(str, k)) if isinstance(k, tuple) else str(k)): _keys_to_str(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_keys_to_str(v) for v in obj]
    return obj


def _write(rd, name, obj):
    text = canonical_json(_keys_to_str(obj))
    (rd / name).write_text(text)
    return text


def n_test_clusters(cfg):
    return len(load_split(cfg).clusters("test"))


def subset(view, keep):
    """A copy of a View restricted to the pairs for which keep(pair) is true."""
    pairs = {pid: p for pid, p in view.pairs.items() if keep(p)}
    obs = {k: v for k, v in view.obs.items() if k[0] in pairs}
    return D.View(view.split, view.view, pairs, obs, view.unresolved, view.cost, view.extra)


def _dq(view, thresholds, cfg):
    return {
        "unresolved_trials_by_reviewer_state": {f"{r}/{s}": n for (r, s), n in sorted(view.unresolved.items())},
        "verdict_threshold_disagreement": D.disagreement(view, thresholds),
        "justifications_over_limit": D.long_justifications(view, cfg["caps"]["justification_words"]),
        "pairs": len(view.pairs), "clusters": len(view.clusters()),
    }


def _bank_stats(cfg, rd, split_name):
    rep = [r for r in logs.read(rd / logs.FILES["reproduction"]) if r.get("split") == split_name]
    att = [r for r in logs.read(rd / logs.FILES["attempts"])
           if r.get("kind") == "classification" and r.get("split") == split_name]
    sel = [r for r in logs.read(rd / logs.FILES["selection"]) if r.get("split") == split_name]
    sib = logs.latest((r for r in logs.read(rd / logs.FILES["siblings"])
                       if r.get("kind") == "sibling" and r.get("split") == split_name), "pair_id")
    stops = [r for r in logs.read(rd / logs.FILES["siblings"])
             if r.get("kind") == "sibling_stop" and r.get("split") == split_name]
    inp = [r for r in logs.read(rd / logs.FILES["inputs"]) if r.get("split") == split_name]
    return {
        "reproduction": dict(collections.Counter(r["status"] for r in rep)),
        "attempt_classes_by_generator": {
            g: dict(collections.Counter(r["class"] for r in att if r["generator"] == g))
            for g in sorted({r["generator"] for r in att})},
        "near_miss_cells": len(sel),
        "twins": dict(collections.Counter(r["status"] for r in sib.values())),
        "correction_stopped_at": stops[-1]["stopped_at_order"] if stops else None,
        "excluded_inputs": dict(collections.Counter(
            r["status"] for r in inp if r["status"] != "ok" and r.get("packet") is None)),
    }


# ---------------------------------------------------------------------------
# development
# ---------------------------------------------------------------------------


def analyse_dev(cfg, rd, write=True):
    target = cfg["acceptance_target"]
    ext = cfg["extension"]["enabled"]
    core = D.load(rd, "development", "core")
    bank = D.load(rd, "development", "core_bank")
    thr = T.fit_all(core, bank, target, ext)
    R = CF.make_rates(core, thr)
    rows = R.rows(R.keys())
    choice = POL.select(R, rows, thr["reviewers"])
    k = n_test_clusters(cfg)

    if choice.get("r_star") is None:
        rg = {"primary": "exploratory", "reason": "no feasible core reviewer"}
    else:
        rg = RG.regret_rule(core, choice, target, cfg["bootstrap"]["regret_draws"],
                            cfg["regret"]["delta"], cfg["regret"]["stability_share"], cfg["seed"])
    promo = EXT.promotion_check(bank, thr, choice, cfg, k) if ext and choice.get("r_star") else None
    promoted = bool(promo and promo["promoted"] and cfg["extension"]["rq2o_mode"] == "promotion_rule")

    feas = None
    if choice.get("r_star"):
        fns = CF.contrasts(choice, "generator_aware")
        fe = CF.contrasts(choice, "exclusion")
        feas = RG.projected_half_widths(
            R, {"delta1_U_generator_aware": lambda rows: fns["delta1_U"](R, rows),
                "delta1_U_exclusion": lambda rows: fe["delta1_U"](R, rows),
                "delta2_U": lambda rows: fns["delta2_U"](R, rows),
                "delta2_A": lambda rows: fns["delta2_A"](R, rows)},
            k, cfg["bootstrap"]["regret_draws"], cfg["seed"], "dev")
        for name, v in (feas or {}).items():
            if v:
                v["exceeds_0.10"] = v["half_width"] > 0.10

    dev_rates = {g: {r: {"U": rows[g].get((r, "V")), "A": rows[g].get((r, "F")),
                         "C": rows[g].get(("C", r))} for r in S.CORE_REVIEWERS}
                 for g in R.generators}
    primary_choice = {
        "primary": rg["primary"], "choice": choice, "regret": rg,
        "promotion": promo, "rq2o_promoted": promoted,
        "rq2o_mode": cfg["extension"]["rq2o_mode"],
        "family": CF.family(rg["primary"], promoted, cfg["extension"]["rq2o_mode"]) if ext
        else CF.family(rg["primary"], False, "promotion_rule"),
    }
    expb_view = D.load(rd, "development", "expB")
    report = {
        "label": "DEVELOPMENT (optimistic: thresholds and policies were fit on these data)",
        "thresholds": thr,
        "policies": choice,
        "primary_contrast": rg["primary"],
        "regret": rg,
        "rq2o_promotion": promo,
        "feasibility_half_widths": feas,
        "dev_rates_optimistic": dev_rates,
        "row_level_acceptance": {r: T.row_acceptance(R, r, rows) for r in S.CORE_REVIEWERS},
        "experiment_b": XB.analyse(expb_view, core, thr, cfg["experiment_b"]["packets"], target),
        "data_quality": {"core": _dq(core, thr["reviewers"], cfg),
                         "core_bank": _dq(bank, thr["reviewers"], cfg) if ext else None},
        "bank": _bank_stats(cfg, rd, "development"),
    }
    if write:
        _write(rd, "thresholds.json", thr)
        _write(rd, "primary_choice.json", primary_choice)
        _write(rd, "dev_report.json", report)
        (rd / "dev_report.txt").write_text(text_dev(report))
    return {"thresholds": thr, "primary_choice": primary_choice, "report": report}


# ---------------------------------------------------------------------------
# test (confirmatory)
# ---------------------------------------------------------------------------


def _load_frozen(rd):
    thr = json.loads((rd / "thresholds.json").read_text())
    pc = json.loads((rd / "primary_choice.json").read_text())
    return thr, pc


def confirm(cfg, rd):
    ok, reason = S.freeze_status(cfg)
    if not ok:
        raise SplitLockError(f"the confirmatory analysis runs only on a frozen study ({reason})")
    thr, pc = _load_frozen(rd)
    again = analyse_dev(cfg, rd, write=False)
    same = (canonical_json(_keys_to_str(again["thresholds"])) == canonical_json(thr)
            and canonical_json(_keys_to_str(again["primary_choice"])) == canonical_json(pc))
    if not same:
        raise RuntimeError("frozen development artefacts are not what the logs give; refusing")

    ext = cfg["extension"]["enabled"]
    core_out, point, dist = core_section(cfg, rd, thr, pc)
    ext_out, point_o, dist_o = extension_section(cfg, rd, thr, pc) if ext else (None, {}, {})
    margins = {"ni_accept": cfg["margins"]["ni_accept"], "ni_unsafe": cfg["margins"]["ni_unsafe"]}
    primary = pc["primary"]

    fam = pc["family"]
    inference = {"family": fam, "alpha_one_sided": cfg["alpha_one_sided"],
                 **CF.decide({**point, **point_o}, {**dist, **dist_o}, fam, margins,
                             cfg["alpha_one_sided"], pc["rq2o_mode"], cfg["margins"]["sesoi_unsafe"])}
    if primary == "exploratory":
        inference["RQ1"] = "exploratory (regret rule): estimates reported, no test"
    report = {
        "label": "TEST (confirmatory; frozen thresholds and policies)",
        "primary_contrast": primary,
        "artefacts_recomputed_identical": same,
        "core": core_out, "extension": ext_out, "inference": inference,
        "bank": _bank_stats(cfg, rd, "test"),
    }
    _write(rd, "test_report.json", report)
    (rd / "test_report.txt").write_text(text_test(report))
    return report


def core_section(cfg, rd, thr, pc):
    """Every core estimate. Reads core rows only (bit-identical with or without the
    extension in the logs). Returns (section, point, dist)."""
    B, seed = cfg["bootstrap"]["confirm_draws"], cfg["seed"]
    choice, primary = pc["choice"], pc["primary"]
    core = D.load(rd, "test", "core")
    Rc = CF.make_rates(core, thr)
    point, dist = CF.bootstrap(Rc, CF.contrasts(choice, primary), B, seed, "confirm|core")
    tp = thr.get("panel_cheap")
    out = {
        "estimates": CF.summarise(point, dist),
        "frame_clusters": len(Rc.clusters),
        "rq3_common_mode": {
            "cheap_panel_primary": CM.panel_common_mode(
                core, list(S.CHEAP_REVIEWERS), {m: tp for m in S.CHEAP_REVIEWERS},
                list(S.CORE_GENERATORS)) if tp is not None else None,
            "strong_panel_descriptive": CM.panel_common_mode(
                core, list(S.CORE_GENERATORS), thr["reviewers"], list(S.CORE_GENERATORS))
            if all(thr["reviewers"].get(m) is not None for m in S.CORE_GENERATORS) else None,
            "drivers_cheap_panel": CM.drivers(
                core, list(S.CHEAP_REVIEWERS), {m: tp for m in S.CHEAP_REVIEWERS},
                list(S.CORE_GENERATORS)) if tp is not None else None,
        },
        "rq5_interactions": EXT.diag_blocks(core, core, thr, extension=False),
        "pipeline_risk_commercial": EXT.pipeline_risk(
            core, thr, choice, _near_misses(rd, "test", S.CORE_GENERATORS), _eligible(rd, "test"),
            list(S.CORE_GENERATORS),
            ["fixed", "generator_aware", "exclusion", "strong_star", "cheap_star", "panel_cheap"]),
        "sensitivity": sensitivity(cfg, rd, core, thr, choice, primary),
        "data_quality": _dq(core, thr["reviewers"], cfg),
    }
    return out, point, dist


def extension_section(cfg, rd, thr, pc):
    """RQ2o, RQ6, the open block, open-panel common mode, open pipeline risk."""
    B, seed = cfg["bootstrap"]["confirm_draws"], cfg["seed"]
    choice, primary = pc["choice"], pc["primary"]
    bank = D.load(rd, "test", "core_bank")
    allv = D.load(rd, "test", "all_e0")
    point_o, dist_o = {}, {}
    if thr.get("panel_open") is not None and choice.get("strong_star"):
        Ro = CF.make_rates(bank, thr, panels=("panel_cheap", "panel_open"))
        point_o, dist_o = CF.bootstrap(Ro, CF.contrasts(choice, primary, extension_open=True, core=False),
                                       B, seed, "confirm|rq2o")
    paid = cfg["extension"]["paid_block_on_test"]
    d6_view = allv if paid else D.load(rd, "development", "all_e0")
    nm = _near_misses(rd, "test", S.ALL_MODELS)
    out = {
        "rq2o": CF.summarise(point_o, dist_o) if point_o else None,
        "rq6_delta6": {**EXT.delta6(d6_view, thr, B, seed, "delta6"),
                       "label": "test" if paid else "DEVELOPMENT ONLY (paid_block_on_test = false)"},
        "rq5_open_block": EXT.diag_blocks(allv, allv, thr, extension=True)["open_same_model"],
        "rq3_open_panel": CM.panel_common_mode(
            bank, list(S.OPEN_MODELS), {m: thr["panel_open"] for m in S.OPEN_MODELS},
            list(S.CORE_GENERATORS)) if thr.get("panel_open") is not None else None,
        "pipeline_risk_open": EXT.pipeline_risk(
            allv, thr, choice, nm, _eligible(rd, "test"), list(S.OPEN_MODELS),
            ["fixed", "exclusion", "strong_star", "cheap_star", "panel_cheap", "panel_open"]),
        "pipeline_risk_commercial_open_panel": EXT.pipeline_risk(
            bank, thr, choice, nm, _eligible(rd, "test"), list(S.CORE_GENERATORS), ["panel_open"]),
        "data_quality": _dq(D.load(rd, "test", "extension"), thr["reviewers"], cfg),
    }
    return out, point_o, dist_o


def _near_misses(rd, split_name, generators):
    c = collections.Counter()
    for r in logs.read(rd / logs.FILES["attempts"]):
        if (r.get("kind") == "classification" and r.get("split") == split_name
                and r["class"] == "near_miss" and r["generator"] in generators):
            c[(r["cve"], r["generator"])] += 1
    return c


def _eligible(rd, split_name):
    return sorted(r["cve"] for r in logs.read(rd / logs.FILES["reproduction"])
                  if r.get("split") == split_name and r["status"] == "eligible")


def sensitivity(cfg, rd, core, thr, choice, primary):
    """Section 15.5; none of these can rescue a claim."""
    B, seed = cfg["bootstrap"]["confirm_draws"], cfg["seed"]
    keys = ["delta1_U", "delta1_A", "delta2_U", "delta2_A", "cost_ratio"]

    def run(view, coding="primary", label=""):
        if not view.pairs:
            return None
        R = CF.make_rates(view, thr, coding=coding)
        fns = {k: v for k, v in CF.contrasts(choice, primary).items() if k in keys}
        p, d = CF.bootstrap(R, fns, B, seed, f"sensitivity|{label}")
        return CF.summarise(p, d)

    gens_per_cve = collections.defaultdict(set)
    for p in core.pairs.values():
        gens_per_cve[p["cve"]].add(p["generator"])
    indet = {r["cve"] for r in logs.read(rd / logs.FILES["attempts"])
             if r.get("kind") == "classification" and r.get("split") == "test"
             and r["class"] == "indeterminate" and r["generator"] in S.CORE_GENERATORS}
    out = {
        "1_native_verdicts": run(core, "native", "native"),
        "2_worst_case_coding": run(core, "worst_case", "worst"),
        "3_cves_with_all_three_generators": run(
            subset(core, lambda p: len(gens_per_cve[p["cve"]]) == 3), label="allgen"),
        "4_without_jenkins": run(subset(core, lambda p: p["cluster"] != "jenkinsci/jenkins"), label="nojenkins"),
        "5_second_correction_method": run(
            subset(core, lambda p: p.get("method") == "openweight_model"), label="method2")
        or "not available: no pairs corrected by the second method",
        "7_without_indeterminate_adjacent_cves": run(
            subset(core, lambda p: p["cve"] not in indet), label="noindet"),
    }
    cuts = CM.strata([p.get("similarity") for p in core.pairs.values()])
    if cuts:
        strat = {}
        for b in range(len(cuts) + 1):
            sub = subset(core, lambda p, b=b: p.get("similarity") is not None
                         and sum(p["similarity"] >= c for c in cuts) == b)
            if sub.pairs:
                R = CF.make_rates(sub, thr)
                rows = R.rows(R.keys())
                fns = CF.contrasts(choice, primary)
                strat[f"tercile_{b + 1}"] = {k: fns[k](R, rows) for k in keys if k in fns}
        out["6_similarity_strata"] = strat
    if thr.get("panel_cheap") is not None:
        cm = CM.panel_common_mode(core, list(S.CHEAP_REVIEWERS),
                                  {m: thr["panel_cheap"] for m in S.CHEAP_REVIEWERS}, list(S.CORE_GENERATORS))
        out["8_panel_trial_matchings"] = cm and {"R2_over_36_matchings": cm["matchings_36"],
                                                 "R2_identity": cm["identity_matching"]["R2"],
                                                 "R2_primary": cm["R2"]}
    out["9_logit_scale_contrasts"] = "see core.rq5_interactions[*][*].logit"
    return out


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------


def _f(v, nd=3):
    if v is None:
        return "n/a"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_f(x, nd) for x in v) + "]"
    if isinstance(v, float):
        return f"{v:+.{nd}f}" if v < 0 else f"{v:.{nd}f}"
    return str(v)


def text_dev(rep):
    L = [rep["label"], ""]
    L.append("thresholds (one per reviewer, shared by every policy; fit on the core bank):")
    for r, t in sorted(rep["thresholds"]["reviewers"].items()):
        L.append(f"  {r}: {_f(t)}")
    L.append(f"  panel_cheap t_p: {_f(rep['thresholds']['panel_cheap'])}   "
             f"panel_open t_o: {_f(rep['thresholds']['panel_open'])}")
    p = rep["policies"]
    L.append(f"\nr* = {p.get('r_star')}  strong* = {p.get('strong_star')}  cheap* = {p.get('cheap_star')}")
    L.append(f"generator-aware = {p.get('generator_aware')}  exclusion = {p.get('exclusion')}")
    L.append(f"primary contrast (regret rule): {rep['primary_contrast']}")
    for k, v in (rep["regret"].get("stability") or {}).items():
        L.append(f"  {k:<26} within delta in {_f(v['share_within_delta'])} of resamples"
                 f"{'  STABLE' if v['stable'] else ''}")
    if rep["rq2o_promotion"]:
        pr = rep["rq2o_promotion"]
        L.append(f"RQ2o promotion: {pr['promoted']}  conditions {pr['conditions']}")
    if rep["feasibility_half_widths"]:
        L.append("projected half-widths at the test cluster count:")
        for k, v in rep["feasibility_half_widths"].items():
            L.append(f"  {k:<28} {_f(v and v['half_width'])}"
                     f"{'  EXCEEDS 0.10: claim limited' if v and v['exceeds_0.10'] else ''}")
    L.append("\nunresolved trials (fail-closed) by reviewer/state:")
    L.append("  " + str(rep["data_quality"]["core"]["unresolved_trials_by_reviewer_state"]))
    return "\n".join(L) + "\n"


def text_test(rep):
    L = [rep["label"], f"primary contrast: {rep['primary_contrast']}", ""]
    est = rep["core"]["estimates"]
    for k in ("delta1_U", "delta1_A", "delta2_U", "delta2_A", "cost_ratio"):
        if k in est:
            L.append(f"  {k:<12} {_f(est[k]['estimate'])}  95% CI {_f(est[k]['ci95'])}")
    if rep["extension"] and rep["extension"].get("rq2o"):
        for k, v in rep["extension"]["rq2o"].items():
            if k.startswith(("delta2o", "cost_ratio_o")):
                L.append(f"  {k:<12} {_f(v['estimate'])}  95% CI {_f(v['ci95'])}")
    inf = rep["inference"]
    L.append(f"\nHolm family {inf['family']} at one-sided {inf['alpha_one_sided']}:")
    for h, d in inf["hypotheses"].items():
        L.append(f"  {h}: p={_f(d['p'], 4)} p_holm={_f(d['p_holm'], 4)} -> {d['decision']}")
    cm = rep["core"]["rq3_common_mode"]["cheap_panel_primary"]
    if cm:
        b = cm["benchmark"]
        L.append(f"\nRQ3 cheap panel: R2={_f(cm['R2'])} R3={_f(cm['R3'])} benchmark gap={_f(b['gap'])} "
                 f"dt/dq={_f(b['dt_over_dq'])} ({b['shape']})")
        L.append(f"  within-patch gap (design check, expectation 0): "
                 f"{_f(cm['within_patch_design_check']['plugin_gap'])}")
    return "\n".join(L) + "\n"
