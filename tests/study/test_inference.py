"""D_diag (14.4), promotion (15.7), Holm and the decision rules (15.3, 15.4, Q8), Δ6."""

import itertools

import pytest

from hp import study_config as S
from hp.analysis import confirm as CF
from hp.analysis import extension as EXT
from hp.analysis.rates import Rates, d_diag
from tests.study.helpers import make_view, ok

GENS, REVS = list(S.CORE_GENERATORS), list(S.CORE_GENERATORS)


class _Rows:
    """d_diag needs rates.items / view.pairs only for cell sizes on the logit scale."""

    def __init__(self, n=10):
        self.items = {f"{g}{i}": {(r, "V"): 0 for r in REVS} for g in GENS for i in range(n)}
        self.view = type("V", (), {"pairs": {f"{g}{i}": {"generator": g} for g in GENS for i in range(n)}})


@pytest.mark.parametrize("bump", [0.0, 0.07, -0.05])
def test_d_diag_recovers_a_planted_diagonal_bump_and_ignores_additive_effects(bump):
    alpha = {"A": 0.10, "B": 0.25, "C": 0.05}     # how hard each generator's defects are
    beta = {"A": 0.02, "B": 0.20, "C": 0.11}      # how lenient each reviewer is
    rows = {g: {(r, "V"): 0.2 + alpha[g] + beta[r] + (bump if g == r else 0.0) for r in REVS} for g in GENS}
    d = d_diag(_Rows(), GENS, REVS, "V", rows)
    assert d["prob"] == pytest.approx(bump, abs=1e-12)
    no_bump = {g: {(r, "V"): 0.2 + alpha[g] + beta[r] for r in REVS} for g in GENS}
    assert d_diag(_Rows(), GENS, REVS, "V", no_bump)["prob"] == pytest.approx(0.0, abs=1e-12)


def test_d_diag_logit_scale_is_reported_and_zero_for_logit_additive_effects():
    import math
    lg = lambda x: 1 / (1 + math.exp(-x))  # noqa: E731
    rows = {g: {(r, "V"): lg(-1 + 0.4 * i + 0.3 * j) for j, r in enumerate(REVS)} for i, g in enumerate(GENS)}
    d = d_diag(_Rows(n=10), GENS, REVS, "V", rows)
    assert d["logit"] == pytest.approx(0.0, abs=1e-6)
    assert d["prob"] != pytest.approx(0.0, abs=1e-6)  # interaction depends on the scale


@pytest.mark.parametrize("t_o, du, da, hw", list(itertools.product(
    [None, 40], [0.01, 0.06], [-0.01, -0.06], [0.08, 0.12])))
def test_rq2o_promotion_fires_only_when_all_three_conditions_hold(t_o, du, da, hw):
    pr = {"ni_unsafe": 0.05, "ni_accept": 0.05, "max_half_width": 0.10}
    cond, promoted = EXT.decide_promotion(t_o, du, da, hw, pr)
    expected = t_o is not None and du < 0.05 and da > -0.05 and hw <= 0.10
    assert promoted is expected
    assert promoted is all(cond.values())


def _dist(center, spread=0.01, n=999):
    return [center + spread * ((i / (n - 1)) - 0.5) * 2 for i in range(n)]


MARGINS = {"ni_accept": 0.10, "ni_unsafe": 0.10}


def test_p_values_hypothesis_maximum_and_holm():
    point = {"delta1_U": -0.2, "delta1_A": 0.0, "cost_ratio": 0.3, "delta2_U": 0.0, "delta2_A": 0.0}
    dist = {"delta1_U": _dist(-0.2), "delta1_A": _dist(0.0), "cost_ratio": _dist(0.3),
            "delta2_U": _dist(0.12), "delta2_A": _dist(0.0)}
    out = CF.decide(point, dist, ["RQ1", "RQ2"], MARGINS, 0.025, "promotion_rule", 0.10)
    h = out["hypotheses"]
    assert h["RQ1"]["p"] == pytest.approx(1 / 1000) and h["RQ1"]["decision"] == "improvement"
    # RQ2 fails its unsafe-approval non-inferiority component: max over components
    assert h["RQ2"]["p"] == pytest.approx(1.0) and h["RQ2"]["decision"] == "insufficient precision"
    assert out["components"]["RQ2:cost_ratio"]["p_one_sided"] == pytest.approx(1 / 1000)
    assert h["RQ1"]["p_holm"] == pytest.approx(2 / 1000)  # smallest p times m = 2


def test_cheaper_and_safer_versus_non_inferior():
    base = {"cost_ratio": _dist(0.3), "delta2_A": _dist(0.0)}
    point = {"cost_ratio": 0.3, "delta2_U": 0.0, "delta2_A": 0.0}
    safer = CF.decide(point, {**base, "delta2_U": _dist(-0.08)}, ["RQ2"], MARGINS, 0.025, "promotion_rule", 0.1)
    noninf = CF.decide(point, {**base, "delta2_U": _dist(0.03)}, ["RQ2"], MARGINS, 0.025, "promotion_rule", 0.1)
    assert safer["hypotheses"]["RQ2"]["decision"] == "cheaper and safer"
    assert noninf["hypotheses"]["RQ2"]["decision"] == "cheaper and non-inferior"


def test_rq1_equivalence_is_reported_outside_the_family():
    point = {"delta1_U": 0.0, "delta1_A": 0.0, "cost_ratio": 0.3, "delta2_U": 0.0, "delta2_A": 0.0}
    dist = {"delta1_U": _dist(0.0, 0.05), "delta1_A": _dist(0.0), "cost_ratio": _dist(0.3),
            "delta2_U": _dist(0.0), "delta2_A": _dist(0.0)}
    h = CF.decide(point, dist, ["RQ1", "RQ2"], MARGINS, 0.025, "promotion_rule", 0.10)["hypotheses"]
    assert h["RQ1"]["practical_equivalence"] is True
    assert h["RQ1"]["decision"] == "insufficient precision"


def test_family_composition_and_fixed_sequence():
    assert CF.family("exclusion", False, "promotion_rule") == ["RQ1", "RQ2"]
    assert CF.family("generator_aware", True, "promotion_rule") == ["RQ1", "RQ2", "RQ2o"]
    assert CF.family("exploratory", False, "promotion_rule") == ["RQ2"]
    assert CF.family("exclusion", False, "fixed_sequence") == ["RQ1", "RQ2", "RQ2o"]
    point = {"cost_ratio": 0.3, "delta2_U": 0.0, "delta2_A": 0.0,
             "cost_ratio_o": 0.5, "delta2o_U": 0.0, "delta2o_A": 0.0}
    dist = {"cost_ratio": _dist(0.3), "delta2_U": _dist(0.2), "delta2_A": _dist(0.0),
            "cost_ratio_o": _dist(0.5), "delta2o_U": _dist(-0.1), "delta2o_A": _dist(0.0)}
    h = CF.decide(point, dist, ["RQ2", "RQ2o"], MARGINS, 0.025, "fixed_sequence", 0.1)["hypotheses"]
    assert h["RQ2"]["decision"] == "insufficient precision"
    assert h["RQ2o"]["decision"] == "insufficient precision"  # gated behind RQ2
    assert h["RQ2o"]["p_holm"] >= h["RQ2"]["p_holm"]


def test_delta6_uses_cross_family_cells_with_equal_reviewer_weight():
    rows = {g: {(r, "V"): (0.4 if g in S.OPEN_MODELS else 0.1) for r in S.ALL_MODELS}
            for g in list(S.CORE_GENERATORS) + list(S.OPEN_MODELS)}
    # same-family cells (e.g. X reviewing X, A reviewing A) must not count
    for g in S.ALL_MODELS[:3] + S.OPEN_MODELS:
        rows[g][(g, "V")] = 0.99
    assert EXT._delta6(None, rows, "V") == pytest.approx(0.3)


def test_confirm_refuses_an_unfrozen_study(dev_run):
    from hp.analysis import report
    from hp.bank.split import SplitLockError

    with pytest.raises(SplitLockError, match="frozen"):
        report.confirm(dev_run["cfg"], dev_run["rd"])
