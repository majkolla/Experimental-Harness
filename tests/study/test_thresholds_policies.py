"""Thresholds (12.3), policies (12.2) and the regret rule (12.4) on hand-built data."""

import random

import pytest

from hp import study_config as S
from hp.analysis import confirm as CF
from hp.analysis import policies as POL
from hp.analysis import regret as RG
from hp.analysis import thresholds as T
from hp.analysis.rates import Rates
from tests.study.helpers import make_view, ok


def _one_row_view(f_risks, reviewer="A", v_risks=None):
    """Generator A only; one pair per F-risk triple."""
    pairs, trials = [], {}
    for i, triple in enumerate(f_risks):
        pid = f"p{i}"
        pairs.append((pid, f"C{i}", f"K{i}", "A"))
        trials[(pid, "F", reviewer)] = [ok(x) for x in triple]
        trials[(pid, "V", reviewer)] = [ok(x) for x in (v_risks or triple)]
    return make_view(pairs, trials)


def test_threshold_is_the_smallest_observed_cutoff_meeting_the_target():
    """Section 18.4: known score set."""
    # 10 pairs x 3 trials = 30 F trials with risks 1..30; A(t) = t/30.
    f = [(3 * i + 1, 3 * i + 2, 3 * i + 3) for i in range(10)]
    v = _one_row_view(f)
    assert T.fit_reviewer(v, "A", 0.90, generators=["A"]) == 27   # 27/30 = 0.90
    assert T.fit_reviewer(v, "A", 0.91, generators=["A"]) == 28   # first observed cut-off above
    assert T.fit_reviewer(v, "A", 1.00, generators=["A"]) == 30


def test_infeasible_when_failed_calls_cap_acceptance():
    f = [(10, 20, 30)] * 9 + [(10, 20, 30)]
    v = _one_row_view(f)
    v.obs[("p0", "F", "A", None)][0].status = "timeout"     # fail-closed: never approves
    v.obs[("p1", "F", "A", None)][0].verdict = "abstain"
    v.obs[("p2", "F", "A", None)][0].status = "schema_invalid"
    assert T.fit_reviewer(v, "A", 0.91, generators=["A"]) is None
    assert T.fit_reviewer(v, "A", 0.90, generators=["A"]) == 30


def test_acceptance_is_averaged_over_generators_not_pooled():
    """Row A has 1 pair, row B has 9: pooled and hierarchical acceptance differ."""
    pairs = [("a0", "CA", "K0", "A")] + [(f"b{i}", f"CB{i}", f"K{i + 1}", "B") for i in range(9)]
    trials = {("a0", "F", "A"): [ok(90)] * 3}
    for i in range(9):
        trials[(f"b{i}", "F", "A")] = [ok(10)] * 3
    for pid, *_ in pairs:
        trials[(pid, "V", "A")] = [ok(50)] * 3
    v = make_view(pairs, trials)
    # at t=10: pooled acceptance 27/30 = 0.9, hierarchical (1.0 + 0.0)/2 = 0.5
    assert T.fit_reviewer(v, "A", 0.90, generators=["A", "B"]) == 90


def test_panel_cutoff_uses_h_of_member_means():
    pairs = [(f"p{i}", f"C{i}", f"K{i}", "A") for i in range(4)]
    trials = {}
    for i, (pid, *_ ) in enumerate(pairs):
        for m in "abc":
            trials[(pid, "F", m)] = [ok(10 * (i + 1))] * 3
            trials[(pid, "V", m)] = [ok(50)] * 3
    v = make_view(pairs, trials)
    assert T.fit_panel(v, ["a", "b", "c"], 0.75, generators=["A"]) == 30
    assert T.panel_acceptance(v, ["a", "b", "c"], 30, generators=["A"]) == 0.75


def _random_core_view(seed, n_cves=6):
    rng = random.Random(seed)
    pairs = [(f"{g}{i}", f"C{i}", f"K{i % 4}", g) for i in range(n_cves) for g in S.CORE_GENERATORS]
    lenient = {r: rng.uniform(-15, 15) for r in S.CORE_REVIEWERS}

    def fn(pid, state, r):
        base = 30 if state == "V" else 15
        return [ok(max(0, min(100, round(base + lenient[r] + rng.gauss(0, 12))))) for _ in range(3)]

    return make_view(pairs, {"_fn": fn, "_reviewers": list(S.CORE_REVIEWERS)})


@pytest.mark.parametrize("seed", range(12))
def test_exclusion_equals_fixed_in_every_row_except_the_family_of_r_star(seed):
    """Section 18.4."""
    v = _random_core_view(seed)
    thr = {r: T.fit_reviewer(v, r, 0.6) for r in S.CORE_REVIEWERS}
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    rows = R.rows(R.keys())
    choice = POL.select(R, rows, thr)
    r_star = choice["r_star"]
    for g in S.CORE_GENERATORS:
        if S.FAMILY[g] == S.FAMILY[r_star]:
            assert choice["exclusion"][g] != r_star
            assert S.FAMILY[choice["exclusion"][g]] != S.FAMILY[g]
            assert choice["exclusion_generator"] == g
        else:
            assert choice["exclusion"][g] == choice["fixed"][g] == r_star


def test_one_threshold_per_reviewer_is_used_by_every_policy():
    v = _random_core_view(3)
    thr = {r: T.fit_reviewer(v, r, 0.6) for r in S.CORE_REVIEWERS}
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    rows = R.rows(R.keys())
    choice = POL.select(R, rows, thr)
    for policy in ("fixed", "generator_aware", "exclusion"):
        for g, r in choice[policy].items():
            # the policy's row value is exactly the reviewer's rate at ITS threshold
            manual = []
            for pid, p in v.pairs.items():
                if p["generator"] == g:
                    manual.append(sum(int(t.risk <= thr[r]) for t in v.trials(pid, "V", r)) / 3)
            assert rows[g][(r, "V")] == pytest.approx(sum(manual) / len(manual))
    assert set(thr) == set(S.CORE_REVIEWERS)  # one number per reviewer, nothing per generator


def test_ties_are_broken_by_cost_then_model_id():
    pairs = [(f"{g}0", "C0", "K0", g) for g in S.CORE_GENERATORS]
    same = lambda pid, s, r: [ok(10)] * 3  # noqa: E731
    v = make_view(pairs, {"_fn": same, "_reviewers": list(S.CORE_REVIEWERS)})
    thr = {r: 50 for r in S.CORE_REVIEWERS}
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    rows = R.rows(R.keys())
    assert POL.select(R, rows, thr)["r_star"] == "A"   # all tied, equal cost -> ASCII order
    for pid in [p[0] for p in pairs]:
        for s in ("V", "F"):
            for t in v.obs[(pid, s, "A", None)]:
                t.cost = 9.0                               # A becomes the most expensive
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    assert POL.select(R, R.rows(R.keys()), thr)["r_star"] == "B"


def _tied_view():
    """A and B identical and good (high risk on V), C clearly worse (low risk on V)."""
    pairs = [(f"{g}{i}", f"C{i}", f"K{i}", g) for i in range(8) for g in S.CORE_GENERATORS]
    rng = random.Random(0)
    noise = {(pid, s, j): rng.gauss(0, 5) for pid, *_ in pairs for s in "VF" for j in range(3)}
    level = {"A": 70, "B": 70, "C": 6, "a": 12, "b": 12, "c": 12}

    def fn(pid, s, r):
        base = level[r] if s == "V" else 0
        return [ok(max(0, min(100, round(base + noise[(pid, s, j)])))) for j in range(3)]

    return make_view(pairs, {"_fn": fn, "_reviewers": list(S.CORE_REVIEWERS)})


def test_regret_rule_passes_two_tied_reviewers_and_fails_a_clearly_worse_one():
    """Section 18.4."""
    v = _tied_view()
    thr = {r: T.fit_reviewer(v, r, 0.9) for r in S.CORE_REVIEWERS}
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    rows = R.rows(R.keys())
    choice = POL.select(R, rows, thr)
    assert choice["r_star"] in ("A", "B")
    res = RG.regret_rule(v, choice, 0.9, draws=200, delta=0.05, share=0.8, seed=1)
    assert res["stability"]["fixed"]["stable"]
    for other in ("A", "B"):  # either of the tied pair is a harmless choice
        alt = dict(choice, r_star=other)
        assert RG.regret_rule(v, alt, 0.9, 200, 0.05, 0.8, 1)["stability"]["fixed"]["stable"]
    worse = dict(choice, r_star="C")
    assert not RG.regret_rule(v, worse, 0.9, 200, 0.05, 0.8, 1)["stability"]["fixed"]["stable"]


def test_primary_contrast_logic():
    v = _tied_view()
    thr = {r: T.fit_reviewer(v, r, 0.9) for r in S.CORE_REVIEWERS}
    R = Rates(v, thr, generators=list(S.CORE_GENERATORS))
    choice = POL.select(R, R.rows(R.keys()), thr)
    res = RG.regret_rule(v, choice, 0.9, 100, 0.05, 0.8, 2)
    assert res["primary"] in ("generator_aware", "exclusion")
    bad = dict(choice, r_star="C")
    assert RG.regret_rule(v, bad, 0.9, 100, 0.05, 0.8, 2)["primary"] == "exploratory"


def test_contrast_functions_on_a_known_table():
    v = _tied_view()
    thr = {r: 50 for r in S.CORE_REVIEWERS}
    R = CF.make_rates(v, {"reviewers": thr, "panel_cheap": 50})
    rows = R.rows(R.keys())
    choice = POL.select(R, rows, thr)
    fns = CF.contrasts(choice, "exclusion")
    assert fns["delta1_U"](R, rows) == pytest.approx(
        R.policy(choice["exclusion"], "V", rows) - R.policy(choice["fixed"], "V", rows))
    assert fns["cost_ratio"](R, rows) == pytest.approx(3.0)  # three calls of equal cost vs one
