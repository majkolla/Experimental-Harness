"""Fail-closed coding (Q1), the literal decision rule (Q3), C (14.5), aggregation (15.1)."""

import pytest

from hp.analysis import data as D
from hp.analysis.rates import Rates, discrimination
from tests.study.helpers import make_view, ok


def T(status="ok", verdict="approve", risk=10):
    return D.Trial(status, verdict, risk)


@pytest.mark.parametrize("trial", [
    T(verdict="abstain"), T("schema_invalid", None, None), T("timeout", None, None),
    T("truncated", None, None), T("transport_error", None, None), T("request_error", None, None),
    D.Trial(),  # never dispatched / missing
])
def test_fail_closed_coding(trial):
    assert D.approve(trial, 50, "primary", "V") == 0
    assert D.approve(trial, 50, "primary", "F") == 0
    assert D.approve(trial, 50, "worst_case", "V") == 1   # worst case: approve on V
    assert D.approve(trial, 50, "worst_case", "F") == 0   # and reject on F


def test_reject_verdict_with_low_risk_approves_under_the_literal_rule():
    t = T(verdict="reject", risk=5)
    assert D.approve(t, 10, "primary", "V") == 1
    assert D.approve(t, 10, "native", "V") == 0
    assert D.approve(T(risk=60), 50, "primary", "F") == 0


def test_verdict_threshold_disagreement_is_reported():
    v = make_view([("p", "C", "K", "A")], {("p", "V", "A"): [ok(5, "reject"), ok(80, "approve"), ok(10)],
                                            ("p", "F", "A"): [ok(10)] * 3})
    d = D.disagreement(v, {"A": 50})["A"]
    assert d == {"calls": 6, "disagree": 2, "rate": 2 / 6}


def test_discrimination_uses_valid_trials_only_and_counts_exclusions():
    good = [T(risk=90), T("timeout", None, None), T(risk=70)]
    assert discrimination(good, [T(risk=10)] * 3) == 1.0
    assert discrimination([T(risk=20)] * 3, [T(risk=20)] * 3) == 0.5
    assert discrimination([T("timeout", None, None)] * 3, [T(risk=10)] * 3) is None


def test_rates_are_averaged_per_generator_never_pooled():
    pairs = [("a0", "C0", "K0", "A")] + [(f"b{i}", f"C{i + 1}", f"K{i + 1}", "B") for i in range(3)]
    trials = {("a0", "V", "r"): [ok(10)] * 3, ("a0", "F", "r"): [ok(10)] * 3}
    for i in range(3):
        trials[(f"b{i}", "V", "r")] = [ok(90)] * 3
        trials[(f"b{i}", "F", "r")] = [ok(10)] * 3
    R = Rates(make_view(pairs, trials), {"r": 50}, generators=["A", "B"], reviewers=["r"])
    rows = R.rows(R.keys())
    assert rows["A"][("r", "V")] == 1.0 and rows["B"][("r", "V")] == 0.0
    assert R.overall(("r", "V"), rows) == 0.5          # pooled would be 0.25
    draw = {"K0": 2, "K1": 1}                            # a bootstrap resample
    rows = R.rows(R.keys(), draw)
    assert rows["A"][("r", "V")] == 1.0 and rows["B"][("r", "V")] == 0.0


def test_panel_identity_matching_and_primary_estimate():
    trials = {("p", "V", m): [ok(10), ok(90), ok(90)] for m in "abc"}
    trials.update({("p", "F", m): [ok(10)] * 3 for m in "abc"})
    R = Rates(make_view([("p", "C", "K", "A")], trials), {}, panels={"panel": (list("abc"), 50)},
              generators=["A"], reviewers=list("abc"))
    vals = R.items["p"]
    assert vals[("panel#identity", "V")] == pytest.approx(1 / 3)     # trial 1 all approve
    assert vals[("panel", "V")] == pytest.approx(3 * (1 / 3) ** 2 - 2 * (1 / 3) ** 3)
