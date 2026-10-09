"""RQ3 common mode (sections 4.4, 4.5, 4.7, 14.6; SPEC_ANSWERS Q5-Q7)."""

import itertools
import random

import pytest

from hp import estimators as E
from hp.analysis import commonmode as CM
from hp.analysis.rates import h3
from tests import dgp
from tests.study.helpers import make_view, ok

MEMBERS = ["a", "b", "c"]
THR = {m: 50 for m in MEMBERS}


def _view_from_member_trials(per_candidate):
    """per_candidate: list of 3x3 0/1 approvals (members x trials) on V."""
    pairs, trials = [], {}
    for i, a in enumerate(per_candidate):
        pid = f"p{i}"
        pairs.append((pid, f"C{i}", f"K{i}", "A"))
        for m, row in zip(MEMBERS, a):
            trials[(pid, "V", m)] = [ok(10 if x else 90) for x in row]
            trials[(pid, "F", m)] = [ok(10)] * 3
    return make_view(pairs, trials)


def test_mean_over_the_36_matchings_equals_h_of_the_per_trial_means():
    """Q7d / section 18.4: the panel's primary per-candidate estimate."""
    for bits in itertools.product((0, 1), repeat=9):
        a = [list(bits[0:3]), list(bits[3:6]), list(bits[6:9])]
        s = CM.candidate_stats(a)
        assert len(s["R2_matchings"]) == 36
        assert sum(s["R2_matchings"]) / 36 == pytest.approx(h3(*s["p"]))
        assert sum(s["R3_matchings"]) / 36 == pytest.approx(s["p"][0] * s["p"][1] * s["p"][2])
        assert s["R2"] == pytest.approx(h3(*s["p"]))


def test_within_patch_gap_is_zero_in_expectation_under_conditional_independence():
    """Section 18.4: a design check, expectation 0."""
    rng = random.Random(5)
    cands = []
    for _ in range(4000):
        pis = [rng.random() for _ in range(3)]
        cands.append([[int(rng.random() < p) for _ in range(3)] for p in pis])
    r = CM.panel_common_mode(_view_from_member_trials(cands), MEMBERS, THR, ["A"])
    assert abs(r["within_patch_design_check"]["plugin_gap"]) < 0.015
    assert abs(r["within_patch_design_check"]["recombination_gap"]) < 0.015


def _latent_candidates(pis):
    """Every member of a candidate has per-trial mean exactly pi (pi in thirds)."""
    out = []
    for pi in pis:
        k = round(pi * 3)
        row = [1] * k + [0] * (3 - k)
        out.append([row, row[1:] + row[:1], row[2:] + row[:2]])
    return out


def test_concentrated_common_cause_gives_dt_over_dq_above_three_halves():
    """Section 18.4, against the benchmark-level reference (Q6)."""
    pis = [1 / 3] * 9 + [1.0]          # most patches mildly hard, one fools everyone
    r = CM.panel_common_mode(_view_from_member_trials(_latent_candidates(pis)), MEMBERS, THR, ["A"])
    b = r["benchmark"]
    # exact: p = E[pi], q = E[pi^2], t = E[pi^3]
    p = sum(pis) / 10
    assert r["p"] == pytest.approx([p, p, p])
    assert b["dq"] == pytest.approx(sum(x * x for x in pis) / 10 - p * p)
    assert b["dt"] == pytest.approx(sum(x ** 3 for x in pis) / 10 - p ** 3)
    assert b["dt_over_dq"] > 1.5 and b["shape"] == "concentrated"
    assert b["d_gate_2of3"] == pytest.approx(3 * b["dq"] - 2 * b["dt"])
    assert b["gap"] == pytest.approx(b["d_gate_2of3"])
    assert b["d_gate_2of3"] < 0 < b["d_gate_3of3"]   # the majority gate hides it


def test_diffuse_common_cause_gives_dt_over_dq_near_one():
    pis = [0.0, 1 / 3, 2 / 3] * 4
    r = CM.panel_common_mode(_view_from_member_trials(_latent_candidates(pis)), MEMBERS, THR, ["A"])
    assert r["benchmark"]["dt_over_dq"] == pytest.approx(1.0)
    assert r["benchmark"]["shape"] == "diffuse"


def _gate_from_law(patterns):
    """Exact 2-of-3 rate of a multiset of member patterns (one candidate per pattern)."""
    return E.gate_risk(patterns, 2)


@pytest.mark.parametrize("name, patterns, expected", [
    ("never overlap", [(1, 0, 0)] * 3 + [(0, 1, 0)] * 3 + [(0, 0, 1)] * 3 + [(0, 0, 0)], 0.0),
    ("independent", dgp.independent_trials([0.3, 0.3, 0.3], 10), 0.216),
    ("fully shared", [(1, 1, 1)] * 3 + [(0, 0, 0)] * 7, 0.30),
    ("all errors in pairs", [(1, 1, 0)] * 3 + [(1, 0, 1)] * 3 + [(0, 1, 1)] * 3 + [(0, 0, 0)] * 11, 0.45),
])
def test_three_reviewers_at_thirty_percent_span_zero_to_forty_five(name, patterns, expected):
    """Section 4.7 (SPEC_ANSWERS Q20): 0, 0.216, 0.30, 0.45 at marginals 0.3 each."""
    assert E.marginals(patterns) == pytest.approx([0.3, 0.3, 0.3])
    assert _gate_from_law(patterns) == pytest.approx(expected)
    # and through the panel estimator, one deterministic candidate per pattern
    cands = [[[x] * 3 for x in pat] for pat in patterns]
    r = CM.panel_common_mode(_view_from_member_trials(cands), MEMBERS, THR, ["A"])
    assert r["R2"] == pytest.approx(expected)
    assert r["identity_residual"] == pytest.approx(0.0, abs=1e-12)


def test_independent_reviewers_show_no_benchmark_gap_without_shared_difficulty():
    pis = [[1 / 3, 2 / 3, 1 / 3]] * 6
    cands = []
    for p in pis:
        rows = [[1] * round(x * 3) + [0] * (3 - round(x * 3)) for x in p]
        cands.append(rows)
    r = CM.panel_common_mode(_view_from_member_trials(cands), MEMBERS, THR, ["A"])
    assert r["benchmark"]["gap"] == pytest.approx(0.0, abs=1e-12)
