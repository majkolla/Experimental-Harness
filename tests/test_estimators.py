"""Estimator identities, checked against brute force and closed forms."""

import itertools
import math
import random

import pytest

from hp import estimators as E
from tests import dgp


def _law_trials(probs, denom=1000):
    """Exact multiset realising an 8-cell joint law with rational weights."""
    trials = []
    for y, w in probs.items():
        trials.extend([y] * round(w * denom))
    return trials


def _random_law(rng):
    w = [rng.random() for _ in range(8)]
    s = sum(w)
    pats = list(itertools.product((0, 1), repeat=3))
    return {p: round(wi / s, 3) for p, wi in zip(pats, w)}


def test_the_gate_identity_R23_equals_sum_q_minus_2t():
    """R_{2/3} = q12 + q13 + q23 - 2t, exactly.

    Substituting t = p1 p2 p3 recovers the independence formula, so the
    Poisson-binomial reference is the special case rather than a separate model.
    The negative coefficient on t is the reason the majority gate is a poor
    detector of coupling.
    """
    rng = random.Random(1)
    for _ in range(200):
        trials = _law_trials(_random_law(rng))
        if len(trials) < 3:
            continue
        q = E.pairwise(trials)
        t = E.joint_all(trials)
        assert E.gate_risk(trials, 2) == pytest.approx(sum(q.values()) - 2 * t, abs=1e-9)


def test_poisson_binomial_matches_the_closed_form_for_n3():
    for ps in ([0.2, 0.4, 0.6], [0.05, 0.05, 0.9], [0.5, 0.5, 0.5]):
        p1, p2, p3 = ps
        want = p1 * p2 + p1 * p3 + p2 * p3 - 2 * p1 * p2 * p3
        assert E.poisson_binomial_ge_k(ps, 2) == pytest.approx(want)


def test_recombination_closed_form_equals_brute_force():
    """The O(2^n Bell(n) R) Mobius form against the O(R^n) enumeration."""
    rng = random.Random(2)
    for _ in range(40):
        R = rng.randint(3, 7)
        trials = [tuple(rng.randint(0, 1) for _ in range(3)) for _ in range(R)]
        for k in (1, 2, 3):
            assert E.recomb_gate_risk(trials, k) == pytest.approx(
                E.brute_recomb_gate_risk(trials, k), abs=1e-12
            )


def test_recombined_law_satisfies_the_same_gate_identity():
    """So D(2/3) = 3 dq - 2 dt holds exactly, which the sign argument relies on."""
    rng = random.Random(3)
    for _ in range(50):
        R = rng.randint(4, 9)
        trials = [tuple(rng.randint(0, 1) for _ in range(3)) for _ in range(R)]
        qr = E.recomb_pairwise(trials)
        tr = E.recomb_joint_all(trials)
        assert E.recomb_gate_risk(trials, 2) == pytest.approx(
            sum(qr.values()) - 2 * tr, abs=1e-12
        )

        st = E.cell_stats(trials, 2)
        assert st["D"] == pytest.approx(3 * st["dq"] - 2 * st["dt"], abs=1e-12)


def test_recombination_returns_none_when_replicates_cannot_be_distinct():
    trials = [(1, 0, 1), (0, 1, 1)]
    assert E.recomb_gate_risk(trials, 2) is None
    assert E.cell_stats(trials, 2) is None


def test_frechet_bounds_contain_the_truth_and_bracket_the_gate():
    """Marginals plus all pairwise joints leave R_{2/3} undetermined.

    This is why full n-tuples are recorded rather than pairwise summaries: the
    engineering shortcut "estimate each rate, estimate pairwise correlation,
    compute gate risk" is not approximate, it is unidentified.
    """
    rng = random.Random(4)
    widths = []
    for _ in range(200):
        trials = _law_trials(_random_law(rng))
        if len(trials) < 3:
            continue
        ps, qs = E.marginals(trials), E.pairwise(trials)
        t = E.joint_all(trials)
        b = E.frechet_triple_bounds(ps, qs)
        assert b["t_lower"] - 1e-9 <= t <= b["t_upper"] + 1e-9
        r = E.gate_risk(trials, 2)
        assert b["R23_lower"] - 1e-9 <= r <= b["R23_upper"] + 1e-9
        widths.append(b["R23_upper"] - b["R23_lower"])
    assert max(widths) > 0.2, "some laws must be badly unidentified"


def test_non_identifiability_construction_is_reproduced():
    """Identical marginals, identical pairwise joints, threefold gate difference.

    Law A: mass 1/4 on 111, 100, 010, 001 -> R_2/3 = 1/4
    Law B: mass 1/4 on 110, 101, 011, 000 -> R_2/3 = 3/4
    Both have p_j = 1/2 and every q_jk = 1/4, i.e. exact pairwise independence.
    """
    a = _law_trials({(1, 1, 1): 0.25, (1, 0, 0): 0.25, (0, 1, 0): 0.25, (0, 0, 1): 0.25}, 400)
    b = _law_trials({(1, 1, 0): 0.25, (1, 0, 1): 0.25, (0, 1, 1): 0.25, (0, 0, 0): 0.25}, 400)
    for trials in (a, b):
        assert E.marginals(trials) == pytest.approx([0.5, 0.5, 0.5])
        assert all(v == pytest.approx(0.25) for v in E.pairwise(trials).values())
    assert E.gate_risk(a, 2) == pytest.approx(0.25)
    assert E.gate_risk(b, 2) == pytest.approx(0.75)


def test_n_eff_worked_example_and_its_refusals():
    """Three reviewers at p = 0.2 with unanimous false approval 0.04 -> 2.0."""
    # exact multiset: p = 0.2 per channel, t = 0.04
    trials = _law_trials(
        {
            (1, 1, 1): 0.04,
            (1, 0, 0): 0.16,
            (0, 1, 0): 0.16,
            (0, 0, 1): 0.16,
            (0, 0, 0): 0.48,
        },
        2500,
    )
    assert E.marginals(trials) == pytest.approx([0.2, 0.2, 0.2])
    assert E.n_eff(trials, homogeneous=True) == pytest.approx(2.0, abs=1e-9)
    # refused for heterogeneous panels: there is no unique "effective n" there
    assert E.n_eff(trials, homogeneous=False) is None
    # refused when the unanimity rate is zero rather than reported as infinite
    clean = _law_trials({(1, 0, 0): 0.5, (0, 0, 0): 0.5}, 100)
    assert E.n_eff(clean, homogeneous=True) is None


def test_amplification_is_suppressed_when_its_denominator_is_tiny():
    """A is unstable and undefined near zero; D in percentage points is not."""
    trials = _law_trials({(1, 0, 0): 0.02, (0, 0, 0): 0.98}, 5000)
    st = E.cell_stats(trials, 2)
    assert st["A"] is None
    assert st["D"] is not None


def test_pattern_table_separates_two_panels_with_equal_gate_risk():
    """Mass on 110 (one permissive reviewer) vs on 111 (panel-wide blind spot).

    Same R_{2/3}, opposite engineering response: replace a model, or abandon
    the redundancy argument.
    """
    a = _law_trials({(1, 1, 0): 0.3, (0, 0, 0): 0.7}, 1000)
    b = _law_trials({(1, 1, 1): 0.3, (0, 0, 0): 0.7}, 1000)
    assert E.gate_risk(a, 2) == pytest.approx(E.gate_risk(b, 2))
    assert E.pattern_counts(a) != E.pattern_counts(b)
    assert E.cell_stats(a, 2)["D_unan"] < E.cell_stats(b, 2)["D_unan"]


def test_identity_residual_is_zero_on_real_cells():
    trials = dgp.independent_trials([0.2, 0.4, 0.6], 5, reps=8)
    st = E.cell_stats(trials, 2)
    assert st["identity_residual"] == pytest.approx(0.0, abs=1e-12)
    assert math.isclose(st["p_bar"], 0.4, abs_tol=1e-12)
