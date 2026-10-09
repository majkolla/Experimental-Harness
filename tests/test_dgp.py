"""Planted-dependence recovery: the tests that decide whether the paper's
numbers mean anything.

An estimator bug here is silent and fatal -- the pipeline runs, the tables
format, and the conclusions are wrong. So every claim the analysis makes is
checked against a process whose true dependence structure is known by
construction.
"""

import random
import statistics

import pytest

from hp import bootstrap, estimators as E
from tests import dgp

# Exact multisets: the only error is the O(1/R) difference between the
# recombination estimator over a finite multiset and the product of marginals.
TOL = 2e-3


def test_conditionally_independent_reviewers_show_no_dependence():
    """Heterogeneous marginals, zero coupling -> D, dq, dt all ~ 0."""
    trials = dgp.independent_trials([0.2, 0.4, 0.6], denom=5, reps=8)
    st = E.cell_stats(trials, 2)
    assert st["p"] == pytest.approx([0.2, 0.4, 0.6], abs=1e-12)
    assert st["D"] == pytest.approx(0.0, abs=TOL)
    assert st["D_unan"] == pytest.approx(0.0, abs=TOL)
    assert st["dq"] == pytest.approx(0.0, abs=TOL)
    # and the observed gate risk sits on the Poisson-binomial reference
    assert st["R_obs"] == pytest.approx(
        E.poisson_binomial_ge_k([0.2, 0.4, 0.6], 2), abs=TOL
    )


def test_planted_shared_cause_is_recovered():
    """A shared packet state that lifts the whole panel at once."""
    trials = dgp.exchangeable_mixture_trials([0.2, 0.2, 0.2, 0.2, 0.2, 0.9], denom=20)
    st = E.cell_stats(trials, 2)
    assert st["dq"] > 0.05, "pairwise gap must detect it"
    assert st["D_unan"] > 0.05, "unanimity gate must detect it"
    assert st["A"] is None or st["A"] > 1.0


def test_concentrated_common_cause_hides_on_the_majority_gate():
    """One catastrophic packet state: unanimity up, 2-of-3 *down*.

    dq = Var(pi), dt = E[pi^3] - E[pi]^3, and D(2/3) = 3 dq - 2 dt, so the sign
    of the majority-gate effect turns on whether dt/dq exceeds 3/2. A shared
    cause with one dominant state loads the triple rather than the pairs and
    pushes the ratio above 3/2 -- so unanimous false approval rises sharply
    while the measured 2-of-3 rate falls. A team watching only that number
    reads a worsening panel as redundancy working.
    """
    pis = [0.30] * 5 + [0.95]
    trials = dgp.exchangeable_mixture_trials(pis, denom=20)
    st = E.cell_stats(trials, 2)

    assert st["dq"] > 0, "coupling is unambiguously present"
    assert st["dt"] > 0
    assert st["dt_over_dq"] > 1.5
    assert st["D"] < 0, "the majority gate reports an improvement"
    assert st["D_unan"] > 0.05, "while unanimous false approval is much worse"
    assert E.gate_gap_sign_note(st) == "concentrated"


def test_diffuse_common_cause_shows_up_on_the_majority_gate():
    pis = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45]
    trials = dgp.exchangeable_mixture_trials(pis, denom=20)
    st = E.cell_stats(trials, 2)

    assert st["dt_over_dq"] < 1.5
    assert st["D"] > 0
    assert st["D_unan"] > 0
    assert E.gate_gap_sign_note(st) == "diffuse"


def test_the_two_shapes_are_indistinguishable_without_the_triple():
    """Same detector, opposite verdicts -- which is why t must be reported."""
    conc = E.cell_stats(dgp.exchangeable_mixture_trials([0.30] * 5 + [0.95], 20), 2)
    diff = E.cell_stats(dgp.exchangeable_mixture_trials(
        [0.20, 0.25, 0.30, 0.35, 0.40, 0.45], 20), 2)
    # both are coupled, both have a positive pairwise gap
    assert conc["dq"] > 0 and diff["dq"] > 0
    # yet the majority gate moves in opposite directions
    assert conc["D"] < 0 < diff["D"]
    # and only the third-order statistic separates them
    assert conc["dt_over_dq"] > 1.5 > diff["dt_over_dq"]


def test_total_coupling_puts_the_crossover_at_p_equals_one_half():
    """Condorcet's condition.

    Under total coupling q = t = p against references p^2 and p^3,
    dt/dq = (p - p^3)/(p - p^2) = 1 + p, which exceeds 3/2 exactly when
    p > 1/2. A majority gate only improves on a single reviewer when the
    individual false-approval rate is under one half; coupling erodes precisely
    that advantage.
    """
    for p in (0.25, 0.4, 0.5, 0.6, 0.75):
        # total coupling: all channels always agree
        trials = [(1, 1, 1)] * round(p * 1000) + [(0, 0, 0)] * round((1 - p) * 1000)
        st = E.cell_stats(trials, 2)
        assert st["dt_over_dq"] == pytest.approx(1 + p, abs=0.01)
        if p < 0.5:
            assert st["D"] > 0
        elif p > 0.5:
            assert st["D"] < 0


def test_task_heterogeneity_alone_fabricates_dependence_against_a_pooled_null():
    """The trap the within-task recombination baseline exists to avoid.

    Two equally frequent strata, reviewers conditionally independent within
    stratum (zero coupling by construction): easy tasks p = 0.05, hard tasks
    p = 0.70. Against a pooled-marginal null this reads as Delta = +10.6 pp,
    C = 1.75 and a gate penalty of +7.9 pp. Every one of those numbers is an
    artefact of difficulty. The task-conditioned estimator must return ~0.
    """
    easy = dgp.independent_trials([0.05] * 3, denom=20)
    hard = dgp.independent_trials([0.70] * 3, denom=20)

    # task-conditioned: no dependence anywhere
    for trials in (easy, hard):
        st = E.cell_stats(trials, 2)
        assert st["D"] == pytest.approx(0.0, abs=TOL)
        assert st["dq"] == pytest.approx(0.0, abs=TOL)
    conditioned = statistics.mean(
        E.cell_stats(t, 2)["R_obs"] for t in (easy, hard)
    )
    assert conditioned == pytest.approx(0.3958, abs=1e-3)

    # pooled: the artefact, at the pairwise level and at the gate
    pooled = easy + hard
    ps = E.marginals(pooled)
    qs = E.pairwise(pooled)
    assert ps[0] == pytest.approx(0.375, abs=1e-9)
    assert list(qs.values())[0] == pytest.approx(0.24625, abs=1e-9)
    assert list(qs.values())[0] - ps[0] * ps[1] == pytest.approx(0.1056, abs=1e-3)
    assert list(qs.values())[0] / (ps[0] * ps[1]) == pytest.approx(1.751, abs=1e-2)

    naive = E.poisson_binomial_ge_k(ps, 2)
    assert naive == pytest.approx(0.3164, abs=1e-3)
    assert conditioned - naive == pytest.approx(0.0794, abs=2e-3)


def test_plugin_null_leaks_one_over_R_of_the_dependence():
    """Why the null is built by recombination and not by plugging in p-hat.

        E[p_j-hat p_k-hat] = (1/R) q_same + (1 - 1/R) p_j p_k

    so the plug-in "independence" baseline is a convex combination that puts
    weight 1/R on the very same-panel joint whose excess is being measured.
    With p = 0.4, q_same = 0.25 and R = 5 the true pairwise penalty is 9.0 pp
    and the plug-in estimate is 7.2 pp -- understated by exactly one fifth.
    """
    R, draws = 5, 20000
    cells, truth = dgp.sample_shared_cause(0.4, 0.25, w=0.3, R=R, draws=draws, seed=11)

    plugin, recomb = [], []
    for trials in cells:
        ps = E.marginals(trials)
        qs = E.pairwise(trials)
        qr = E.recomb_pairwise(trials)
        pairs = list(qs)
        plugin.append(
            statistics.mean(qs[e] - ps[e[0]] * ps[e[1]] for e in pairs)
        )
        recomb.append(statistics.mean(qs[e] - qr[e] for e in pairs))

    true_penalty = truth["q"] - truth["p"] ** 2
    assert true_penalty == pytest.approx(0.09, abs=1e-9)
    assert statistics.mean(recomb) == pytest.approx(true_penalty, abs=0.004)
    assert statistics.mean(plugin) == pytest.approx(
        true_penalty * (1 - 1 / R), abs=0.004
    )
    # and the direction of the error is always the same: it hides dependence
    assert statistics.mean(plugin) < statistics.mean(recomb)


def test_gate_level_plugin_reference_also_understates_the_penalty():
    R, draws = 5, 8000
    cells, _ = dgp.sample_shared_cause(0.4, 0.25, w=0.3, R=R, draws=draws, seed=12)
    d_recomb, d_plugin = [], []
    for trials in cells:
        st = E.cell_stats(trials, 2)
        d_recomb.append(st["R_obs"] - st["R_recomb"])
        d_plugin.append(st["R_obs"] - st["R_plugin"])
    assert statistics.mean(d_plugin) < statistics.mean(d_recomb)


# ---------------------------------------------------------------------------
# end-to-end recovery of a planted regime contrast through the analysis path
# ---------------------------------------------------------------------------


def _sample_cell(pis, R, rng):
    trials = []
    for _ in range(R):
        pi = pis[rng.randrange(len(pis))]
        trials.append(tuple(1 if rng.random() < pi else 0 for _ in range(3)))
    return trials


def _planted_cells(n_tasks, R, seed, shared_pis, diverse_pis):
    rng = random.Random(seed)
    cells = {}
    for i in range(n_tasks):
        task = f"task{i:02d}"
        for regime, pis in (("shared", shared_pis), ("diverse", diverse_pis)):
            cells[(task, "ABC", regime)] = {
                "task": task,
                "panel": "ABC",
                "regime": regime,
                "cluster": f"cluster{i:02d}",
                "label": "vulnerable",
                "functional": "pass",
                "homogeneous": False,
                "trials": _sample_cell(pis, R, rng),
                "incomplete": 0,
            }
    return cells


def test_analysis_recovers_a_planted_regime_effect_with_a_cluster_bootstrap():
    """Shared arm coupled, diverse arm not. The contrast must come out positive
    with an interval that excludes zero, through exactly the code path the paper
    will use."""
    cells = _planted_cells(
        n_tasks=30,
        R=24,
        seed=5,
        shared_pis=[0.15, 0.15, 0.15, 0.15, 0.15, 0.90],
        diverse_pis=[0.30] * 6,
    )
    per_task, clusters = bootstrap.per_task_stats(cells, k=2)
    agg = bootstrap.aggregate(per_task)

    assert bootstrap.contrast_regime(agg, "D_unan") > 0.05
    assert bootstrap.contrast_regime(agg, "dq") > 0.02

    stats = {
        "D_unan": (lambda a: bootstrap.contrast_regime(a, "D_unan"), "greater"),
        "dq": (lambda a: bootstrap.contrast_regime(a, "dq"), "greater"),
    }
    boot = bootstrap.cluster_bootstrap(per_task, clusters, stats, draws=400, seed=3)
    for name in stats:
        lo, hi = boot[name]["ci"]
        assert lo > 0, f"{name} interval must exclude zero: {boot[name]}"
        assert boot[name]["p"] < 0.05


def test_analysis_reports_no_effect_when_none_was_planted():
    """The negative control. A null result must look null."""
    cells = _planted_cells(
        n_tasks=30, R=24, seed=6, shared_pis=[0.35] * 6, diverse_pis=[0.35] * 6
    )
    per_task, clusters = bootstrap.per_task_stats(cells, k=2)
    stats = {"D": (lambda a: bootstrap.contrast_regime(a, "D"), "greater")}
    boot = bootstrap.cluster_bootstrap(per_task, clusters, stats, draws=400, seed=4)
    lo, hi = boot["D"]["ci"]
    assert lo < 0 < hi, boot["D"]


def test_holm_corrects_across_exactly_three_confirmatory_tests():
    p = {"H1": 0.01, "H2": 0.04, "H3": 0.20}
    out = bootstrap.holm(p)
    assert out["H1"] == pytest.approx(0.03)
    assert out["H2"] == pytest.approx(0.08)
    assert out["H3"] == pytest.approx(0.20)
    assert set(bootstrap.CONFIRMATORY) == {
        "H1_regime_R_obs",
        "H2_composition_R_obs",
        "H3_regime_D",
    }


def test_saturation_check_flags_a_pilot_that_cannot_move_the_gate():
    """The pilot's job is not results. It is establishing that the marginal
    false-approval rate lands in a band where the gate can move at all."""
    agg = {("AAA", "shared"): {"p_bar": 0.99}, ("BBB", "shared"): {"p_bar": 0.4}}
    warns = bootstrap.saturation_check(agg)
    assert len(warns) == 1 and "AAA/shared" in warns[0]
