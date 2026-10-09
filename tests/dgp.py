"""Exact data-generating processes for estimator tests.

Trials are constructed as *exact* multisets realising a target joint law rather
than sampled, so a test can assert a dependence estimate to 1e-4 instead of
guessing at a Monte-Carlo tolerance. The residual error is the O(1/R) difference
between the recombination estimator over a finite multiset and the product of
marginals, which is why the multisets are large.
"""

import itertools
import random


def independent_trials(ps, denom, reps=1):
    """Exact multiset with independent channels at rational marginals ps.

    Each p_j must be expressible as an integer over `denom`.
    """
    counts = [round(p * denom) for p in ps]
    assert all(abs(c / denom - p) < 1e-12 for c, p in zip(counts, ps)), ps
    trials = []
    for y in itertools.product((0, 1), repeat=len(ps)):
        m = 1
        for yj, c in zip(y, counts):
            m *= c if yj else denom - c
        trials.extend([y] * (m * reps))
    return trials


def exchangeable_mixture_trials(pis, denom, n=3):
    """Mixture over latent states; within a state channels are independent.

    This is the shared-cause structure that matters: a state is a context
    packet, and `pis` is the per-packet approval propensity it induces. It gives

        p = E[pi],  q = E[pi^2],  t = E[pi^3],

    so dq = Var(pi) and dt = E[pi^3] - E[pi]^3 -- and the *shape* of the pis,
    not just their mean, decides dt/dq and therefore the sign of the majority
    gate effect.
    """
    trials = []
    for pi in pis:
        trials.extend(independent_trials([pi] * n, denom))
    return trials


def sample_shared_cause(p_target, q_target, w, R, draws, seed=0, n=3):
    """iid cells of R replicates from an exchangeable law with given p and q.

    With probability w the state is "all channels take one common coin"
    (perfectly coupled); otherwise the channels are independent. The parameters
    a and b are solved so the law hits (p_target, q_target) exactly.

    Used to demonstrate the 1/R leak in the plug-in null, which is an artefact
    of *estimating* the marginals from the same R replicates and therefore
    invisible at large R.
    """
    # w a + (1-w) b   = p ; w a + (1-w) b^2 = q
    c = (p_target - q_target) / (1 - w)  # = b - b^2
    disc = 1 - 4 * c
    assert disc >= 0, (p_target, q_target, w)
    b = (1 - disc**0.5) / 2
    a = (p_target - (1 - w) * b) / w
    assert 0 <= a <= 1 and 0 <= b <= 1, (a, b)

    rng = random.Random(seed)
    cells = []
    for _ in range(draws):
        trials = []
        for _ in range(R):
            if rng.random() < w:
                v = 1 if rng.random() < a else 0
                trials.append(tuple([v] * n))
            else:
                trials.append(tuple(1 if rng.random() < b else 0 for _ in range(n)))
        cells.append(trials)
    return cells, {"a": a, "b": b, "p": p_target, "q": q_target}
