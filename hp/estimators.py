"""Dependence estimators, computed offline from the frozen log.

SHARED: written for Experiment 1, reused unchanged by the v1.3 study
(gate_risk, pairwise, joint_all, recomb_* via hp/analysis/commonmode.py).

Naming follows *Formalisms and Modelling Choices*:

    p_j       marginal false-approval rate of reviewer channel j
    q_jk      same-panel joint false approval
    t         all-channel joint false approval
    R_{k/n}   gate risk, the primary endpoint
    D_{k/n}   gate dependence penalty, R_obs - R_recomb   (percentage points)
    A_{k/n}   gate amplification factor, R_obs / R_recomb (interval required)

Three choices in here are load-bearing and are worth stating at the top,
because each has an obvious-looking alternative that is wrong.

**The null is cross-replicate recombination, within task.** Pairing channel
outcomes drawn from *different* replicates of the same task and configuration
holds task, patch, reviewer identity, prompt, model version and treatment
literally fixed, and differs from the observed quantity in exactly one respect:
whether the n outcomes came from the same panel. The obvious alternative --
plug in p̂_j p̂_k -- is a convex combination

    E[p̂_j p̂_k] = (1/R) q_jk^same + (1 - 1/R) p_j p_k

that puts weight 1/R on the very same-panel joint whose excess is being
measured, so it leaks a 1/R fraction of the true dependence into the null. It
is computed here as `R_plugin` for the robustness display only.

**Recombination is valid only within a task.** Pooling tasks and recombining
across them fails to condition on difficulty and reproduces the same artefact
as p_j p_k: stable task heterogeneity alone manufactures apparent co-failure
with no panel coupling whatsoever (+7.9 pp in the worked example). `naive_pooled`
exists so the paper can show that curve, labelled as the trap it is.

**Reviewers are indexed by channel, not by seat.** Under seat rotation a seat
holds a different model in different replicates, so recombining by seat would
pair reviewer A's outcome with reviewer B's. Channels are model-stable by
construction (see design.py).
"""

import collections
import itertools
import math

EPS = 1e-12


# ---------------------------------------------------------------------------
# basic within-cell statistics. `trials` is a list of complete replicates,
# each a tuple of n outcomes indexed by channel.
# ---------------------------------------------------------------------------


def marginals(trials):
    R = len(trials)
    n = len(trials[0])
    return [sum(t[j] for t in trials) / R for j in range(n)]


def pairwise(trials):
    R = len(trials)
    n = len(trials[0])
    return {
        (j, k): sum(t[j] * t[k] for t in trials) / R
        for j, k in itertools.combinations(range(n), 2)
    }


def joint_all(trials):
    """t = P(every channel falsely approves)."""
    R = len(trials)
    return sum(all(t) for t in trials) / R


def pattern_counts(trials):
    """The full 2^n outcome table.

    Reported as a headline figure because two panels can share the same R_{2/3}
    for opposite reasons -- mass on 110 (one systematically permissive reviewer
    plus a coin flip) versus mass on 111 (a panel-wide blind spot) -- and the
    engineering response differs completely.
    """
    return collections.Counter(tuple(t) for t in trials)


def gate_risk(trials, k):
    return sum(sum(t) >= k for t in trials) / len(trials)


# ---------------------------------------------------------------------------
# cross-replicate recombination
# ---------------------------------------------------------------------------


def _set_partitions(items):
    if not items:
        yield []
        return
    first, rest = items[0], items[1:]
    for part in _set_partitions(rest):
        for i in range(len(part)):
            yield part[:i] + [[first] + part[i]] + part[i + 1 :]
        yield [[first]] + part


def recomb_stat(trials, f, idx=None):
    """E[f(Y_{i1}[c1], ..., Y_{im}[cm])] over tuples of *distinct* replicates.

    Closed form by Mobius inversion over set partitions of the channel index
    set: the sum over injective index tuples is

        S_distinct = sum_pi mu(pi) * S_pi,
        mu(pi) = prod_B (-1)^{|B|-1} (|B|-1)!,
        S_pi   = sum_y f(y) prod_B N_B[y|_B],

    with N_B[y|_B] the number of replicates matching pattern y on block B. For
    n = 3 this is exactly

        S_distinct = S_all - E12 - E13 - E23 + 2 E_equal,

    each term a sum over the eight outcome patterns weighted by joint counts.
    That makes the estimator O(2^n * Bell(n) * R) rather than O(R^n) -- which is
    the difference between a 2000-draw cluster bootstrap over six statistics
    finishing in seconds and finishing in minutes, and therefore the difference
    between the robustness analysis being explored and being skipped.
    """
    R = len(trials)
    idx = list(range(len(trials[0]))) if idx is None else list(idx)
    m = len(idx)
    if R < m:
        return None

    total = 0.0
    for part in _set_partitions(list(range(m))):
        mu = 1
        for block in part:
            mu *= (-1) ** (len(block) - 1) * math.factorial(len(block) - 1)
        counts = [
            collections.Counter(tuple(t[idx[j]] for j in block) for t in trials)
            for block in part
        ]
        s = 0.0
        for y in itertools.product((0, 1), repeat=m):
            v = f(y)
            if not v:
                continue
            prod = 1
            for block, cnt in zip(part, counts):
                prod *= cnt.get(tuple(y[j] for j in block), 0)
                if prod == 0:
                    break
            s += v * prod
        total += mu * s
    return total / math.perm(R, m)


def recomb_gate_risk(trials, k):
    return recomb_stat(trials, lambda y: 1.0 if sum(y) >= k else 0.0)


def recomb_pairwise(trials):
    n = len(trials[0])
    return {
        (j, k): recomb_stat(trials, lambda y: float(y[0] and y[1]), idx=(j, k))
        for j, k in itertools.combinations(range(n), 2)
    }


def recomb_joint_all(trials):
    n = len(trials[0])
    return recomb_gate_risk(trials, n)


def brute_recomb_gate_risk(trials, k):
    """O(R^n) reference implementation. Exists so the closed form can be tested."""
    R = len(trials)
    n = len(trials[0])
    num = den = 0
    for combo in itertools.permutations(range(R), n):
        den += 1
        if sum(trials[combo[j]][j] for j in range(n)) >= k:
            num += 1
    return num / den if den else None


# ---------------------------------------------------------------------------
# independence references
# ---------------------------------------------------------------------------


def poisson_binomial_ge_k(ps, k):
    """P(sum of independent heterogeneous Bernoullis >= k).

    Poisson-binomial, not binomial: reviewers are pinned, named, heterogeneous
    models, and assuming a common p would charge one weak panel member's
    contribution to "dependence".
    """
    dist = [1.0]
    for p in ps:
        nxt = [0.0] * (len(dist) + 1)
        for i, w in enumerate(dist):
            nxt[i] += w * (1 - p)
            nxt[i + 1] += w * p
        dist = nxt
    return sum(dist[k:])


def frechet_triple_bounds(ps, qs):
    """Sharp bounds on t given marginals and all pairwise joints (n = 3).

    t_L = max(0, q12+q13-p1, q12+q23-p2, q13+q23-p3)
    t_U = min(q12, q13, q23, 1-p1-p2-p3+q12+q13+q23)

    Since R_{2/3} = q12+q13+q23 - 2t exactly, these translate into sharp bounds
    on gate risk. Marginals plus *all* pairwise joints leave R_{2/3}
    undetermined up to twice the feasible width of t -- which is the whole
    reason full n-tuples are recorded rather than pairwise summaries.
    """
    p1, p2, p3 = ps
    q12, q13, q23 = qs[(0, 1)], qs[(0, 2)], qs[(1, 2)]
    s = q12 + q13 + q23
    t_lo = max(0.0, q12 + q13 - p1, q12 + q23 - p2, q13 + q23 - p3)
    t_hi = min(q12, q13, q23, 1 - p1 - p2 - p3 + s)
    return {
        "t_lower": t_lo,
        "t_upper": t_hi,
        "R23_lower": s - 2 * t_hi,
        "R23_upper": s - 2 * t_lo,
    }


def n_eff(trials, homogeneous):
    """log R_{n/n} / log p, for homogeneous panels under a unanimity gate only.

    Returned as None otherwise, on purpose. For heterogeneous panels or
    majority rules there is no unique "effective n": the answer depends on the
    gate rule, on which marginals are held fixed, and on the matching
    criterion. A number there would be a false summary of a multi-dimensional
    object. Note also that n_eff > n means negative dependence, not a bonus
    reviewer, and that it is extremely noisy because R_{n/n} sits inside a log.
    """
    if not homogeneous:
        return None
    n = len(trials[0])
    p = sum(marginals(trials)) / n
    r = gate_risk(trials, n)
    if not (EPS < p < 1 - EPS) or r <= EPS:
        return None
    return math.log(r) / math.log(p)


# ---------------------------------------------------------------------------
# one cell = one (task, panel, regime)
# ---------------------------------------------------------------------------


def cell_stats(trials, k, homogeneous=False):
    """All statistics for one (task, panel, regime) cell."""
    if len(trials) < len(trials[0]):
        return None
    n = len(trials[0])
    ps = marginals(trials)
    qs = pairwise(trials)
    t = joint_all(trials)

    r_obs = gate_risk(trials, k)
    r_rec = recomb_gate_risk(trials, k)
    q_rec = recomb_pairwise(trials)
    t_rec = recomb_joint_all(trials)

    dq = sum(qs[key] - q_rec[key] for key in qs) / len(qs)
    dt = t - t_rec

    out = {
        "n": n,
        "replicates_used": len(trials),
        "p": ps,
        "p_bar": sum(ps) / n,
        "q": qs,
        "q_recomb": q_rec,
        "t": t,
        "t_recomb": t_rec,
        "patterns": dict(pattern_counts(trials)),
        "R_obs": r_obs,
        "R_recomb": r_rec,
        "R_plugin": poisson_binomial_ge_k(ps, k),  # leaky; display only
        "R_unan_obs": gate_risk(trials, n),
        "R_unan_recomb": t_rec,
        "D": r_obs - r_rec,
        "D_unan": t - t_rec,
        "A": (r_obs / r_rec) if r_rec > 1e-3 else None,
        "delta": {key: qs[key] - q_rec[key] for key in qs},
        "C": {key: (qs[key] / q_rec[key]) if q_rec[key] > 1e-3 else None for key in qs},
        "dq": dq,
        "dt": dt,
        "dt_over_dq": (dt / dq) if abs(dq) > 1e-6 else None,
        "n_eff": n_eff(trials, homogeneous),
    }
    if n == 3:
        out["frechet"] = frechet_triple_bounds(ps, qs)
        # R_{2/3} = q12 + q13 + q23 - 2t, exactly. Kept as a self-check on the
        # log rather than as a reported quantity.
        out["identity_residual"] = abs(
            gate_risk(trials, 2) - (sum(qs.values()) - 2 * t)
        )
    return out


def gate_gap_sign_note(cell):
    """Why the majority gate cannot be monitored without a third-order statistic.

    For n = 3, D(2/3) = 3 dq - 2 dt, so the *sign* of the majority-gate effect
    is decided by whether dt/dq exceeds 3/2 -- and is therefore not determined
    by the marginals and the pairwise rates. A concentrated common cause (one
    context packet that misleads the whole panel at once) loads the triple
    rather than the pairs, pushing dt/dq above 3/2, driving unanimous false
    approval up sharply while the measured 2-of-3 rate goes *down*. A team
    watching only that number reads a worsening panel as redundancy working.
    """
    ratio = cell.get("dt_over_dq")
    if ratio is None:
        return "indeterminate (dq ~ 0)"
    return "concentrated" if ratio > 1.5 else "diffuse"
