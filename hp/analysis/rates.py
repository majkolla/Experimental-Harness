"""U, A, C per cell, panels, and the hierarchical aggregation (sections 14.1, 14.5, 15.1).

Aggregation is always trials -> candidate -> CVE -> generator row -> equal-
generator average. Calls are never pooled. One pair per (CVE, generator), so a
row mean over pairs is a mean over CVEs with equal weight.

A bootstrap resample is a multiset of clusters; a pair's weight is its
cluster's multiplicity. `Rates` precomputes every per-candidate number once
(at fixed thresholds) and sums it per (cluster, generator), so one resample
costs O(clusters x generators x keys), not a pass over the calls.

Panels (section 11.5, SPEC_ANSWERS Q7d): each member approves under the
panel's common cut-off. The primary per-candidate estimate is the mean over
all 36 trial matchings, which equals h(p1(x), p2(x), p3(x)) of the members'
per-trial mean approvals; the identity matching (trial j with trial j) is kept
as the check under the key `<panel>#identity`.
"""

import math

from .. import study_config as S
from .data import TRIALS, approve

STATES = ("V", "F")


def h3(p1, p2, p3):
    """P(at least 2 of 3 independent approvals): the 2-of-3 independence reference."""
    return p1 * p2 + p1 * p3 + p2 * p3 - 2 * p1 * p2 * p3


def discrimination(v_trials, f_trials):
    """1 / 0.5 / 0 for mean risk(V) > / = / < mean risk(F) over VALID trials; None if
    either side has no valid trial (left out of C and counted, SPEC_ANSWERS Q1)."""
    v = [t.risk for t in v_trials if t.ok and t.risk is not None]
    f = [t.risk for t in f_trials if t.ok and t.risk is not None]
    if not v or not f:
        return None
    mv, mf = sum(v) / len(v), sum(f) / len(f)
    return 1.0 if mv > mf else (0.5 if mv == mf else 0.0)


class Rates:
    """Per-candidate rates at fixed thresholds, aggregated hierarchically."""

    def __init__(self, view, thresholds, coding="primary", panels=None, generators=None,
                 reviewers=None):
        self.view = view
        self.coding = coding
        gens = list(generators) if generators is not None else [
            g for g in S.CORE_GENERATORS if g in view.generators]
        self.generators = gens
        revs = list(reviewers) if reviewers is not None else view.reviewers
        self.items = {}
        for pid, p in view.pairs.items():
            if p["generator"] not in gens:
                continue
            vals = {}
            for r in revs:
                t = thresholds.get(r)
                tv = view.trials(pid, "V", r)
                tf = view.trials(pid, "F", r)
                if all(x.status == "missing" for x in tv + tf):
                    continue
                vals[(r, "V")] = sum(approve(x, t, coding, "V") for x in tv) / len(TRIALS)
                vals[(r, "F")] = sum(approve(x, t, coding, "F") for x in tf) / len(TRIALS)
                c = discrimination(tv, tf)
                if c is not None:
                    vals[("C", r)] = c
                vals[("cost", r)] = sum(x.cost for x in tv + tf) / (2 * len(TRIALS))
            for name, (members, t) in (panels or {}).items():
                for state in STATES:
                    trials = [view.trials(pid, state, m) for m in members]
                    if any(all(x.status == "missing" for x in ts) for ts in trials):
                        continue
                    a = [[approve(x, t, coding, state) for x in ts] for ts in trials]
                    ps = [sum(x) / len(TRIALS) for x in a]
                    vals[(name, state)] = h3(*ps)
                    vals[(name + "#identity", state)] = sum(
                        sum(a[m][j] for m in range(3)) >= 2 for j in range(len(TRIALS))) / len(TRIALS)
                if all((m, "V") in vals for m in members):
                    vals[("cost", name)] = sum(vals[("cost", m)] for m in members)
            self.items[pid] = vals
        # per (cluster, generator): sums and counts per key
        self.sums = {}
        for pid, vals in self.items.items():
            p = view.pairs[pid]
            cell = self.sums.setdefault(p["cluster"], {}).setdefault(p["generator"], [{}, {}])
            for k, v in vals.items():
                cell[0][k] = cell[0].get(k, 0.0) + v
                cell[1][k] = cell[1].get(k, 0) + 1
        self.clusters = sorted(self.sums)

    # -- aggregation ------------------------------------------------------------

    def rows(self, keys, draw=None):
        """{g: {key: weighted mean over pairs}}; `draw` = {cluster: multiplicity}."""
        acc = {g: ({}, {}) for g in self.generators}
        for cl in (draw or {c: 1 for c in self.clusters}):
            w = (draw or {}).get(cl, 1)
            if not w or cl not in self.sums:
                continue
            for g, (s, n) in self.sums[cl].items():
                if g not in acc:
                    continue
                for k in keys:
                    if k in n:
                        acc[g][0][k] = acc[g][0].get(k, 0.0) + w * s[k]
                        acc[g][1][k] = acc[g][1].get(k, 0) + w * n[k]
        return {g: {k: (a[0][k] / a[1][k]) for k in a[0] if a[1][k]} for g, a in acc.items()}

    def overall(self, key, rows):
        """Equal-generator average; None if any generator row lacks the key."""
        vals = [rows[g].get(key) for g in self.generators]
        if not vals or any(v is None for v in vals):
            return None
        return sum(vals) / len(vals)

    def policy(self, mapping, state, rows):
        """Equal-generator average of each row's chosen unit (reviewer or panel)."""
        vals = [rows[g].get((mapping[g], state)) for g in self.generators]
        if not vals or any(v is None for v in vals):
            return None
        return sum(vals) / len(vals)

    def keys(self):
        ks = set()
        for vals in self.items.values():
            ks |= set(vals)
        return sorted(ks, key=str)


def logit(p, n):
    """Empirical logit with eps = 1/(2N) (PLAN.md section 10 item 10)."""
    eps = 1.0 / (2 * max(1, n))
    p = min(1 - eps, max(eps, p))
    return math.log(p / (1 - p))


def d_diag(rates, rows_g, cols_r, state_or_c, rows=None):
    """D_diag = mean(diagonal) - mean(off-diagonal) of a 3x3 block (section 14.4).

    `state_or_c` is "V" (U), "F" (A) or "C" (discrimination). Returns
    {"prob": D, "logit": D on the logit scale, "cells": {...}} or None.
    """
    rows = rows if rows is not None else rates.rows(
        [(r, state_or_c) if state_or_c in STATES else ("C", r) for r in cols_r])
    cells, n_pairs = {}, {}
    for g in rows_g:
        for r in cols_r:
            key = (r, state_or_c) if state_or_c in STATES else ("C", r)
            v = rows.get(g, {}).get(key)
            if v is None:
                return None
            cells[(g, r)] = v
            n_pairs[(g, r)] = sum(1 for pid, vals in rates.items.items()
                                  if rates.view.pairs[pid]["generator"] == g and key in vals)
    diag = [cells[(g, r)] for g, r in zip(rows_g, cols_r)]
    off = [cells[(g, r)] for g in rows_g for r in cols_r if cols_r.index(r) != rows_g.index(g)]
    d = sum(diag) / len(diag) - sum(off) / len(off)
    lg = {k: logit(v, 3 * n_pairs[k]) for k, v in cells.items()}
    ldiag = [lg[(g, r)] for g, r in zip(rows_g, cols_r)]
    loff = [lg[(g, r)] for g in rows_g for r in cols_r if cols_r.index(r) != rows_g.index(g)]
    return {"prob": d, "logit": sum(ldiag) / len(ldiag) - sum(loff) / len(loff),
            "cells": {f"{g}->{r}": v for (g, r), v in cells.items()}}


def cell_table(rates, reviewers):
    """Per (generator, reviewer) cell: U, A, C next to the counts behind them.

    `unresolved_V` / `unresolved_F` are trials coded fail-closed in the cell (of
    `trials_V` / `trials_F` scheduled); `C_excluded_pairs` are pairs left out of C
    because one side has no valid trial (SPEC_ANSWERS Q1), with their share of
    the cell's pairs. Rates are row means over pairs (CVEs), as in `Rates.rows`.
    """
    view = rates.view
    rows = rates.rows([(r, s) for r in reviewers for s in STATES] + [("C", r) for r in reviewers])
    out = {}
    for g in rates.generators:
        pids = [pid for pid in sorted(rates.items) if view.pairs[pid]["generator"] == g]
        out[g] = {}
        for r in reviewers:
            n_pairs = n_c_out = 0
            unres = {s: 0 for s in STATES}
            trials = {s: 0 for s in STATES}
            for pid in pids:
                if (r, "V") not in rates.items[pid]:
                    continue
                n_pairs += 1
                for s in STATES:
                    ts = view.trials(pid, s, r)
                    trials[s] += len(ts)
                    unres[s] += sum(1 for t in ts if not t.ok)
                if ("C", r) not in rates.items[pid]:
                    n_c_out += 1
            out[g][r] = {
                "U": rows[g].get((r, "V")), "A": rows[g].get((r, "F")), "C": rows[g].get(("C", r)),
                "pairs": n_pairs,
                "unresolved_V": unres["V"], "trials_V": trials["V"],
                "unresolved_F": unres["F"], "trials_F": trials["F"],
                "C_excluded_pairs": n_c_out,
                "C_excluded_share": (n_c_out / n_pairs) if n_pairs else None,
            }
    return out


def c_exclusions(table):
    """Totals of pairs left out of C, per reviewer and overall, from `cell_table`."""
    per = {}
    for g, cells in table.items():
        for r, c in cells.items():
            a = per.setdefault(r, [0, 0])
            a[0] += c["C_excluded_pairs"]
            a[1] += c["pairs"]
    tot = [sum(v[0] for v in per.values()), sum(v[1] for v in per.values())]
    fmt = lambda v: {"excluded_pairs": v[0], "pairs": v[1], "share": v[0] / v[1] if v[1] else None}
    return {"by_reviewer": {r: fmt(v) for r, v in sorted(per.items())}, "overall": fmt(tot)}
