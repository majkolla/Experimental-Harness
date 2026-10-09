"""Experiment B, the exploratory evidence screen (RQ4, section 13). Descriptive only.

On the Experiment B pairs (development, core generators), for the cheap
reviewers at their own frozen-on-development thresholds (panels at t_p):
* U, A and paired discrimination C per (reviewer, packet), next to e0;
* the best fixed (reviewer, packet): lowest U among those with A >= target;
* the panel with one packet per reviewer, for each of the 6 assignments;
* the panel on e0, on the same pairs.
No confirmatory claim is made.
"""

import itertools

from .. import study_config as S
from .rates import Rates


class PacketView:
    """A view whose reviewer trials come from a chosen packet (None = e0)."""

    def __init__(self, base, e0_view, packet_of):
        self.base, self.e0, self.packet_of = base, e0_view, packet_of
        self.pairs = base.pairs
        self.generators = base.generators

    @property
    def reviewers(self):
        return sorted(self.packet_of)

    def trials(self, pid, state, r, packet=None):
        pk = self.packet_of.get(r)
        if pk is None:
            return self.e0.trials(pid, state, r)
        return self.base.trials(pid, state, r, pk)


def analyse(expb_view, core_view, thresholds, packets, target):
    if not expb_view.pairs:
        return None
    gens = [g for g in S.CORE_GENERATORS if g in expb_view.generators]
    thr = dict(thresholds["reviewers"])
    tp = thresholds.get("panel_cheap")
    out = {"pairs": len(expb_view.pairs), "cves": len({p["cve"] for p in expb_view.pairs.values()}),
           "single": {}, "panel_assignments": {}, "panel_e0": None, "best_fixed": None}
    rev = list(S.CHEAP_REVIEWERS)
    for pk in [None] + list(packets):
        pv = PacketView(expb_view, core_view, {r: pk for r in rev})
        R = Rates(pv, thr, generators=gens, reviewers=rev)
        rows = R.rows(R.keys())
        for r in rev:
            out["single"][f"{r}/{pk or 'e0'}"] = {
                "U": R.overall((r, "V"), rows), "A": R.overall((r, "F"), rows),
                "C": R.overall(("C", r), rows)}
    feasible = [(v["U"], k) for k, v in out["single"].items()
                if v["A"] is not None and v["A"] >= target and v["U"] is not None]
    out["best_fixed"] = min(feasible)[1] if feasible else None
    if tp is not None:
        for perm in itertools.permutations(packets):
            assign = dict(zip(rev, perm))
            pv = PacketView(expb_view, core_view, assign)
            R = Rates(pv, thr, panels={"panel": (rev, tp)}, generators=gens, reviewers=rev)
            rows = R.rows(R.keys())
            label = ",".join(f"{r}:{assign[r]}" for r in rev)
            out["panel_assignments"][label] = {"U": R.overall(("panel", "V"), rows),
                                               "A": R.overall(("panel", "F"), rows)}
        pv = PacketView(expb_view, core_view, {r: None for r in rev})
        R = Rates(pv, thr, panels={"panel": (rev, tp)}, generators=gens, reviewers=rev)
        rows = R.rows(R.keys())
        out["panel_e0"] = {"U": R.overall(("panel", "V"), rows), "A": R.overall(("panel", "F"), rows)}
    return out
