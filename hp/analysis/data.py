"""Read the logs into the analysis view: pairs, per-trial outcomes, coding.

Views (section 3, 12.6; SPEC_ANSWERS Q9):
* `core`: generators A, B, C x reviewers A, B, C, a, b, c, base input e0.
  Rows of any other kind are dropped *at load*, so no core estimate can ever
  depend on an extension row. Its bootstrap frame is the clusters with at
  least one evaluable core pair, derived from these rows only.
* `extension`: every e0 row that is not core (open reviewers on core pairs,
  every reviewer on open-generated pairs).
* `core_bank`: every e0 row on a core pair (generators A, B, C), any reviewer:
  what the thresholds of X, Y, Z and t_o are fit on (Q10), and RQ2o.
* `all_e0`: core + extension (for D_diag of the open block, Δ6).
* `expB`: Experiment B rows (with a packet).

Coding of one trial (section 11.5, SPEC_ANSWERS Q1, Q3):
* `primary` (fail-closed): approve iff the call ended `ok`, the verdict is not
  abstain, and risk <= t_r. A reject verdict with a low risk approves (Q3,
  literal); the disagreement rate is reported.
* `native`: approve iff the call ended `ok` with verdict approve (no threshold).
* `worst_case`: abstain, invalid or unresolved count as approve on V and reject
  on F; valid calls as in `primary`.
A trial with no `ok` record (after the four-attempt budget, or closed by a
non-retryable status) is unresolved.
"""

import collections

from .. import logs, study_config as S

TRIALS = (1, 2, 3)


class Trial:
    __slots__ = ("status", "verdict", "risk", "cost", "attempts", "words")

    def __init__(self, status="missing", verdict=None, risk=None, cost=0.0, attempts=0, words=None):
        self.status = status
        self.verdict = verdict
        self.risk = risk
        self.cost = cost
        self.attempts = attempts
        self.words = words

    @property
    def ok(self):
        return self.status == "ok"


def approve(trial, t, coding, state):
    if coding == "native":
        return int(trial.ok and trial.verdict == "approve")
    if not trial.ok or trial.verdict == "abstain":
        if coding == "worst_case":
            return int(state == "V")
        return 0
    if t is None:
        return 0
    return int(trial.risk <= t)


def in_view(row, view):
    g, r, pk = row.get("generator"), row.get("reviewer"), row.get("packet")
    core = g in S.CORE_GENERATORS and r in S.CORE_REVIEWERS and pk is None
    if view == "core":
        return core
    if view == "core_bank":
        return g in S.CORE_GENERATORS and pk is None
    if view == "extension":
        return pk is None and not core
    if view == "all_e0":
        return pk is None
    if view == "expB":
        return pk is not None
    raise ValueError(view)


class View:
    """Pairs and per-trial outcomes of one split and one view."""

    def __init__(self, split_name, view, pairs, obs, unresolved, cost, extra):
        self.split = split_name
        self.view = view
        self.pairs = pairs            # pair_id -> info dict
        self.obs = obs                # (pair_id, state, reviewer, packet) -> [Trial x3]
        self.unresolved = unresolved  # (reviewer, state) -> count of unresolved trials
        self.cost = cost              # reviewer -> [total cost, calls]
        self.extra = extra

    @property
    def reviewers(self):
        return sorted({k[2] for k in self.obs})

    @property
    def generators(self):
        return sorted({p["generator"] for p in self.pairs.values()})

    def clusters(self):
        return sorted({p["cluster"] for p in self.pairs.values()})

    def trials(self, pair_id, state, reviewer, packet=None):
        return self.obs.get((pair_id, state, reviewer, packet)) or [Trial() for _ in TRIALS]

    def mean_cost(self, reviewer):
        tot, n = self.cost.get(reviewer, (0.0, 0))
        return tot / n if n else None


def load(runs_dir, split_name, view="core"):
    """Build a View from the logs alone."""
    rows = [r for r in logs.read(runs_dir / logs.FILES["reviews"])
            if r.get("kind") == "review" and r.get("split") == split_name and in_view(r, view)]
    by_call = collections.defaultdict(list)
    for r in rows:
        by_call[r["call_id"]].append(r)

    obs = {}
    cost = collections.defaultdict(lambda: [0.0, 0])
    unresolved = collections.Counter()
    pair_meta = {}
    # Everything below iterates in sorted order: log order depends on thread
    # completion, and float sums must not (bit-identical estimates).
    for cid in sorted(by_call):
        attempts = sorted(by_call[cid], key=lambda r: r["attempt"])
        okr = [r for r in attempts if r["status"] == "ok"]
        last = okr[-1] if okr else attempts[-1]
        tr = Trial(
            status="ok" if okr else last["status"],
            verdict=last.get("verdict") if okr else None,
            risk=last.get("risk") if okr else None,
            cost=sum(r.get("cost") or 0.0 for r in attempts),
            attempts=len(attempts),
            words=last.get("justification_words") if okr else None,
        )
        key = (last["pair_id"], last["state"], last["reviewer"], last.get("packet"))
        lst = obs.setdefault(key, [Trial() for _ in TRIALS])
        lst[int(last["trial"]) - 1] = tr
        if last.get("packet") is None:
            cost[last["reviewer"]][0] += tr.cost
            cost[last["reviewer"]][1] += 1
        if not tr.ok:
            unresolved[(last["reviewer"], last["state"])] += 1
        pair_meta.setdefault(last["pair_id"], {
            "pair_id": last["pair_id"], "cve": last["cve"], "cluster": last["cluster"],
            "generator": last["generator"]})

    # pair attributes from the bank logs (filtered to the pairs in this view)
    sel = {r["pair_id"]: r for r in logs.read(runs_dir / logs.FILES["selection"])
           if r.get("pair_id") in pair_meta}
    sib = logs.latest((r for r in logs.read(runs_dir / logs.FILES["siblings"])
                       if r.get("kind") == "sibling" and r.get("pair_id") in pair_meta), "pair_id")
    att = {}
    for r in logs.read(runs_dir / logs.FILES["attempts"]):
        if r.get("kind") == "classification":
            att[r["attempt_id"]] = r
    pairs = {}
    for pid in sorted(pair_meta):
        m = pair_meta[pid]
        s = sel.get(pid, {})
        c = att.get(s.get("attempt_id"), {})
        pairs[pid] = {**m, "cwe": s.get("cwe"), "similarity": c.get("similarity_to_human"),
                      "patch_size": c.get("diff_changed_lines"),
                      "method": (sib.get(pid) or {}).get("method")}
    extra = {"rows": len(rows), "calls": len(by_call)}
    obs = dict(sorted(obs.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2], kv[0][3] or "")))
    return View(split_name, view, pairs, obs, unresolved, {k: cost[k] for k in sorted(cost)}, extra)


def disagreement(view, thresholds):
    """Per reviewer: share of ok, non-abstain calls whose verdict and threshold disagree (Q3)."""
    out = {}
    for r in view.reviewers:
        n = d = 0
        for (pid, state, rev, pk), trials in view.obs.items():
            if rev != r or pk is not None:
                continue
            for tr in trials:
                if tr.ok and tr.verdict != "abstain":
                    n += 1
                    thr = thresholds.get(r)
                    by_thr = thr is not None and tr.risk <= thr
                    d += int(by_thr != (tr.verdict == "approve"))
        out[r] = {"calls": n, "disagree": d, "rate": d / n if n else None}
    return out


def long_justifications(view, limit):
    out = collections.Counter()
    for (pid, state, rev, pk), trials in view.obs.items():
        for tr in trials:
            if tr.ok and tr.words is not None and tr.words > limit:
                out[rev] += 1
    return dict(sorted(out.items()))
