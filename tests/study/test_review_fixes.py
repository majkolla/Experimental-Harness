"""Regression tests for the findings of the independent code review (PLAN.md section 10).

One test (or a small group) per fixed finding, named after what it guards.
"""

import collections
import json
import random
import shutil

import pytest

from hp import engine, logs, providers, schema, study_config as S
from hp.analysis import confirm as CF
from hp.analysis import extension as EXT
from hp.analysis import rates as RT
from hp.analysis import report
from hp.bank import reproduce
from hp.bank.split import SplitLockError
from hp.bank.vul4j import SuiteRun, TestResult
from tests.study.helpers import make_view, ok

# ---------------------------------------------------------------------------
# Stage 1: a CVE with several PoV tests
# ---------------------------------------------------------------------------


class _TwoPovRunner:
    """Two PoV tests, each failing with its own stable signature."""

    SIG = {"p.T#pov1": {"type": "AssertionError", "message": "one", "frame": "p.T.pov1"},
           "p.T#pov2": {"type": "IllegalStateException", "message": "two", "frame": "p.T.pov2"}}

    def __init__(self, unstable=None):
        self.unstable = unstable

    def pov_tests(self, cve):
        return sorted(self.SIG)

    def describe(self):
        return {"runner": "fake"}

    def prepare(self, cve, version):
        return {"version": version, "n": 0}

    def run_tests(self, h, scope="full"):
        h["n"] += 1
        res = {"p.T#ordinary": TestResult("p.T#ordinary", "pass")}
        for t, sig in self.SIG.items():
            if h["version"] == "fixed":
                res[t] = TestResult(t, "pass")
            else:
                s = dict(sig)
                if t == self.unstable and h["n"] % 2:
                    s["message"] = "drifted"
                res[t] = TestResult(t, "fail", s)
        return SuiteRun(True, res, 1.0, scope)

    def release(self, h):
        pass


def test_each_pov_test_needs_its_own_stable_signature_not_one_shared():
    row = reproduce.reproduce_cve(_TwoPovRunner(), "VUL4J-1", "k", "development", 4)
    assert row["status"] == "eligible"
    assert set(row["signature"]) == {"p.T#pov1", "p.T#pov2"}
    row = reproduce.reproduce_cve(_TwoPovRunner(unstable="p.T#pov2"), "VUL4J-1", "k", "development", 4)
    assert row["status"] == "pov_unstable"


# ---------------------------------------------------------------------------
# Dispatch: local faults, attempts logged as they end, partial lines
# ---------------------------------------------------------------------------


def _mini_cfg():
    return {"models": {"A": {"provider": "scripted", "model": "m", "snapshot": "m", "tier": "strong"}},
            "max_attempts": 4, "workers": 1, "seed": 1,
            "sampling": {"review_temperature": 0.7, "review_top_p": 1.0},
            "caps": {"review_output_tokens": 10}, "timeouts_s": {"review_timeout_s": 1},
            "prices_usd_per_mtok": {"A": {"input": 1.0, "output": 2.0}}, "openweight_cost": {}}


def _row(call, rec, extra):
    return {**{k: None for k in logs.REQUIRED["review"]},
            "kind": "review", "call_id": call["call_id"], "status": rec["status"],
            "attempt": rec["attempt"], "served_model": rec.get("served_model"), "cost": extra["cost"]}


def _run(cfg, log, call_id="c"):
    return engine.run_calls(cfg, [{"call_id": call_id, "panel_key": "x", "model_ref": "A"}], log,
                            "review", schema.REVIEW_V13, lambda c: ("p", "s"), _row, "review",
                            sleep=lambda s: None)


def test_a_missing_key_or_sdk_stops_the_run_and_logs_nothing(monkeypatch, tmp_path):
    def no_key(spec, prompt, cfg, contract):
        raise KeyError("ANTHROPIC_API_KEY")

    monkeypatch.setitem(providers.PROVIDERS, "scripted", no_key)
    log = tmp_path / "r.jsonl"
    with pytest.raises(engine.LocalFault, match="local configuration fault"):
        _run(_mini_cfg(), log)
    assert not log.exists() or log.read_text() == ""


class _Killed(BaseException):
    """Stands in for the process being killed mid-call."""


def test_attempts_are_logged_as_they_end_so_a_killed_run_keeps_its_budget(monkeypatch, tmp_path):
    seen = []

    class APITimeoutError(Exception):
        pass

    def flaky(spec, prompt, cfg, contract):
        seen.append(spec["_attempt"])
        if spec["_attempt"] == 3 and len(seen) == 3:
            raise _Killed()
        raise APITimeoutError()

    monkeypatch.setitem(providers.PROVIDERS, "scripted", flaky)
    log = tmp_path / "r.jsonl"
    with pytest.raises(_Killed):
        _run(_mini_cfg(), log)
    assert [r["attempt"] for r in logs.read(log)] == [1, 2]   # both ended attempts survived
    s = _run(_mini_cfg(), log)                                # resume
    assert seen == [1, 2, 3, 3, 4]                            # never more than four in total
    assert [r["attempt"] for r in logs.read(log)] == [1, 2, 3, 4]
    assert s["closed_without_ok"] == 1 and s["open"] == 0


def test_append_after_a_partial_line_starts_a_new_line(tmp_path):
    log = tmp_path / "r.jsonl"
    first = _row({"call_id": "c1"}, {"status": "ok", "attempt": 1}, {"cost": 0})
    second = _row({"call_id": "c2"}, {"status": "ok", "attempt": 1}, {"cost": 0})
    logs.append(log, [first])
    with open(log, "a") as fh:
        fh.write('{"call_id": "half')                              # killed mid-write
    logs.append(log, [second])
    assert log.read_text().splitlines()[-1] == json.dumps(second, sort_keys=True)
    assert list(logs.read(log)) == [first, second]                 # the fragment is skipped


# ---------------------------------------------------------------------------
# Inference: bounds agree with p-values, None draws count against the claim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(20))
def test_one_sided_bounds_agree_with_the_p_value_rule(seed):
    rng = random.Random(seed)
    n = rng.choice([19, 99, 199, 999])
    vals = [None if rng.random() < 0.03 else round(rng.gauss(0, 1), 2) for _ in range(n)]
    alpha = rng.choice([0.0125, 0.025, 0.05])
    grid = sorted({v for v in vals if v is not None}) + [-9.0, 9.0, 0.0]
    lo, hi = CF.lower_bound(vals, alpha), CF.upper_bound(vals, alpha)
    for b in grid:
        p_lo = CF._p_wrong(vals, lambda x: x <= b)
        p_hi = CF._p_wrong(vals, lambda x: x >= b)
        assert (lo is not None and lo > b) == (p_lo <= alpha)
        assert (hi is not None and hi < b) == (p_hi <= alpha)


def test_undefined_draws_count_against_the_claim():
    vals = [0.5] * 990 + [None] * 10
    assert CF._p_wrong(vals, lambda x: x <= 0) == pytest.approx(11 / 1001)
    assert CF.lower_bound(vals, 0.005) is None   # fewer than k defined draws below


# ---------------------------------------------------------------------------
# Extension: pipeline risk and Delta6 never average around a gap
# ---------------------------------------------------------------------------


def test_pipeline_risk_is_undefined_when_a_cve_with_near_misses_has_no_u():
    view = make_view([("p1", "CVE-1", "K1", "A")],
                     {("p1", "V", "a"): [ok(90)] * 3, ("p1", "F", "a"): [ok(10)] * 3})
    thr = {"reviewers": {"a": 50}, "panel_cheap": None, "panel_open": None}
    choice = {"r_star": "a"}
    full = EXT.pipeline_risk(view, thr, choice, {("CVE-1", "A"): 2}, ["CVE-1"], ["A"], ["fixed"])
    assert full["fixed"]["risk_per_attempt"] == 0.0 and full["fixed"]["cves_with_near_misses_but_no_U"] == 0
    gap = EXT.pipeline_risk(view, thr, choice, {("CVE-1", "A"): 2, ("CVE-2", "A"): 1},
                            ["CVE-1", "CVE-2"], ["A"], ["fixed"])
    assert gap["fixed"] == {"risk_per_attempt": None, "cves_with_near_misses_but_no_U": 1}
    none = EXT.pipeline_risk(view, thr, choice, {("CVE-1", "A"): 0, ("CVE-2", "A"): 0},
                             ["CVE-1", "CVE-2"], ["A"], ["fixed"])
    assert none["fixed"]["risk_per_attempt"] == 0.0   # no near-misses: zero risk, not undefined


def test_delta6_leaves_infeasible_reviewers_out_and_lists_them():
    rows = {g: {(r, "V"): (0.4 if g in S.OPEN_MODELS else 0.1) for r in S.ALL_MODELS}
            for g in list(S.CORE_GENERATORS) + list(S.OPEN_MODELS)}
    for g in S.CORE_GENERATORS + S.OPEN_MODELS:
        rows[g][(g, "V")] = 0.99
    for g in S.OPEN_MODELS:
        rows[g][("a", "V")] = 0.99  # would move the mean if "a" (infeasible) were counted
    feasible = set(S.ALL_MODELS) - {"a"}
    assert EXT._delta6(None, rows, "V", feasible) == pytest.approx(0.3)
    assert EXT._delta6(None, rows, "V") != pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Reports: per-cell counts next to the rates
# ---------------------------------------------------------------------------


def test_cell_table_reports_unresolved_trials_and_pairs_left_out_of_c():
    timeout = ("timeout", None, None)
    view = make_view(
        [("p1", "CVE-1", "K1", "A"), ("p2", "CVE-2", "K2", "A")],
        {("p1", "V", "a"): [ok(90), timeout, ok(80)], ("p1", "F", "a"): [ok(10)] * 3,
         ("p2", "V", "a"): [timeout] * 3, ("p2", "F", "a"): [ok(10), ok(20), timeout]})
    R = RT.Rates(view, {"a": 50}, generators=["A"], reviewers=["a"])
    c = RT.cell_table(R, ["a"])["A"]["a"]
    assert (c["pairs"], c["unresolved_V"], c["trials_V"], c["unresolved_F"], c["trials_F"]) == (2, 4, 6, 1, 6)
    assert c["C_excluded_pairs"] == 1 and c["C_excluded_share"] == 0.5   # p2: no valid V trial
    assert c["C"] == 1.0                                                  # from p1 alone
    assert RT.c_exclusions({"A": {"a": c}})["overall"] == {"excluded_pairs": 1, "pairs": 2, "share": 0.5}


def test_reports_carry_the_cell_tables(full_run):
    dev, test = full_run["dev"]["report"], full_run["test"]
    cell = dev["dev_rates_optimistic"]["A"]["a"]
    assert {"U", "A", "C", "unresolved_V", "unresolved_F", "C_excluded_pairs"} <= set(cell)
    assert test["core"]["cell_rates"] and test["core"]["c_exclusions"]["overall"]["pairs"] > 0
    assert test["extension"]["cell_rates_all_e0"]["X"]["a"]["pairs"] > 0
    txt = (full_run["rd"] / "test_report.txt").read_text()
    assert "pairs left out of C" in txt and "[unresolved V/trials]" in txt


# ---------------------------------------------------------------------------
# Analysis refuses incomplete or stale runs
# ---------------------------------------------------------------------------


def _copy_runs(src, dst):
    shutil.copytree(src, dst)
    return dst


def _rewrite(path, keep=lambda r: True, change=lambda r: r):
    rows = [change(r) for r in logs.read(path) if keep(r)]
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def test_analysis_refuses_a_run_with_missing_or_open_calls(dev_run, tmp_path):
    cfg = dev_run["cfg"]
    assert report.completeness(cfg, dev_run["rd"], "development")["missing"] == 0

    rd = _copy_runs(dev_run["rd"], tmp_path / "missing")
    rows = list(logs.read(rd / "reviews.jsonl"))
    gone = next(r["call_id"] for r in rows if r.get("block") == "core")
    _rewrite(rd / "reviews.jsonl", keep=lambda r: r["call_id"] != gone)
    with pytest.raises(report.IncompleteRun, match="1 scheduled call"):
        report.analyse_dev(cfg, rd, write=False)

    rd = _copy_runs(dev_run["rd"], tmp_path / "open")
    per = collections.defaultdict(list)
    for r in logs.read(rd / "reviews.jsonl"):
        per[r["call_id"]].append(r)
    cid = next(c for c, v in sorted(per.items())
               if len(v) == 4 and all(r["status"] == "timeout" for r in v))
    _rewrite(rd / "reviews.jsonl", keep=lambda r: not (r["call_id"] == cid and r["attempt"] == 4))
    c = report.completeness(cfg, rd, "development")
    assert c["open"] == 1 and c["missing"] == 0
    with pytest.raises(report.IncompleteRun, match="still open"):
        report.analyse_dev(cfg, rd, write=False)


def test_confirm_refuses_test_rows_made_under_another_config(full_run, tmp_path):
    rd = _copy_runs(full_run["rd"], tmp_path / "stale")
    first = []

    def stale(r):
        if r.get("split") == "test" and r.get("kind") == "review" and not first:
            first.append(r["call_id"])
            return {**r, "config_sha256": "0" * 64}
        return r

    _rewrite(rd / "reviews.jsonl", change=stale)
    with pytest.raises(SplitLockError, match="another config than the frozen one"):
        report.confirm(full_run["cfg"], rd)
