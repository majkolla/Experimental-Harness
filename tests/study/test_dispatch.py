"""Dispatch: admission per candidate, the attempt budget across resumes, pins, packets."""

import collections
import json

import pytest

from hp import engine, logs, providers, schema
from hp.review import packets as P
from hp.runner import eligible_order


def test_admission_never_puts_two_calls_on_one_candidate_in_flight(dev_run):
    rows = [r for r in logs.read(dev_run["rd"] / "reviews.jsonl")]
    calls = [{"panel_key": r["candidate_id"], "call_id": r["call_id"]} for r in rows]
    picked = eligible_order(calls, {}, 50)
    keys = [calls[i]["panel_key"] for i in picked]
    assert len(keys) == len(set(keys)) == 50


def test_dev_run_summary_and_unresolved_calls(dev_run):
    s = dev_run["summary"]
    assert s["open"] == 0 and s["ok"] > 0 and s["closed_without_ok"] > 0
    rows = list(logs.read(dev_run["rd"] / "reviews.jsonl"))
    per = collections.defaultdict(list)
    for r in rows:
        per[r["call_id"]].append(r)
    exhausted = [v for v in per.values() if len(v) == 4 and v[-1]["status"] == "timeout"]
    assert exhausted, "persistent timeouts should exhaust the four-attempt budget"
    assert max(len(v) for v in per.values()) <= 4


def _mini_cfg(provider="scripted", snapshot="m"):
    return {"models": {"A": {"provider": provider, "model": "m", "snapshot": snapshot, "tier": "strong"}},
            "max_attempts": 4, "workers": 2, "seed": 1,
            "sampling": {"review_temperature": 0.7, "review_top_p": 1.0},
            "caps": {"review_output_tokens": 10}, "timeouts_s": {"review_timeout_s": 1},
            "prices_usd_per_mtok": {"A": {"input": 1.0, "output": 2.0}}, "openweight_cost": {}}


def _row(call, rec, extra):
    return {**{k: None for k in logs.REQUIRED["review"]},
            "kind": "review", "call_id": call["call_id"], "status": rec["status"],
            "attempt": rec["attempt"], "served_model": rec.get("served_model"),
            "cost": extra["cost"]}


def test_attempt_budget_continues_across_resumes(monkeypatch, tmp_path):
    seen = collections.Counter()

    class APITimeoutError(Exception):
        pass

    def scripted(spec, prompt, cfg, contract):
        seen[spec["_attempt"]] += 1
        raise APITimeoutError()

    monkeypatch.setitem(providers.PROVIDERS, "scripted", scripted)
    log = tmp_path / "reviews.jsonl"
    cfg = _mini_cfg()
    logs.append(log, [_row({"call_id": "c1"}, {"status": "timeout", "attempt": a}, {"cost": 0})
                      for a in (1, 2)])
    s = engine.run_calls(cfg, [{"call_id": "c1", "panel_key": "x", "model_ref": "A"}], log, "review",
                         schema.REVIEW_V13, lambda c: ("p", "s"), _row, "review", sleep=lambda s: None)
    assert sorted(seen) == [3, 4]
    assert s["closed_without_ok"] == 1 and s["open"] == 0
    again = engine.run_calls(cfg, [{"call_id": "c1", "panel_key": "x", "model_ref": "A"}], log,
                             "review", schema.REVIEW_V13, lambda c: ("p", "s"), _row, "review")
    assert again["dispatched"] == 0


def test_a_non_retryable_failure_closes_the_call(monkeypatch, tmp_path):
    calls = collections.Counter()

    def invalid(spec, prompt, cfg, contract):
        calls["n"] += 1
        return {"verdict": "maybe"}, {"served_model": "m"}

    monkeypatch.setitem(providers.PROVIDERS, "scripted", invalid)
    log = tmp_path / "r.jsonl"
    for _ in range(2):
        engine.run_calls(_mini_cfg(), [{"call_id": "c", "panel_key": "x", "model_ref": "A"}], log,
                         "review", schema.REVIEW_V13, lambda c: ("p", "s"), _row, "review")
    assert calls["n"] == 1  # resumes never re-roll a closed call


def test_a_served_snapshot_mismatch_is_logged_then_stops_the_run(monkeypatch, tmp_path):
    def drift(spec, prompt, cfg, contract):
        return {"verdict": "approve", "risk": 3, "justification": ""}, {"served_model": "other"}

    monkeypatch.setitem(providers.PROVIDERS, "scripted", drift)
    log = tmp_path / "r.jsonl"
    with pytest.raises(providers.PinViolation, match="pinned 'm' but the provider served 'other'"):
        engine.run_calls(_mini_cfg(), [{"call_id": "c", "panel_key": "x", "model_ref": "A"}], log,
                         "review", schema.REVIEW_V13, lambda c: ("p", "s"), _row, "review")
    assert [json.loads(l)["served_model"] for l in log.read_text().splitlines()] == ["other"]


def test_cost_is_tokens_times_the_price_sheet():
    cfg = _mini_cfg()
    assert engine.cost_of(cfg, "A", {"in_tokens": 1_000_000, "out_tokens": 500_000}) == (2.0, None)


# --- Experiment B packets ------------------------------------------------------------

MAIN = {"src/main/java/p/H.java": """package p;
public class H {
    /**
     * Processes input.
     * @param input never null
     */
    public String process(String input) {
        if (input.isEmpty()) {
            return input;
        }
        return helper(input);
    }

    /** Helps. */
    String helper(String s) {
        return s.trim();
    }
}
""", "src/main/java/p/D.java": """package p;
public class D {
    public String handle(String raw) {
        return new H().process(raw);
    }
}
"""}
CHANGED = {"src/main/java/p/H.java": {8}}


def test_structure_packet_has_callers_callees_and_guards():
    pk = P.build("structure", post_files=MAIN, main_files=MAIN, changed=CHANGED, cap_tokens=3000)
    assert "Callee helper" in pk["text"] and "Caller handle" in pk["text"]
    assert "if (input.isEmpty())" in pk["text"]
    assert pk["method"] == "lightweight-text" and not pk["truncated"]


def test_contracts_packet_has_javadoc_of_changed_and_called_methods():
    pk = P.build("contracts", post_files=MAIN, main_files=MAIN, changed=CHANGED, cap_tokens=3000)
    assert "Processes input." in pk["text"] and "Helps." in pk["text"]


def test_tests_packet_excludes_the_whole_pov_file_and_respects_the_cap():
    tests = {"src/test/java/p/HTest.java": "class HTest { void pov() { new H(); } void ok() {} }",
             "src/test/java/p/DTest.java": "class DTest { void t() { new H(); } }"}
    pk = P.build("ordinary_tests", test_files=tests, pov_test_files=["src/test/java/p/HTest.java"],
                 changed_classes=["H"], regression_note="all passed", cap_tokens=3000)
    assert "DTest" in pk["text"] and "HTest" not in pk["text"]
    tiny = P.build("ordinary_tests", test_files={"T.java": "x " * 25000}, pov_test_files=[],
                   changed_classes=["x"], regression_note="", cap_tokens=100)
    assert tiny["truncated"] and tiny["proxy_tokens"] <= 100 + 5
