"""Resume, dispatch admission, and provider fault classification."""

import json

from hp import dataset, providers, runner
from hp.schema import OK, REQUEST_ERROR, TIMEOUT, TRANSPORT_ERROR


def _log(tmp_path, records):
    p = tmp_path / "log.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in records))
    return p


def test_failed_calls_are_not_treated_as_done(tmp_path):
    """The bug that silently biased the whole experiment.

    `done_ids` previously collected every call_id in the log regardless of
    status, so one transient 429 retired that call for good: the panel came out
    incomplete and was dropped. Error rates differ by provider and by response
    length, so this made missingness correlated with the composition factor.
    """
    p = _log(
        tmp_path,
        [
            {"call_id": "a", "status": "ok"},
            {"call_id": "b", "status": "transport_error"},
            {"call_id": "c", "status": "timeout"},
            {"call_id": "d", "status": "schema_invalid"},
            {"call_id": "e", "status": "truncated"},
        ],
    )
    assert runner.done_ids(p) == {"a"}


def test_a_retry_that_succeeds_marks_the_call_done(tmp_path):
    p = _log(
        tmp_path,
        [
            {"call_id": "a", "status": "timeout", "attempt": 1},
            {"call_id": "a", "status": "ok", "attempt": 2},
        ],
    )
    assert runner.done_ids(p) == {"a"}


def test_truncated_final_line_from_a_killed_run_is_survivable(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps({"call_id": "a", "status": "ok"}) + "\n{\"call_id\": \"b\"")
    assert [r["call_id"] for r in runner.read_log(p)] == ["a"]


def test_later_ok_record_supersedes_an_earlier_one(tmp_path):
    p = _log(
        tmp_path,
        [
            {"call_id": "a", "status": "ok", "decision": "approve", "attempt": 1},
            {"call_id": "a", "status": "ok", "decision": "reject", "attempt": 2},
        ],
    )
    latest, attempts, _ = dataset.load_records(p, runner.read_log)
    assert latest["a"]["decision"] == "reject"
    assert attempts["a"] == 2


def test_missingness_is_tabulated_per_model(tmp_path):
    p = _log(
        tmp_path,
        [
            {"call_id": "1", "status": "ok", "model_ref": "A"},
            {"call_id": "2", "status": "ok", "model_ref": "A"},
            {"call_id": "3", "status": "truncated", "model_ref": "B"},
            {"call_id": "4", "status": "ok", "model_ref": "B"},
        ],
    )
    _, _, by_model = dataset.load_records(p, runner.read_log)
    rows = {r["model_ref"]: r for r in dataset.missingness_table(by_model)}
    assert rows["A"]["loss_rate"] == 0.0
    assert rows["B"]["loss_rate"] == 0.5


# --- dispatch admission ----------------------------------------------------


def _pending(*keys):
    return [{"panel_key": k, "call_id": f"{k}-{i}"} for i, k in enumerate(keys)]


def test_dispatcher_never_admits_two_calls_from_one_panel():
    """Concurrency must not put a panel's reviewers at the vendor together.

    Same instant means shared cache state, shared load and any shared
    service-side condition -- panel-level coupling manufactured by construction
    and indistinguishable from the coupling under study.
    """
    pending = _pending("P", "P", "P", "Q", "Q", "R")
    picked = runner.eligible_order(pending, {}, 4)
    keys = [pending[i]["panel_key"] for i in picked]
    assert len(keys) == len(set(keys)) == 3


def test_dispatcher_respects_a_busy_panel():
    pending = _pending("P", "Q")
    picked = runner.eligible_order(pending, {"P": 1}, 4)
    assert [pending[i]["panel_key"] for i in picked] == ["Q"]


def test_dispatcher_admits_nothing_when_there_are_no_free_slots():
    """Regression: a zero limit must not fall through and admit everything."""
    assert runner.eligible_order(_pending("P", "Q"), {}, 0) == []
    assert runner.eligible_order(_pending("P", "Q"), {}, -1) == []


def test_dispatcher_preserves_shuffled_order_otherwise():
    pending = _pending("A", "B", "C")
    assert runner.eligible_order(pending, {}, 2) == [0, 1]


# --- fault classification --------------------------------------------------


class _Boom(Exception):
    def __init__(self, code=None):
        super().__init__("boom")
        self.status_code = code


def test_rate_limits_and_5xx_are_retryable_but_4xx_is_not():
    assert providers._classify(_Boom(429)) == TRANSPORT_ERROR
    assert providers._classify(_Boom(503)) == TRANSPORT_ERROR
    assert providers._classify(_Boom(400)) == REQUEST_ERROR
    assert providers._classify(_Boom(401)) == REQUEST_ERROR


def test_timeouts_are_classified_by_name():
    class APITimeoutError(Exception):
        pass

    assert providers._classify(APITimeoutError()) == TIMEOUT


def test_a_missing_api_key_is_our_fault_and_is_not_retried():
    spec = {"provider": "anthropic", "model": "m"}
    cfg = {"timeout_s": 1, "temperature": 0.5, "max_tokens": 8, "max_attempts": 3}
    recs = providers.call_with_retries(spec, "prompt", cfg)
    assert len(recs) == 1
    assert recs[0]["status"] in (REQUEST_ERROR, TRANSPORT_ERROR)
    assert recs[0]["verdict"] is None and recs[0]["decision"] is None


def test_synthetic_provider_round_trips_to_a_valid_verdict():
    spec = {"provider": "synthetic", "model": "s-2026-01-01", "base_rate": 1.0,
            "_call_key": "k", "_packet_id": "p"}
    cfg = {"timeout_s": 1, "temperature": 0.5, "max_tokens": 8, "max_attempts": 1}
    rec = providers.call_once(spec, "prompt", cfg)
    assert rec["status"] == OK and rec["decision"] == "approve"
