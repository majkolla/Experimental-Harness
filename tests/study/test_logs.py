"""WP6: the logs carry every section 18.3 field, are append-only, and suffice."""

import hashlib

import pytest

from hp import logs, study_config as S
from hp.bank import classify, generate, select, sibling
from hp.review import dispatch

SPEC_ATTEMPTS = ("attempt_id", "cve", "cluster", "generator", "snapshot", "prompt_sha", "temperature",
                 "seed", "diff_sha", "class", "rerun_results", "signature_match",
                 "similarity_to_human", "tokens", "cost")
SPEC_REVIEWS = ("call_id", "candidate_id", "state", "cve", "cluster", "generator", "reviewer",
                "snapshot", "trial", "input_sha", "prompt_sha", "status", "attempt", "verdict",
                "risk", "tokens", "latency_s", "cost")


def test_every_row_of_every_log_validates(full_run):
    counts = logs.audit(full_run["rd"])
    assert counts["reviews.jsonl"]["review"] > 0
    assert set(counts["attempts.jsonl"]) == {"generation", "classification"}
    assert set(counts["siblings.jsonl"]) == {"sibling", "sibling_stop"}


def test_section_18_3_fields_are_all_present(full_run):
    rd = full_run["rd"]
    att = list(logs.read(rd / "attempts.jsonl"))
    joined = {}
    for r in att:
        joined.setdefault(r["attempt_id"], {}).update(r)
    for row in joined.values():
        for f in SPEC_ATTEMPTS:
            assert f in row, f
    for r in logs.read(rd / "reviews.jsonl"):
        for f in SPEC_REVIEWS + logs.EXTENSION_FIELDS:
            assert f in r, f


def test_missing_fields_are_refused():
    with pytest.raises(logs.LogSchemaError, match="missing fields"):
        logs.check_row({"kind": "review", "call_id": "x"})
    with pytest.raises(logs.LogSchemaError, match="unknown"):
        logs.check_row({"kind": "mystery"})


def _digest(rd):
    return {f: hashlib.sha256((rd / f).read_bytes()).hexdigest()
            for f in logs.FILES.values() if (rd / f).exists()}


def test_resuming_every_stage_appends_nothing(full_run, tmp_path):
    import shutil

    cfg, runner = full_run["cfg"], full_run["runner"]
    rd = tmp_path / "runs"
    shutil.copytree(full_run["rd"], rd)
    before = _digest(rd)
    for split_name in ("development", "test"):
        generate.run(cfg, runner, split_name, rd / "attempts.jsonl")
        classify.run(cfg, runner, split_name, rd)
        select.run(cfg, split_name, rd)
        dispatch.run(cfg, runner, split_name, rd, expb=(split_name == "development"))
    after = _digest(rd)
    assert {k: v for k, v in after.items() if k != "siblings.jsonl"} == \
        {k: v for k, v in before.items() if k != "siblings.jsonl"}


def test_logs_are_only_ever_appended(full_run, tmp_path):
    import shutil

    rd = tmp_path / "runs"
    shutil.copytree(full_run["rd"], rd)
    src = (rd / "siblings.jsonl").read_bytes()
    sibling.run(full_run["cfg"], full_run["runner"], "test", rd)
    assert (rd / "siblings.jsonl").read_bytes().startswith(src)
