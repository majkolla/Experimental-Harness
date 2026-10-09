"""Offline end-to-end: schedule -> dispatch -> log -> estimators -> report.

Runs the whole apparatus against the synthetic provider, with no network and no
budget, so a change that breaks the wiring fails here rather than 4000 paid
calls into a run.
"""

import json

from hp import config, design, report, runner


def test_dry_run_spends_nothing_and_reports_the_design(real_repo, capsys):
    table = runner.run(real_repo / "experiment.offline.json", dry_run=True)
    assert table["calls"] == 4 * 4 * 2 * 6 * 3
    assert table["independent_clusters"] == 2
    assert not (real_repo / "runs").exists() or not list(
        (real_repo / "runs").glob("*.jsonl")
    )


def test_full_offline_run_then_analysis(real_repo):
    cfg_path = real_repo / "experiment.offline.json"
    runner.run(cfg_path)

    cfg = config.load(cfg_path)
    log = real_repo / cfg["log"]
    lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert len(lines) == 576
    assert all(r["status"] == "ok" for r in lines)
    assert {r["regime"] for r in lines} == {"shared", "diverse"}
    assert all(r["config_hash"] == cfg["_config_hash"] for r in lines)
    assert all("packet_hash" in r and "channel" in r for r in lines)

    res = report.analyse(cfg_path, draws=200)
    assert res["records_ok"] == 576
    assert res["incomplete_panels"] == 0
    assert res["clusters"] == 2
    # 4 panels x 2 regimes on the two vulnerable tasks
    assert len(res["aggregate"]) == 8
    for row in res["aggregate"].values():
        assert 0.0 <= row["R_obs"] <= 1.0
        assert row["R_recomb"] is not None
    # secure siblings are analysed separately, not folded into the primary
    assert res["secure_approval"]
    report.print_report(res)


def test_resume_is_idempotent_and_adds_nothing(real_repo):
    cfg_path = real_repo / "experiment.offline.json"
    runner.run(cfg_path)
    cfg = config.load(cfg_path)
    log = real_repo / cfg["log"]
    before = log.read_text()
    runner.run(cfg_path)
    assert log.read_text() == before


def test_resume_reruns_only_the_failed_calls(real_repo):
    """A log with holes must be repaired, not accepted."""
    cfg_path = real_repo / "experiment.offline.json"
    runner.run(cfg_path, limit=30)
    cfg = config.load(cfg_path)
    log = real_repo / cfg["log"]

    rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    # poison three records as transport errors, as a rate limit would
    for r in rows[:3]:
        r["status"] = "transport_error"
        r["verdict"] = None
        r["decision"] = None
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))

    done = runner.done_ids(log)
    assert len(done) == 27
    runner.run(cfg_path)
    assert runner.done_ids(log) == {
        c["call_id"] for c in design.build_schedule(cfg)
    }


def test_abstention_coding_is_a_reported_sensitivity(real_repo):
    """Under a permissive gate "abstain" is not obviously safe, so both codings
    are produced and neither is chosen inside the harness."""
    cfg_path = real_repo / "experiment.offline.json"
    runner.run(cfg_path)
    strict = report.analyse(cfg_path, draws=50, abstain_as_approval=False)
    loose = report.analyse(cfg_path, draws=50, abstain_as_approval=True)
    for key in strict["aggregate"]:
        assert loose["aggregate"][key]["R_obs"] >= strict["aggregate"][key]["R_obs"]
