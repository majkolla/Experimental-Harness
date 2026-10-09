"""End to end, offline: development and test, nine synthetic models, the full report.

Also: every reported number is recomputable from the logs alone.
"""

import json
import shutil
import subprocess
import sys

import pytest

from hp import logs, study_config as S
from hp.analysis import report
from tests.study.helpers import ROOT


def test_full_report_has_every_section(full_run):
    rd, test, dev = full_run["rd"], full_run["test"], full_run["dev"]
    for name in ("reproduction.jsonl", "attempts.jsonl", "selection.jsonl", "siblings.jsonl",
                 "inputs.jsonl", "reviews.jsonl", "freeze.json", "thresholds.json",
                 "primary_choice.json", "dev_report.json", "dev_report.txt",
                 "test_report.json", "test_report.txt"):
        assert (rd / name).is_file(), name
    est = test["core"]["estimates"]
    for k in ("delta2_U", "delta2_A", "cost_ratio"):
        assert est[k]["estimate"] is not None and len(est[k]["ci95"]) == 2
    if test["primary_contrast"] != "exploratory":
        assert est["delta1_U"]["ci95"] is not None
    assert set(test["inference"]["hypotheses"]) == set(test["inference"]["family"])
    for h in test["inference"]["hypotheses"].values():
        assert h["decision"] in ("improvement", "cheaper and non-inferior", "cheaper and safer",
                                 "insufficient precision")
    cm = test["core"]["rq3_common_mode"]
    assert cm["cheap_panel_primary"]["benchmark"]["shape"] in ("concentrated", "diffuse")
    assert set(cm["drivers_cheap_panel"]) == {"by_generator", "by_cwe", "by_similarity", "by_patch_size"}
    assert set(test["core"]["rq5_interactions"]) >= {"strong_same_model", "cheap_same_family"}
    assert {k.split("_")[0] for k in test["core"]["sensitivity"]} == set("123456789")
    ext = test["extension"]
    assert ext["rq2o"]["delta2o_U"]["estimate"] is not None
    assert ext["rq6_delta6"]["estimate"]["U"] is not None
    assert ext["rq5_open_block"]["U"] is not None
    assert dev["report"]["experiment_b"]["panel_assignments"]
    assert test["artefacts_recomputed_identical"] is True


def test_all_nine_models_and_extension_fields_are_logged(full_run):
    rows = list(logs.read(full_run["rd"] / "reviews.jsonl"))
    assert {r["reviewer"] for r in rows} == set(S.ALL_MODELS)
    for r in rows:
        if r["reviewer"] in S.OPEN_MODELS and r["status"] == "ok":
            assert r["weights_sha"] and r["precision"] and r["serving_stack"]
            assert r["gpu_seconds"] is not None and r["cost_sensitivity"] is not None
        if r["reviewer"] in S.CORE_REVIEWERS:
            assert r["weights_sha"] is None and r["cost_sensitivity"] is None
    for r in rows:
        logs.check_row(r)


def test_planted_structure_is_recovered(full_run):
    test = full_run["test"]
    # the concentrated common cause planted on the cheap reviewers
    b = test["core"]["rq3_common_mode"]["cheap_panel_primary"]["benchmark"]
    assert b["dt_over_dq"] > 1.5 and b["d_gate_3of3"] > 0
    # the same-model blind spot (strong block) shows as a positive interaction
    dev_rates = full_run["dev"]["report"]["dev_rates_optimistic"]
    diag = sum(dev_rates[g][g]["U"] for g in S.CORE_GENERATORS) / 3
    off = sum(dev_rates[g][r]["U"] for g in S.CORE_GENERATORS for r in S.CORE_GENERATORS if r != g) / 6
    assert diag > off


def test_every_number_is_recomputable_from_the_logs_alone(full_run, tmp_path):
    cfg, rd = full_run["cfg"], full_run["rd"]
    root = cfg["_root"]
    fresh = tmp_path / "copy"
    for name in ("hp", "prompts"):
        shutil.copytree(root / name, fresh / name)
    (fresh / "docs" / "spec").mkdir(parents=True)
    shutil.copy(root / "docs" / "spec" / "proposed_split.json", fresh / "docs" / "spec")
    shutil.copy(cfg["_path"], fresh / cfg["_path"].name)
    if (root / "study.py").exists():
        shutil.copy(root / "study.py", fresh / "study.py")
    new_rd = fresh / cfg["paths"]["runs"]
    new_rd.mkdir(parents=True)
    for f in list(logs.FILES.values()) + ["freeze.json", "thresholds.json", "primary_choice.json"]:
        shutil.copy(rd / f, new_rd / f)
    cfg2 = S.load(fresh / cfg["_path"].name)
    again = report.confirm(cfg2, new_rd)
    a = report.canonical_json(report._keys_to_str(full_run["test"]))
    b = report.canonical_json(report._keys_to_str(again))
    assert a == b


def test_cli_validate_refuses_the_live_config_and_accepts_the_synthetic_one():
    live = subprocess.run([sys.executable, str(ROOT / "study.py"), "validate", str(ROOT / "study.jsonc")],
                          capture_output=True, text=True, cwd=ROOT)
    assert live.returncode == 2 and "TO_PIN_AT_FREEZE" in live.stderr
    syn = subprocess.run([sys.executable, str(ROOT / "study.py"), "validate",
                          str(ROOT / "study.synthetic.jsonc")], capture_output=True, text=True, cwd=ROOT)
    assert syn.returncode == 0 and "valid (synthetic)" in syn.stdout


def test_cli_timing_pilot_reports_wall_clock_per_suite_run(tmp_path, capsys):
    """Q19: `study.py timing-pilot` (here on the synthetic world and mock runner)."""
    import importlib.util

    from tests.study.helpers import make_study_dir

    d = make_study_dir(tmp_path)
    spec = importlib.util.spec_from_file_location("study_cli", ROOT / "study.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    cfg = S.load(d / "study.synthetic.jsonc")
    from hp.bank.split import load_split

    cves = load_split(cfg).cves("test")[:2]
    assert cli.main(["timing-pilot", str(d / "study.synthetic.jsonc"), "--cves", ",".join(cves),
                     "--runs", "2"]) == 0
    out = capsys.readouterr().out
    assert "mean_run_s" in out and cves[0] in out
    rows = json.loads((S.runs_dir(cfg) / "timing_pilot.json").read_text())
    assert len(rows) == 4 and all(len(r["run_wall_s"]) == 2 for r in rows)
