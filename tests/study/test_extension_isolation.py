"""The core analysis never reads extension rows (sections 3, 12.6; SPEC_ANSWERS Q9, Q10).

Every core estimate must be bit-identical with and without extension rows in
the logs. Checked two ways: (1) strip the extension rows from a finished run
and recompute; (2) run the whole study from scratch with the extension off.
"""

import json
import shutil

from hp import logs, study_config as S
from hp.analysis import report

CORE_G, CORE_R = set(S.CORE_GENERATORS), set(S.CORE_REVIEWERS)


def _frozen(rd):
    return (json.loads((rd / "thresholds.json").read_text()),
            json.loads((rd / "primary_choice.json").read_text()))


def _strip_extension(src, dst):
    shutil.copytree(src, dst)
    def keep(name, r):
        g = r.get("generator")
        if name == "reviews.jsonl":
            return g in CORE_G and r.get("reviewer") in CORE_R
        if name in ("attempts.jsonl", "selection.jsonl", "siblings.jsonl"):
            return r.get("kind") == "sibling_stop" or g in CORE_G
        return True
    for name in ("reviews.jsonl", "attempts.jsonl", "selection.jsonl", "siblings.jsonl"):
        rows = [r for r in logs.read(src / name) if keep(name, r)]
        (dst / name).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    pairs = {r["pair_id"] for r in logs.read(dst / "selection.jsonl")}
    rows = [r for r in logs.read(src / "inputs.jsonl") if r["pair_id"] in pairs]
    (dst / "inputs.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def _core_dev(dev):
    thr = dev["thresholds"]
    pc = dev["primary_choice"]
    return {
        "thresholds": {r: thr["reviewers"][r] for r in S.CORE_REVIEWERS},
        "t_p": thr["panel_cheap"],
        "choice": pc["choice"], "primary": pc["primary"], "regret": pc["regret"],
        "dev_rates": dev["report"]["dev_rates_optimistic"],
        "feasibility": dev["report"]["feasibility_half_widths"],
        "experiment_b": dev["report"]["experiment_b"],
    }


def _canon(x):
    return report.canonical_json(report._keys_to_str(x))


def test_extension_rows_exist_in_the_full_run(full_run):
    rows = list(logs.read(full_run["rd"] / "reviews.jsonl"))
    assert {r["block"] for r in rows} == {"core", "extension", "expB"}
    assert any(r["generator"] in S.OPEN_MODELS for r in rows)
    assert any(r["reviewer"] in S.OPEN_MODELS and r["generator"] in CORE_G for r in rows)


def test_core_estimates_are_bit_identical_after_stripping_extension_rows(full_run, tmp_path):
    cfg, rd = full_run["cfg"], full_run["rd"]
    thr, pc = _frozen(rd)
    with_ext = report.core_section(cfg, rd, thr, pc)[0]
    stripped = tmp_path / "runs"
    _strip_extension(rd, stripped)
    without = report.core_section(cfg, stripped, thr, pc)[0]
    assert _canon(with_ext) == _canon(without)

    dev_with = report.analyse_dev(cfg, rd, write=False)
    dev_without = report.analyse_dev(cfg, stripped, write=False, check=False)  # stripped on purpose
    assert _canon(_core_dev(dev_with)) == _canon(_core_dev(dev_without))


def test_core_estimates_are_identical_to_a_run_without_the_extension(full_run, core_only_run):
    a, b = full_run["test"]["core"], core_only_run["test"]["core"]
    assert _canon(a) == _canon(b)
    assert _canon(_core_dev(full_run["dev"])) == _canon(_core_dev(core_only_run["dev"]))
    assert core_only_run["test"]["extension"] is None


def test_thresholds_of_every_reviewer_come_from_core_bank_development_rows(full_run):
    thr = full_run["dev"]["thresholds"]
    assert set(thr["reviewers"]) == set(S.ALL_MODELS)
    assert thr["fit_on"].startswith("development rows of the core bank")
    assert thr["panel_open"] is not None and thr["panel_cheap"] is not None
