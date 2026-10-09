"""Configuration validation. Every one of these would silently ruin a run."""

import json

import pytest

from hp import config


def test_loads_a_valid_config(write_cfg):
    cfg = config.load(write_cfg())
    assert len(cfg["_tasks"]) == 4
    assert cfg["_prompt_hash"] and cfg["_config_hash"]


def test_temperature_zero_is_rejected(write_cfg):
    with pytest.raises(config.ConfigError, match="temperature"):
        config.load(write_cfg(temperature=0))


def test_replicates_must_be_a_multiple_of_the_packet_count(write_cfg):
    with pytest.raises(config.ConfigError, match="multiple of packets_per_task"):
        config.load(write_cfg(replicates=8))


def test_replicates_must_be_a_multiple_of_n(write_cfg):
    # 9 is a multiple of 3 but not of 6, so it fails the packet rule first;
    # 4 packets with n=3 fails divisibility of P by n.
    with pytest.raises(config.ConfigError, match="divisible by n"):
        config.load(write_cfg(packets_per_task=4))


def test_too_few_replicates_for_recombination(write_cfg):
    with pytest.raises(config.ConfigError, match="replicates must be >= 3"):
        config.load(write_cfg(replicates=2, packets_per_task=2))


def test_floating_model_alias_is_rejected(write_cfg):
    models = {
        "A": {"provider": "synthetic", "model": "some-model"},
        "B": {"provider": "synthetic", "model": "sb-2026-01-01"},
        "C": {"provider": "synthetic", "model": "sc-2026-01-01"},
    }
    with pytest.raises(config.ConfigError, match="floating aliases"):
        config.load(write_cfg(models=models))
    # opting out is allowed, but it is an explicit act
    cfg = config.load(write_cfg(models=models, strict_model_pinning=False))
    assert cfg["models"]["A"]["model"] == "some-model"


def test_panel_size_must_match_gate_n(write_cfg):
    with pytest.raises(config.ConfigError, match="seats, gate n"):
        config.load(write_cfg(panels={"AA": ["A", "A"]}))


def test_unknown_model_reference_is_rejected(write_cfg):
    with pytest.raises(config.ConfigError, match="unknown model"):
        config.load(write_cfg(panels={"AAZ": ["A", "A", "Z"]}))


def test_missing_secure_sibling_is_rejected(write_cfg, expdir):
    for name in ("t1-secure", "t2-secure"):
        m = expdir / "tasks" / name / "manifest.json"
        d = json.loads(m.read_text())
        d["label"] = "vulnerable"
        m.write_text(json.dumps(d))
    with pytest.raises(config.ConfigError, match="rejects everything scores perfectly"):
        config.load(write_cfg())


def test_packet_count_mismatch_is_rejected(write_cfg, expdir):
    (expdir / "tasks" / "t1-vuln" / "packets" / "05.md").unlink()
    with pytest.raises(config.ConfigError, match="packets, config says"):
        config.load(write_cfg())


def test_unequal_packet_budgets_are_rejected(write_cfg, expdir):
    # An arm that happens to draw richer context would confound coupling with
    # information quality.
    (expdir / "tasks" / "t1-vuln" / "packets" / "00.md").write_text("tiny")
    with pytest.raises(config.ConfigError, match="differ by more than 2x"):
        config.load(write_cfg())


def test_prompt_must_carry_both_slots(write_cfg, expdir):
    (expdir / "prompts" / "reviewer.md").write_text("only {{PATCH}}")
    with pytest.raises(config.ConfigError, match="CONTEXT"):
        config.load(write_cfg())
