"""Session fixtures: one synthetic development run shared by the review tests."""

import pytest

from hp import study_config as S
from hp.review import dispatch
from tests.study.helpers import build_bank, synthetic_cfg


@pytest.fixture(scope="session")
def dev_run(tmp_path_factory):
    """Stages 1-5 on development (core + extension + Experiment B), synthetic."""
    cfg = synthetic_cfg(tmp_path_factory.mktemp("devrun"))
    runner = build_bank(cfg, "development")
    rd = S.runs_dir(cfg)
    summary = dispatch.run(cfg, runner, "development", rd, expb=True, sleep=lambda s: None)
    return {"cfg": cfg, "runner": runner, "rd": rd, "summary": summary}


@pytest.fixture(scope="session")
def full_run(tmp_path_factory):
    """The whole study offline: dev Stages 1-5 + Exp B, analyse-dev, freeze,
    test Stages 2-5, confirm. Nine synthetic models, mock Vul4J."""
    from hp import logs
    from hp.analysis import report
    from hp.bank import classify, generate, select, sibling, vul4j

    cfg = synthetic_cfg(tmp_path_factory.mktemp("fullrun"), with_code=True)
    runner = build_bank(cfg, "development")
    rd = S.runs_dir(cfg)
    dispatch.run(cfg, runner, "development", rd, expb=True)
    dev = report.analyse_dev(cfg, rd)
    S.freeze(cfg["_path"], ["thresholds.json", "primary_choice.json"])
    cfg = S.load(cfg["_path"])
    runner = vul4j.runner_for(cfg)
    generate.run(cfg, runner, "test", rd / logs.FILES["attempts"])
    classify.run(cfg, runner, "test", rd)
    select.run(cfg, "test", rd)
    sibling.run(cfg, runner, "test", rd)
    dispatch.run(cfg, runner, "test", rd)
    test = report.confirm(cfg, rd)
    return {"cfg": cfg, "rd": rd, "dev": dev, "test": test, "runner": runner}


@pytest.fixture(scope="session")
def core_only_run(tmp_path_factory):
    """The same study from scratch with extension.enabled = false (core rows only)."""
    from hp import logs
    from hp.analysis import report
    from hp.bank import classify, generate, select, sibling, vul4j

    def off(o):
        o["extension"]["enabled"] = False

    cfg = synthetic_cfg(tmp_path_factory.mktemp("corerun"), with_code=True, edits=off)
    runner = build_bank(cfg, "development")
    rd = S.runs_dir(cfg)
    dispatch.run(cfg, runner, "development", rd, blocks=("core",), expb=True)
    dev = report.analyse_dev(cfg, rd)
    S.freeze(cfg["_path"], ["thresholds.json", "primary_choice.json"])
    cfg = S.load(cfg["_path"])
    runner = vul4j.runner_for(cfg)
    generate.run(cfg, runner, "test", rd / logs.FILES["attempts"])
    classify.run(cfg, runner, "test", rd)
    select.run(cfg, "test", rd)
    sibling.run(cfg, runner, "test", rd)
    dispatch.run(cfg, runner, "test", rd, blocks=("core",))
    test = report.confirm(cfg, rd)
    return {"cfg": cfg, "rd": rd, "dev": dev, "test": test}
