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
