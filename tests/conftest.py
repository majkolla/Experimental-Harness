import json
import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BASE_CFG = {
    "name": "t",
    "seed": 3,
    "temperature": 0.7,
    "replicates": 6,
    "packets_per_task": 6,
    "gate": {"k": 2, "n": 3},
    "regimes": ["shared", "diverse"],
    "tasks_dir": "tasks",
    "prompt_file": "prompts/reviewer.md",
    "log": "runs/t.jsonl",
    "models": {
        "A": {"provider": "synthetic", "model": "sa-2026-01-01", "salt": "A"},
        "B": {"provider": "synthetic", "model": "sb-2026-01-01", "salt": "B"},
        "C": {"provider": "synthetic", "model": "sc-2026-01-01", "salt": "C"},
    },
    "panels": {
        "AAA": ["A", "A", "A"],
        "BBB": ["B", "B", "B"],
        "CCC": ["C", "C", "C"],
        "ABC": ["A", "B", "C"],
    },
}


def _task(d, task_id, label, cluster, packets=6, packet_len=400):
    (d / "packets").mkdir(parents=True, exist_ok=True)
    (d / "patch.diff").write_text(f"--- a/x\n+++ b/x\n@@\n+patch for {task_id}\n")
    (d / "manifest.json").write_text(
        json.dumps(
            {
                "task_id": task_id,
                "cluster": cluster,
                "label": label,
                "functional": "pass",
                "cwe": "CWE-9999",
                "sibling_of": None,
                "oracle_notes": f"ORACLE-SECRET-{task_id}",
                "exploit_path": f"EXPLOIT-SECRET-{task_id}",
            }
        )
    )
    for i in range(packets):
        (d / "packets" / f"{i:02d}.md").write_text(f"packet {i} for {task_id}. " + "x" * packet_len)


@pytest.fixture
def expdir(tmp_path):
    """A minimal but structurally complete experiment directory."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "reviewer.md").write_text(
        "context:\n{{CONTEXT}}\npatch:\n{{PATCH}}\n"
    )
    _task(tmp_path / "tasks" / "t1-vuln", "t1-vuln", "vulnerable", "C1")
    _task(tmp_path / "tasks" / "t1-secure", "t1-secure", "secure", "C1")
    _task(tmp_path / "tasks" / "t2-vuln", "t2-vuln", "vulnerable", "C2")
    _task(tmp_path / "tasks" / "t2-secure", "t2-secure", "secure", "C2")
    (tmp_path / "experiment.json").write_text(json.dumps(BASE_CFG))
    return tmp_path


@pytest.fixture
def write_cfg(expdir):
    def _write(**overrides):
        cfg = json.loads(json.dumps(BASE_CFG))
        cfg.update(overrides)
        (expdir / "experiment.json").write_text(json.dumps(cfg))
        return expdir / "experiment.json"

    return _write


@pytest.fixture
def real_repo(tmp_path):
    """A copy of the shipped demo bank, for the offline end-to-end test."""
    dst = tmp_path / "repo"
    dst.mkdir()
    for item in ("tasks", "prompts", "tools", "hp", "experiment.offline.json"):
        src = ROOT / item
        if src.is_dir():
            shutil.copytree(src, dst / item)
        else:
            shutil.copy(src, dst / item)
    return dst
