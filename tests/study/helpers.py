"""Shared fixtures for the v1.3 study tests (no network, no paid calls)."""

import json
import pathlib
import shutil

from hp import study_config as S

ROOT = pathlib.Path(__file__).resolve().parents[2]


def make_study_dir(tmp_path, with_code=False):
    """A self-contained copy of what a study config needs: configs, prompts, split."""
    d = pathlib.Path(tmp_path) / "study"
    d.mkdir(parents=True, exist_ok=True)
    for name in ("study.jsonc", "study.synthetic.jsonc"):
        shutil.copy(ROOT / name, d / name)
    shutil.copytree(ROOT / "prompts", d / "prompts")
    (d / "docs" / "spec").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "spec" / "proposed_split.json", d / "docs" / "spec")
    if with_code:
        shutil.copytree(ROOT / "hp", d / "hp", ignore=shutil.ignore_patterns("__pycache__"))
        if (ROOT / "study.py").exists():
            shutil.copy(ROOT / "study.py", d / "study.py")
    return d


def read_cfg(path):
    return S.parse_jsonc(pathlib.Path(path).read_text())


def write_cfg(path, obj):
    pathlib.Path(path).write_text(json.dumps(obj, indent=1))
    return path


def edit(path, fn):
    """Parse a config, apply fn(obj) in place, write it back as plain JSON."""
    obj = read_cfg(path)
    fn(obj)
    return write_cfg(path, obj)


def pin_all(obj):
    """Replace every placeholder in a live config with test-only values.

    The values are obviously fake ("test-..."), dated so they satisfy the pin
    rules; they are never shipped.
    """
    for ref, m in obj["models"].items():
        if m.get("provider") == "openweight":
            m.update(
                model=f"test-open-{ref}",
                weights_sha="ab" * 32,
                precision="test-precision",
                serving_stack="test-stack 0.0",
                host="http://test-host:1",
                num_ctx=32768,
                gpus=1,
            )
        else:
            m["model"] = m["snapshot"] = f"test-{ref.lower()}-model-2026-01-01"
            if m["provider"] == "google":
                m["model"] = m["snapshot"] = f"test-{ref.lower()}-model-001"
        m["reasoning_params"] = {}
    obj["allowed_precisions"] = ["test-precision"]
    for ref in obj["prices_usd_per_mtok"]:
        obj["prices_usd_per_mtok"][ref] = {"input": 1.0, "output": 2.0}
    obj["openweight_cost"]["gpu_hour_usd"] = 1.0
    obj["vul4j"]["image"] = "test-image"
    obj["vul4j"]["image_digest"] = "sha256:" + "cd" * 32
    return obj
