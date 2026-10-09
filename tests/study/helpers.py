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


def synthetic_cfg(tmp_path, with_code=False, edits=None):
    """Load the shipped synthetic config from a fresh study dir (optionally edited)."""
    d = make_study_dir(tmp_path, with_code=with_code)
    p = d / "study.synthetic.jsonc"
    if edits:
        edit(p, edits)
    cfg = S.load(p)
    S.runs_dir(cfg).mkdir(parents=True, exist_ok=True)
    return cfg


def build_bank(cfg, split_name="development"):
    """Run Stages 1-4 on the synthetic world for one split. Returns the runner."""
    from hp import logs
    from hp.bank import classify, generate, reproduce, select, sibling, vul4j

    rd = S.runs_dir(cfg)
    runner = vul4j.runner_for(cfg)
    reproduce.run(cfg, runner, rd)
    generate.run(cfg, runner, split_name, rd / logs.FILES["attempts"], sleep=lambda s: None)
    classify.run(cfg, runner, split_name, rd)
    select.run(cfg, split_name, rd)
    sibling.run(cfg, runner, split_name, rd)
    return runner


def make_view(pairs, trials, split="test", view="core"):
    """A hand-built analysis View.

    pairs: [(pair_id, cve, cluster, generator)]
    trials: {(pair_id, state, reviewer): [(status, verdict, risk) x 3]} -- or a
            callable (pair_id, state, reviewer) -> that list, applied to every
            (pair, state, reviewer) of `reviewers` given as trials["_reviewers"].
    """
    from hp.analysis import data as D

    pmap = {pid: {"pair_id": pid, "cve": cve, "cluster": cl, "generator": g, "cwe": None,
                  "similarity": None, "patch_size": None, "method": "author"}
            for pid, cve, cl, g in pairs}
    obs, cost = {}, {}
    if callable(trials.get("_fn")):
        items = {(pid, s, r): trials["_fn"](pid, s, r)
                 for pid in pmap for s in ("V", "F") for r in trials["_reviewers"]}
    else:
        items = trials
    import collections

    unresolved = collections.Counter()
    for (pid, s, r), ts in items.items():
        lst = []
        for status, verdict, risk in ts:
            lst.append(D.Trial(status, verdict, risk, cost=1.0, attempts=1))
            if status != "ok":
                unresolved[(r, s)] += 1
        obs[(pid, s, r, None)] = lst
        c = cost.setdefault(r, [0.0, 0])
        c[0] += len(lst)
        c[1] += len(lst)
    return D.View(split, view, pmap, obs, unresolved, cost, {})


def ok(risk, verdict="approve"):
    return ("ok", verdict, risk)
