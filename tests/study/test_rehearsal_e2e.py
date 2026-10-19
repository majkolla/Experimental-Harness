"""A rehearsal end to end through the REAL adapters: ContainerVul4J with a fake
`docker` that behaves like the Vul4J CLI on disk, and the open-weight provider
with a fake Ollama. Stages 1-5 on one development CVE, then the log audit.
This is the closest offline stand-in for the first run on the study host."""

import json
import pathlib
import shutil

import pytest

from hp import logs, study_config as S
from hp.bank import classify, generate, reproduce, select, sibling, vul4j
from hp.providers import openweight
from hp.review import dispatch
from tests.study.test_rehearsal import Inspect, Probe, ROOT
from hp import pins
from tests.study.fake_vul4j import FakeDocker

CVE = "VUL4J-12"
MAIN = "src/main/java/p/H.java"
TEST = "src/test/java/p/HTest.java"
VULN = "class H {\n  String clean(String s) {\n    return s;\n  }\n}\n"
FIXED = VULN.replace("return s;", 'return s.replace("<", "");')
POV = "p.HTest#testScript"


def _report(main_text):
    bad = "replace" not in main_text
    fail = ('<failure type="java.lang.AssertionError" message="script survived">'
            "java.lang.AssertionError: script survived\n\tat p.HTest.testScript(HTest.java:9)\n"
            "</failure>") if bad else ""
    return (f'<testsuite name="p.HTest"><testcase classname="p.HTest" name="testScript">{fail}'
            '</testcase><testcase classname="p.HTest" name="testOther"/></testsuite>')


PROJECT = {"main": MAIN, "test": TEST, "vuln": VULN, "fixed": FIXED, "pov": POV,
           "report": _report,
           "info": {"vul_id": CVE, "project_url": "https://github.com/acme/imaging",
                    "build_system": "Maven", "test_all_cmd": "mvn test", "cmd_options": "-Dx",
                    "fixing_commit_hash": "e" * 40, "failing_tests": [POV]}}


def _diff(old, new):
    return (f"```diff\n--- a/{MAIN}\n+++ b/{MAIN}\n@@ -3 +3 @@\n-    {old}\n+    {new}\n```\n")


def fake_chat(spec, prompt, cfg, contract):
    model = spec["model"]
    meta = {"served_model": model, "stop_reason": "stop", "in_tokens": 100, "out_tokens": 20,
            "_durations_ns": {"load_duration": 0, "prompt_eval_duration": 10**8,
                              "eval_duration": 10**8}}
    if "is still not fully fixed" in prompt:                      # twin drafting (Z)
        return _diff("return s.trim();", 'return s.trim().replace("<", "");'), meta
    if "Output exactly one unified diff" in prompt:               # generation
        if model.startswith(("granite", "devstral")):
            return _diff("return s;", 'return s.replace("<", "");'), meta   # a real fix
        return _diff("return s;", "return s.trim();"), meta                # a near-miss
    risky = "trim()" in prompt and "replace" not in prompt.split("```diff")[-1]
    return ({"verdict": "reject" if risky and "qwen" in model else "approve",
             "risk": 80 if risky else 10, "justification": "fake review"}, meta)


@pytest.fixture
def rehearsal(tmp_path, monkeypatch):
    shutil.copy(ROOT / "study.rehearsal.jsonc", tmp_path / "study.rehearsal.jsonc")
    shutil.copytree(ROOT / "prompts", tmp_path / "prompts")
    (tmp_path / "docs" / "spec").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "spec" / "proposed_split.json", tmp_path / "docs" / "spec")
    (tmp_path / "bank_inputs" / "advisories").mkdir(parents=True)
    shutil.copy(ROOT / "bank_inputs" / "advisories" / f"{CVE}.json",
                tmp_path / "bank_inputs" / "advisories")
    path = tmp_path / "study.rehearsal.jsonc"
    path.write_text(path.read_text().replace('"/data/vul4j-work"', json.dumps(str(tmp_path / "w"))))
    pins.run(path, write=True, probe_factory=Probe,
             docker_run=Inspect(["tuhhsoftsec/vul4j@sha256:" + "cd" * 32]))
    openweight.set_probe_factory(Probe)
    monkeypatch.setattr(openweight, "_chat", fake_chat)
    docker = FakeDocker(PROJECT, CVE, "sha256:" + "99" * 32)   # the local build's image id
    monkeypatch.setattr(vul4j.ContainerVul4J, "_run", staticmethod(docker))
    yield S.load(path)
    openweight.set_probe_factory(openweight.OllamaProbe)


def test_a_rehearsal_runs_stages_1_to_5_through_the_real_adapters(rehearsal):
    cfg = rehearsal
    rd = S.runs_dir(cfg)
    rd.mkdir(parents=True)
    nop = lambda s: None  # noqa: E731
    with vul4j.runner_for(cfg) as runner:
        assert isinstance(runner, vul4j.ContainerVul4J)
        repro = reproduce.run(cfg, runner, rd, cves=[CVE], jobs=2)
        assert repro[0]["status"] == "eligible", repro[0]
        assert repro[0]["ordinary_tests"] == ["p.HTest#testOther"]
        generate.run(cfg, runner, "development", rd / logs.FILES["attempts"], sleep=nop)
        cls = classify.run(cfg, runner, "development", rd, jobs=4)
        by_gen = {}
        for r in cls:
            by_gen.setdefault(r["generator"], set()).add(r["class"])
        assert by_gen["A"] == {"near_miss"} and by_gen["Y"] == {"blocked"}
        select.run(cfg, "development", rd)
        sib = [r for r in sibling.run(cfg, runner, "development", rd) if r["kind"] == "sibling"]
        final = {r["pair_id"]: r for r in sib}            # latest row per pair
        assert final and all(r["status"] == "valid" and r["method"] == "openweight_model"
                             for r in final.values())
        assert sum(r["status"] == "drafted" for r in sib) == len(final)   # draft logged first
        summary = dispatch.run(cfg, runner, "development", rd, sleep=nop)
        assert not summary["excluded_pairs"], summary
    reviews = [r for r in logs.read(rd / logs.FILES["reviews"]) if r.get("kind") == "review"]
    assert reviews and all(r["status"] == "ok" for r in reviews)
    assert {r["mode"] for r in reviews} == {"rehearsal"}
    assert all(r["weights_sha"] == "ab" * 32 for r in reviews)
    logs.audit(rd)   # every row has every required field
    assert not list((pathlib.Path(cfg["vul4j"]["workdir"])).iterdir())   # workspaces removed
