"""study.smoke.jsonc end to end through the exact CLI commands of docs/smoke-test.md,
with the REAL adapters (ContainerVul4J with a fake docker, openweight with a fake
Ollama). Two scenarios: generators that produce near-misses, and weak generators that
never do (empty bank): every later stage must still finish and the logs must audit."""

import json
import shutil

import pytest

import study
from hp import pins
from hp.bank import vul4j
from hp.providers import openweight
from tests.study import test_rehearsal_e2e as E
from tests.study.fake_vul4j import FakeDocker
from tests.study.test_rehearsal import Inspect, Probe, ROOT

GEN = "Output exactly one unified diff"
TWIN = "is still not fully fixed"


class Docker(FakeDocker):
    def __call__(self, argv, timeout=None):
        if argv[1] == "run" and "-v" not in argv and "-d" not in argv:   # provenance probe
            return 0, ("376411da11fa705019f731404de1d0679fe73537\nCOMMIT_OK\nWARMUP_OK\n"
                       "FAILED:\n"), ""
        return super().__call__(argv, timeout)


def _chat(scenario):
    def chat(spec, prompt, cfg, contract):
        payload, meta = E.fake_chat(spec, prompt, cfg, contract)
        if GEN in prompt and TWIN not in prompt:
            model = spec["model"]
            if scenario == "no_near_miss" and model.startswith("gemma"):
                payload = "I cannot produce a diff for this."              # unparseable
            elif scenario == "no_near_miss" or model.startswith("gemma"):
                payload = E._diff("return s;", 'return s.replace("<", "");')   # a real fix
        return payload, meta
    return chat


@pytest.fixture
def smoke(tmp_path, monkeypatch):
    cfg = tmp_path / "study.smoke.jsonc"
    shutil.copy(ROOT / "study.smoke.jsonc", cfg)
    shutil.copytree(ROOT / "prompts", tmp_path / "prompts")
    (tmp_path / "bank_inputs" / "advisories").mkdir(parents=True)
    shutil.copy(ROOT / "bank_inputs" / "advisories" / f"{E.CVE}.json",
                tmp_path / "bank_inputs" / "advisories")
    (tmp_path / "docs" / "spec").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "spec" / "proposed_split.json", tmp_path / "docs" / "spec")
    cfg.write_text(cfg.read_text().replace('"/data/vul4j-work"', json.dumps(str(tmp_path / "w"))))
    real_pin = pins.run
    monkeypatch.setattr(pins, "run", lambda path, write=False, vul4j=True: real_pin(
        path, write=write, vul4j=vul4j, probe_factory=Probe,
        docker_run=Inspect([], image_id="sha256:" + "99" * 32)))
    openweight.set_probe_factory(Probe)
    monkeypatch.setattr(vul4j.ContainerVul4J, "_run",
                        staticmethod(Docker(E.PROJECT, E.CVE, "sha256:" + "99" * 32)))
    monkeypatch.setattr("time.sleep", lambda s: None)
    yield tmp_path, str(cfg)
    openweight.set_probe_factory(openweight.OllamaProbe)


def _run_all(c, capsys):
    steps = [["pin", c, "--write"], ["validate", c], ["vul4j-check", c, "--cve", E.CVE],
             ["timing-pilot", c, "--cves", E.CVE, "--runs", "1"],
             ["reproduce", c, "--cves", E.CVE, "--jobs", "2"],
             ["generate", c, "--split", "development"],
             ["classify", c, "--split", "development", "--jobs", "2"],
             ["select", c, "--split", "development"], ["sibling", c, "--split", "development"],
             ["bank", c, "--split", "development"],
             ["review", c, "--split", "development", "--expb"],
             ["analyse-dev", c], ["audit-logs", c]]
    out = {}
    for argv in steps:
        assert study.main(argv) == 0, argv
        out[argv[0]] = capsys.readouterr().out
    return out


def test_smoke_config_is_the_rehearsal_with_small_models_and_a_small_design(smoke):
    from hp import study_config as S
    _, c = smoke
    pins.run(c, write=True)
    cfg = S.load(c)
    assert cfg["mode"] == "rehearsal" and "rehearsal" in cfg["paths"]["runs"]
    assert cfg["paths"]["runs"] != "runs/rehearsal"              # never mixes with the rehearsal
    assert cfg["design"]["attempts_per_cell"] == 2 and cfg["design"]["reruns"] == 3
    assert {m["model"] for m in cfg["models"].values()} == {
        "qwen3.5:9b", "granite4.2:8b", "gemma4:e4b", "qwen3.5:4b", "granite4.2:3b", "gemma4:e2b"}
    for big, ext in (("A", "X"), ("B", "Y"), ("C", "Z")):           # one loaded instance each
        assert cfg["models"][big]["model"] == cfg["models"][ext]["model"]
    rehearsal = S.parse_jsonc((ROOT / "study.rehearsal.jsonc").read_text())
    assert cfg["split"] == rehearsal["split"] and cfg["prompts"] == rehearsal["prompts"]


def test_smoke_run_with_near_misses(smoke, monkeypatch, capsys):
    monkeypatch.setattr(openweight, "_chat", _chat("near_miss"))
    tmp, c = smoke
    out = _run_all(c, capsys)
    assert "OK" in out["vul4j-check"]
    assert "'calls': 12" in out["generate"]                      # 6 generators x 2 attempts
    assert "near_miss" in out["classify"]
    assert "0 pairs" not in out["bank"]
    assert "'calls': 0," not in out["review"]
    assert "REHEARSAL" in out["analyse-dev"]
    assert not list((tmp / "w").iterdir())                        # workspaces removed


def test_smoke_run_without_any_near_miss_finishes_with_an_empty_bank(smoke, monkeypatch, capsys):
    monkeypatch.setattr(openweight, "_chat", _chat("no_near_miss"))
    _, c = smoke
    out = _run_all(c, capsys)
    assert "near_miss" not in out["classify"]
    assert "0 pairs" in out["bank"] and "'calls': 0," in out["review"]
