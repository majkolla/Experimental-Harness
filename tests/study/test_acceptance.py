"""`study.py acceptance` offline: the known-answer checks through the REAL adapters
(ContainerVul4J with a fake docker that compiles, tests and fails like Vul4J; the
open-weight provider with a fake Ollama), on study.smoke.jsonc. Also shows that the
checks catch defects: a runner that never reports a build failure, a pin mismatch,
and an edited development report each make the acceptance fail."""

import json

import pytest

import study
from hp import acceptance, pins, study_config as S
from hp.bank import vul4j
from hp.providers import openweight
from tests.study import test_rehearsal_e2e as E
from tests.study.fake_vul4j import FakeDocker
from tests.study.test_smoke_config import Docker, _chat, _run_all, smoke  # noqa: F401


class BuildingDocker(Docker):
    """Like the fake Vul4J, but a patched project with a syntax error does not build."""

    def __init__(self, *a, builds_always=False, **k):
        super().__init__(*a, **k)
        self.builds_always = builds_always

    def _vul4j(self, ws, cmd):
        if cmd[1] == "compile" and not self.builds_always:
            if "StudyAcceptanceCanaryBroken" in (ws / "src" / self.p["main"]).read_text():
                (ws / "src" / "VUL4J" / "compile.log").write_text("COMPILATION ERROR\nBUILD FAILURE\n")
                return 1, "", "BUILD FAILURE"
        return super()._vul4j(ws, cmd)


def _fake_ollama(toy_diff_from=("qwen",)):
    base = _chat("near_miss")

    def chat(spec, prompt, cfg, contract):
        payload, meta = base(spec, prompt, cfg, contract)
        if acceptance.TOY_PATH in prompt and "Output exactly one unified diff" in prompt:
            if spec["model"].startswith(toy_diff_from):
                payload = "```diff\n" + acceptance.unified(
                    acceptance.TOY_PATH, acceptance.TOY_BEFORE, acceptance.TOY_AFTER) + "```\n"
            else:
                payload = "I would validate the name."
        return payload, meta
    return chat


@pytest.fixture
def host(smoke, monkeypatch):
    tmp, c = smoke
    pins.run(c, write=True)
    monkeypatch.setattr(openweight, "_chat", _fake_ollama())
    monkeypatch.setattr(vul4j.ContainerVul4J, "_run",
                        staticmethod(BuildingDocker(E.PROJECT, E.CVE, "sha256:" + "99" * 32)))
    return tmp, c


def _rows(rep, section=None):
    return {r["check"]: r for r in rep.rows if section in (None, r["section"])}


def test_vul4j_canaries_get_their_known_classes(host):
    _, c = host
    rep, path = acceptance.run(S.load(c), cves=[E.CVE], only=("vul4j",))
    rows = _rows(rep, "vul4j")
    want = ["image built from the pinned Vul4J commit", f"{E.CVE}: Stage 1 status",
            f"{E.CVE}: human patch", f"{E.CVE}: comment-only change", f"{E.CVE}: syntax error",
            f"{E.CVE}: wrong context", f"{E.CVE}: empty response",
            f"{E.CVE}: twin validator, human patch", f"{E.CVE}: twin validator, comment-only change"]
    for name in want:
        assert rows[name]["status"] == "PASS", rows[name]
    assert rep.failed == 0 and path.is_file() and "ACCEPTED" in path.read_text()
    doc = json.loads(path.with_suffix(".json").read_text())
    assert doc["accepted"] is True and doc["sections"] == ["vul4j"]


def test_a_runner_that_misses_build_failures_is_not_accepted(host, monkeypatch):
    _, c = host
    monkeypatch.setattr(vul4j.ContainerVul4J, "_run", staticmethod(
        BuildingDocker(E.PROJECT, E.CVE, "sha256:" + "99" * 32, builds_always=True)))
    rep, _ = acceptance.run(S.load(c), cves=[E.CVE], only=("vul4j",))
    row = _rows(rep, "vul4j")[f"{E.CVE}: syntax error"]
    assert row["status"] == "FAIL" and "'build_fail'" in row["detail"]
    assert "NOT ACCEPTED" in rep.text()


def test_model_plumbing_checks(host):
    _, c = host
    rep, _ = acceptance.run(S.load(c), only=("models",))
    rows = _rows(rep, "models")
    assert rep.failed == 0, [r for r in rep.rows if r["status"] == "FAIL"]
    for tag in ("qwen3.5:9b", "granite4.2:8b", "gemma4:e4b", "qwen3.5:4b", "granite4.2:3b",
                "gemma4:e2b"):
        mine = {k: v for k, v in rows.items() if k.startswith(tag + " ")}
        assert mine[next(k for k in mine if k.endswith("served weights match the pins"))]["status"] == "PASS"
        assert mine[next(k for k in mine if k.endswith("context guard"))]["status"] == "PASS"
        assert mine[next(k for k in mine if k.endswith("review call, schema-valid verdict"))]["status"] == "PASS"
        gen = [k for k in mine if k.endswith("generation call")]
        assert bool(gen) == (tag in ("qwen3.5:9b", "granite4.2:8b", "gemma4:e4b"))
    applies = {k.split(" ")[0]: v["status"] for k, v in rows.items() if k.endswith("diff applies")}
    assert applies == {"qwen3.5:9b": "PASS", "granite4.2:8b": "WARN", "gemma4:e4b": "WARN"}


def test_a_pin_mismatch_is_not_accepted(host, monkeypatch):
    _, c = host

    class Other:
        def __init__(self, host):
            pass

        def version(self):
            return "0.14.0"            # Ollama was upgraded since `pin --write`

        def facts(self, model):
            return {"weights_sha": "ab" * 32, "precision": "Q8_0"}

    openweight.set_probe_factory(Other)
    rep, _ = acceptance.run(S.load(c), only=("models",))
    pinrows = [r for r in rep.rows if r["check"].endswith("served weights match the pins")]
    assert pinrows and all(r["status"] == "FAIL" and "0.14.0" in r["detail"] for r in pinrows)


def test_logs_section_after_a_smoke_run(host, capsys):
    tmp, c = host
    rep, _ = acceptance.run(S.load(c), only=("logs",))
    assert _rows(rep)["development report reproducible"]["status"] == "SKIP"
    _run_all(c, capsys)                                    # the smoke run of docs/smoke-test.md
    rep, _ = acceptance.run(S.load(c), only=("logs",))
    assert rep.failed == 0 and _rows(rep)["development report reproducible"]["status"] == "PASS"
    rd = S.runs_dir(S.load(c))
    d = json.loads((rd / "dev_report.json").read_text())
    d["label"] = "edited by hand"
    (rd / "dev_report.json").write_text(json.dumps(d))
    rep, _ = acceptance.run(S.load(c), only=("logs",))
    assert _rows(rep)["development report reproducible"]["status"] == "FAIL"


def test_analysis_known_truth_and_the_cli(host, capsys):
    _, c = host
    rc = study.main(["acceptance", c])               # every section; exits 1 if not accepted
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "ACCEPTED" in out and "NOT ACCEPTED" not in out
    for name in ("planted concentrated common cause recovered",
                 "planted same-model blind spot recovered",
                 "confirmatory numbers recomputed from logs"):
        assert f"[PASS] {name}" in out


def test_unknown_section_is_refused(host):
    _, c = host
    with pytest.raises(SystemExit) as exc:
        study.main(["acceptance", c, "--only", "everything"])
    assert "unknown section" in str(exc.value.code)


@pytest.mark.parametrize("text,where", [
    ("/*\n * License\n */\npackage a.b;\n\nclass H {\n}", "after package"),   # no final newline
    ("package a;\r\nclass H {\r\n}\r\n", "after package"),                     # CRLF
    ("class H {\n}\n", "end"),                                                 # default package
])
def test_canaries_apply_and_land_outside_comments(text, where):
    from hp.bank import difftools
    for line in (acceptance.CANARY_COMMENT, acceptance.CANARY_BROKEN):
        after = acceptance._insert(text, line)
        assert difftools.apply({"H.java": text}, acceptance.unified("H.java", text, after))["H.java"] == after
        lines = after.splitlines()
        i = lines.index(line.rstrip("\n"))
        assert lines[i - 1].startswith("package") if where == "after package" else i == len(lines) - 1


def test_no_canary_when_it_cannot_be_placed_safely():
    assert acceptance._insert("class H {\n}", acceptance.CANARY_COMMENT) is None
