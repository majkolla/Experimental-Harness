"""ContainerVul4J against tests/study/fake_vul4j.FakeDocker, which reproduces what
the Vul4J image does on disk (checked against the Vul4J source, commit 376411d)."""

import json

import pytest

from hp.bank import vul4j
from tests.study.fake_vul4j import FakeDocker

IMG = "img@sha256:" + "ab" * 32
MAIN = "core/src/main/java/p/H.java"
TEST = "core/src/test/java/p/HTest.java"
VULN = "class H { String clean(String s) { return s; } }\n"
FIXED = "class H { String clean(String s) { return s.replace(\"<\", \"\"); } }\n"
POV = "p.HTest#testScript"

INFO = {  # the keys Vulnerability.to_json writes (project is a list: tuple in the source)
    "vul_id": "VUL4J-1", "cve_id": "CVE-2099-0001", "cwe_id": "CWE-79",
    "project": ["acme_widgets"], "project_url": "https://github.com/acme/widgets",
    "build_system": "Maven", "compliance_level": "8", "compile_cmd": "mvn -pl core -am install",
    "test_all_cmd": "mvn test -pl core", "test_cmd": "mvn test -pl core -Dtest=p.HTest",
    "cmd_options": "-Drat.skip=true -Denforcer.skip=true", "failing_module": "core",
    "fixing_commit_hash": "f" * 40,
    "human_patch_url": "https://github.com/acme/widgets/commit/" + "f" * 40,
    "failing_tests": [POV], "warning": [""],
}


def _report(src_text, cls="p.HTest"):
    vulnerable = "replace" not in src_text
    body = ('<failure type="java.lang.AssertionError" message="expected no script">'
            "java.lang.AssertionError: expected no script\n"
            "\tat p.HTestHelper.check(HTestHelper.java:3)\n"
            "\tat p.HTest.testScript(HTest.java:12)\n</failure>") if vulnerable else ""
    return (f'<testsuite name="{cls}"><testcase classname="{cls}" name="testScript">{body}'
            f'</testcase><testcase classname="{cls}" name="testOther"/></testsuite>')


PROJECT = {"main": MAIN, "test": TEST, "vuln": VULN, "fixed": FIXED, "pov": POV,
           "info": INFO, "report": _report, "report_dir": "core/target/surefire-reports"}


def _fake(**kw):
    return FakeDocker(PROJECT, "VUL4J-1", IMG, **kw)


def _runner(tmp_path, fake, **extra):
    v = {"image": "img", "image_digest": "sha256:" + "ab" * 32, "cli": "vul4j",
         "workdir": str(tmp_path / "w"), **extra}
    return vul4j.ContainerVul4J({"vul4j": v}, run=fake)


def test_one_container_per_checkout_pinned_offline_amd64(tmp_path):
    fake = _fake()
    with _runner(tmp_path, fake, cpus_per_container=8, memory_per_container="32g") as r:
        h = r.prepare("VUL4J-1", "fixed")
        for _ in range(3):
            r.run_tests(h)
        r.release(h)
    starts = [a for a in fake.seen if a[1] == "run" and "-d" in a]
    assert len(starts) == 1 + 1          # the build handle + the reference checkout (metadata)
    for a in starts:
        assert a[:5] == ["docker", "run", "-d", "--rm", "--init"]
        assert a[a.index("--platform") + 1] == "linux/amd64"
        assert a[a.index("--network") + 1] == "none"
        assert a[a.index("--cpus") + 1] == "8" and a[a.index("--memory") + 1] == "32g"
        assert IMG in a
    # checkout, apply, compile and all three test runs happened in ONE container
    handle_execs = [a for a in fake.seen if a[1] == "exec" and a[2] == starts[0][starts[0].index("--name") + 1]]
    lines = [" ".join(a[3:]) for a in handle_execs]
    assert sum("vul4j checkout" in l for l in lines) == 1
    assert sum("vul4j compile" in l for l in lines) == 1
    assert sum("vul4j test" in l for l in lines) == 3
    assert not fake.containers                           # every container removed
    assert list((tmp_path / "w").iterdir()) == []


def test_full_suite_command_gets_the_dataset_options(tmp_path):
    fake = _fake()
    with _runner(tmp_path, fake) as r:
        r.release(r.prepare("VUL4J-1", "vulnerable"))
        assert r._meta("VUL4J-1")["test_all_cmd"] == fake.info_seen["test_all_cmd"]
    assert fake.info_seen["test_all_cmd"] == "mvn test -pl core -Drat.skip=true -Denforcer.skip=true"
    assert vul4j.effective_test_all_cmd({"build_system": "Maven", "test_all_cmd":
                                         "mvn -pl rt/rs/security/sso/saml", "cmd_options": "-Dx"}) \
        == "mvn -pl rt/rs/security/sso/saml test -Dx"     # VUL4J-16 has no goal
    assert vul4j.effective_test_all_cmd({"build_system": "Gradle", "test_all_cmd": "./gradlew test",
                                         "cmd_options": ""}) == "./gradlew test"


def test_metadata_comes_from_the_checkout_not_the_log(tmp_path):
    fake = _fake()
    with _runner(tmp_path, fake) as r:
        assert r.human_files("VUL4J-1") == [MAIN]
        assert r.pov_tests("VUL4J-1") == [POV]
        assert r.pov_test_files("VUL4J-1") == [TEST]
        assert r.module_tests("VUL4J-1") is None
        diff = r.human_patch("VUL4J-1")
        assert diff.startswith(f"--- a/{MAIN}\n+++ b/{MAIN}\n")
        meta = r.metadata("VUL4J-1")
        assert meta["cluster"] == "acme/widgets" and meta["commit_hashes"] == ["f" * 40]
        assert meta["pov_output"] == []        # no reproduction log yet
        assert {"acme", "widgets"} <= set(meta["allowed_project_tokens"])
        assert r.list_files("VUL4J-1") == [MAIN, TEST]   # the VUL4J folder is not source
        assert r.read_files("VUL4J-1", [MAIN], "fixed") == {MAIN: FIXED}
    assert not any("vul4j info" in c for c in fake.cmds)
    assert list((tmp_path / "w").iterdir()) == []


def test_pov_output_is_read_from_the_reproduction_log(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    sig = {"type": "java.lang.AssertionError", "message": "expected no script", "frame": "x"}
    (runs / "reproduction.jsonl").write_text(json.dumps(
        {"kind": "reproduction", "cve": "VUL4J-1", "signature": {POV: sig}}) + "\n")
    cfg = {"vul4j": {"image": "img", "image_digest": "sha256:" + "ab" * 32,
                     "workdir": str(tmp_path / "w")},
           "_root": tmp_path, "paths": {"runs": "runs"}}
    with vul4j.ContainerVul4J(cfg, run=_fake()) as r:
        assert r.metadata("VUL4J-1")["pov_output"] == ["expected no script"]


def test_stage1_reference_versions_and_signatures(tmp_path):
    fake = _fake()
    with _runner(tmp_path, fake) as r:
        h = r.prepare("VUL4J-1", "vulnerable")
        run = r.run_tests(h)
        assert run.completed
        assert run.outcome(POV) == "fail"
        assert run.signature(POV) == {"type": "java.lang.AssertionError",
                                      "message": "expected no script",
                                      "frame": "p.HTest.testScript(HTest.java)"}  # not HTestHelper
        assert run.outcome("p.HTest#testOther") == "pass"
        r.release(h)
        h = r.prepare("VUL4J-1", "fixed")
        assert r.run_tests(h).outcome(POV) == "pass"
        r.release(h)
    assert "timeout -k 30 7200 vul4j test -d /ws/src -b all" not in fake.cmds  # timeout stripped
    assert "vul4j test -d /ws/src -b all" in fake.cmds


def test_pov_names_that_differ_only_in_case_are_mapped(tmp_path):
    project = {**PROJECT, "info": {**INFO, "failing_tests": ["P.HTest#testScript"]}}
    fake = FakeDocker(project, "VUL4J-1", IMG)
    with _runner(tmp_path, fake) as r:
        h = r.prepare("VUL4J-1", "vulnerable")
        run = r.run_tests(h)
        r.release(h)
    assert run.outcome("P.HTest#testScript") == "fail"


def test_a_model_diff_is_applied_like_the_review_stage_does(tmp_path):
    fake = _fake()
    good = (f"--- a/{MAIN}\n+++ b/{MAIN}\n@@ -1 +1 @@\n-{VULN.rstrip()}\n+{FIXED.rstrip()}\n")
    wrong_line_numbers = good.replace("@@ -1 +1 @@", "@@ -7 +7 @@")   # LLM-style offsets
    with _runner(tmp_path, fake) as r:
        for diff in (good, wrong_line_numbers):
            h = r.prepare("VUL4J-1", "vulnerable", diff)
            assert h.version == "patched"
            assert r.patched_files(h, [MAIN]) == {MAIN: FIXED}
            run = r.run_tests(h, tests=[POV])
            assert run.outcome(POV) == "pass" and set(run.results) == {POV}
            r.release(h)
        delete = f"--- a/{TEST}\n+++ /dev/null\n@@ -1 +0,0 @@\n-class HTest {{}}\n"
        h = r.prepare("VUL4J-1", "vulnerable", delete)
        assert r.patched_files(h, [TEST]) == {}
        r.release(h)
        bad = f"--- a/{MAIN}\n+++ b/{MAIN}\n@@ -1 +1 @@\n-class Nope {{}}\n+class H {{}}\n"
        with pytest.raises(vul4j.ApplyError):
            r.prepare("VUL4J-1", "vulnerable", bad)
        for escape in ("--- a/../etc/x\n+++ b/../etc/x\n@@ -1 +1 @@\n-a\n+b\n",
                       "--- a/VUL4J/x\n+++ b/VUL4J/x\n@@ -1 +1 @@\n-a\n+b\n"):
            with pytest.raises(vul4j.ApplyError, match="outside the project"):
                r.prepare("VUL4J-1", "vulnerable", escape)
    assert "vul4j test -d /ws/src -b povs" in fake.cmds   # PoV-only selection
    assert list((tmp_path / "w").iterdir()) == []


def test_build_failures_and_infrastructure_failures_differ(tmp_path):
    with _runner(tmp_path, _fake(fail_on="vul4j compile")) as r:
        with pytest.raises(vul4j.BuildError):
            r.prepare("VUL4J-1", "vulnerable")
    for code in (124, 137, 125):
        fake = _fake(fail_on="vul4j compile")
        fake.fail_on_code = code
        with _runner(tmp_path, fake) as r:
            with pytest.raises(vul4j.InfraError):
                r.prepare("VUL4J-1", "vulnerable")
    fake = _fake(fail_on="vul4j checkout")
    with _runner(tmp_path, fake) as r:
        with pytest.raises(vul4j.InfraError, match="checkout"):
            r.prepare("VUL4J-1", "vulnerable")
    assert list((tmp_path / "w").iterdir()) == []


def test_a_test_timeout_is_an_incomplete_run_not_a_crash(tmp_path):
    fake = _fake()
    with _runner(tmp_path, fake, test_timeout_s=5) as r:
        h = r.prepare("VUL4J-1", "vulnerable")
        fake.fail_on, fake.fail_on_code = "vul4j test", 124
        run = r.run_tests(h)
        fake.fail_on_code = 125
        with pytest.raises(vul4j.InfraError):
            r.run_tests(h)
        r.release(h)
    assert run.completed is False and run.error.startswith("timeout")
    execs = [a for a in fake.seen if a[1] == "exec" and "test" in a]
    assert all(a[3:7] == ["timeout", "-k", "30", "5"] for a in execs)


def test_interrupt_kills_running_containers_and_nothing_is_logged(tmp_path):
    fake = _fake()
    r = _runner(tmp_path, fake)
    h = r.prepare("VUL4J-1", "vulnerable")
    assert len(fake.containers) == 1
    r.interrupt()
    assert not fake.containers
    with pytest.raises(vul4j.InfraError, match="interrupted"):
        r.run_tests(h)
    r.close()


def test_a_locally_built_image_is_run_by_its_image_id(tmp_path):
    fake = FakeDocker(PROJECT, "VUL4J-1", "sha256:" + "cd" * 32)
    v = {"image": "vul4j:376411d", "image_digest": "sha256:" + "cd" * 32, "pin_kind": "image_id",
         "workdir": str(tmp_path / "w")}
    with vul4j.ContainerVul4J({"vul4j": v}, run=fake) as r:
        r.release(r.prepare("VUL4J-1", "vulnerable"))
    assert all("sha256:" + "cd" * 32 in a for a in fake.seen if a[1] == "run")


def test_find_reports_covers_maven_modules_failsafe_and_gradle(tmp_path):
    for rel in ("a/target/surefire-reports/TEST-x.xml", "target/failsafe-reports/TEST-y.xml",
                "m/build/test-results/test/TEST-z.xml", "target/site/TEST-no.xml",
                "target/surefire-reports/other.xml"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("<testsuite/>")
    got = [p.relative_to(tmp_path).as_posix() for p in vul4j.find_reports(tmp_path)]
    assert got == ["a/target/surefire-reports/TEST-x.xml",
                   "m/build/test-results/test/TEST-z.xml",
                   "target/failsafe-reports/TEST-y.xml"]


def test_unified_diff_splits_on_newlines_only(tmp_path):
    from hp.bank import difftools
    before = {"a.java": "x\x0cy\nz\n"}
    after = {"a.java": "x\x0cy\nzz\n"}
    d = vul4j.unified_diff(before, after)
    assert difftools.apply(before, d) == after


def test_provenance_reports_the_build_commit_and_the_warmup(tmp_path):
    def run(argv, timeout=None):
        assert argv[1] == "run" and argv[-3:-1] == ["sh", "-c"]
        assert "merge-base --is-ancestor 376411d HEAD" in argv[-1]
        return 0, "abc123\nCOMMIT_OK\nWARMUP_OK\nFAILED:\nVUL4J-16\nVUL4J-40\n", ""

    r = _runner(tmp_path, run)
    assert r.provenance("376411d") == {"head": "abc123", "commit_ok": True, "warmup_ran": True,
                                       "warmup_failed": ["VUL4J-16", "VUL4J-40"]}
