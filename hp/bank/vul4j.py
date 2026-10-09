"""The only code that touches project sources: Vul4J checkout, build and test.

Everything above this module sees a `Vul4JRunner`:

    prepare(cve, version="vulnerable", diff=None) -> Handle
        check out the version, apply `diff` if given, build ONCE
        (raises ApplyError / BuildError)
    run_tests(handle, scope="full", tests=None) -> SuiteRun
        one test run in a clean state (no rebuild); per-test results with a
        failure signature for every failing test
    read_files / list_files / human_files / human_patch / pov_tests /
    pov_test_files / module_tests / describe

Two implementations:

* `MockVul4J` runs on the synthetic world (`hp.synthworld`). It is what the
  test suite and the offline self-test use.
* `ContainerVul4J` drives the Vul4J command-line tool inside the pinned
  container image. It cannot be exercised offline: the command lines below are
  the plan, and must be checked against the pinned image before Stage 1
  (docs/study.html, "still to verify"). Failure signatures are read from the
  surefire XML reports, because Vul4J's own test summary does not carry the
  exception type or assertion message (risk R1 in PLAN.md).

A failure signature is (exception type, whitespace-normalised message, first
stack frame inside the PoV test class); see PLAN.md section 10 item 14.
"""

import json
import pathlib
import shutil
import re
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

from .. import synthworld
from . import difftools


class ApplyError(RuntimeError):
    pass


class BuildError(RuntimeError):
    pass


class TestResult:
    __test__ = False  # not a pytest test class
    __slots__ = ("name", "outcome", "signature")

    def __init__(self, name, outcome, signature=None):
        self.name = name
        self.outcome = outcome  # pass | fail | error | skipped
        self.signature = signature

    @property
    def passed(self):
        return self.outcome == "pass"

    def as_dict(self):
        return {"name": self.name, "outcome": self.outcome, "signature": self.signature}


class SuiteRun:
    def __init__(self, completed, results, wall_s, scope, error=None):
        self.completed = completed
        self.results = results  # {name: TestResult}
        self.wall_s = wall_s
        self.scope = scope
        self.error = error

    def outcome(self, name):
        r = self.results.get(name)
        return r.outcome if r else "missing"

    def signature(self, name):
        r = self.results.get(name)
        return r.signature if r else None


class Handle:
    def __init__(self, cve, version, diff=None, **extra):
        self.cve = cve
        self.version = version
        self.diff = diff
        self.runs = 0
        self.extra = extra

    def category_is_reference(self):
        """True for the unpatched vulnerable / fixed checkouts of Stage 1."""
        return self.extra.get("category") in ("vulnerable", "fixed")


def signature_key(sig):
    if not sig:
        return None
    return "|".join([sig.get("type") or "", " ".join((sig.get("message") or "").split()),
                     sig.get("frame") or ""])


def same_signature(a, b):
    return a is not None and b is not None and signature_key(a) == signature_key(b)


# ---------------------------------------------------------------------------
# surefire reports
# ---------------------------------------------------------------------------


def parse_surefire(xml_texts, pov_classes=()):
    """{ "pkg.Class#method": TestResult } from surefire TEST-*.xml contents."""
    out = {}
    for text in xml_texts:
        root = ET.fromstring(text)
        suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
        for suite in suites:
            for case in suite.findall("testcase"):
                cls = case.get("classname") or suite.get("name") or ""
                name = f"{cls}#{case.get('name')}"
                node, outcome = None, "pass"
                for tag in ("failure", "error"):
                    node = case.find(tag)
                    if node is not None:
                        outcome = "fail" if tag == "failure" else "error"
                        break
                if node is None and case.find("skipped") is not None:
                    outcome = "skipped"
                sig = None
                if node is not None:
                    frame = None
                    for line in (node.text or "").splitlines():
                        line = line.strip()
                        if line.startswith("at ") and cls and cls in line:
                            frame = re.sub(r":\d+\)$", ")", line[3:])
                            break
                    sig = {"type": node.get("type"),
                           "message": " ".join((node.get("message") or "").split()),
                           "frame": frame}
                out[name] = TestResult(name, outcome, sig)
    return out


# ---------------------------------------------------------------------------
# mock (synthetic world)
# ---------------------------------------------------------------------------


class MockVul4J:
    """Vul4J on the synthetic world. Deterministic; instant."""

    name = "mock"

    def __init__(self, world):
        self.world = world

    def describe(self):
        return {"runner": self.name, "image_digest": None}

    def _c(self, cve):
        return self.world.cves[cve]

    def human_files(self, cve):
        return [self._c(cve)["main"]]

    def list_files(self, cve, version="vulnerable"):
        return sorted(self._c(cve)["files"])

    def read_files(self, cve, paths, version="vulnerable"):
        c = self._c(cve)
        src = c["files"] if version == "vulnerable" else c["fixed_files"]
        return {p: src[p] for p in paths if p in src}

    def human_patch(self, cve):
        return self._c(cve)["human_patch"]

    def pov_tests(self, cve):
        return list(self._c(cve)["pov_tests"])

    def pov_test_files(self, cve):
        return list(self._c(cve)["pov_test_files"])

    def module_tests(self, cve):
        c = self._c(cve)
        return list(c["ordinary"]) + list(c["flaky"])

    def metadata(self, cve):
        """What the leak scan must never let through (CVE id, project, commits, PoV)."""
        c = self._c(cve)
        return {"cve": cve, "cluster": c["cluster"], "commit_hashes": c["commit_hashes"],
                "pov_tests": c["pov_tests"], "pov_output": [c["signature"]["message"]],
                "allowed_project_tokens": c["allowed_project_tokens"]}

    def prepare(self, cve, version="vulnerable", diff=None):
        c = self._c(cve)
        if c["status"] == "build_fail":
            raise BuildError("synthetic: project does not build")
        if diff is None:
            files = c["files"] if version == "vulnerable" else c["fixed_files"]
            return Handle(cve, version, None, files=files, category=version)
        try:
            files = difftools.apply(c["files"], diff)
        except difftools.DiffError as exc:
            raise ApplyError(str(exc))
        if synthworld.FIX_TOKEN in files.get(c["main"], ""):
            category = "fix"
        else:
            category = self.world.outcome(cve, difftools.norm_sha(diff))
        if category == "apply_fail":
            raise ApplyError("synthetic: patch does not apply")
        if category == "build_fail":
            raise BuildError("synthetic: patched project does not build")
        sub = None
        if category == "indeterminate":
            sub = ("signature", "inconsistent", "ordinary_flip")[
                int(synthworld.u("indet", cve, difftools.norm_sha(diff)) * 3)]
        return Handle(cve, "patched", diff, files=files, category=category, sub=sub)

    def patched_files(self, handle, paths):
        return {p: handle.extra["files"][p] for p in paths if p in handle.extra["files"]}

    def run_tests(self, handle, scope="full", tests=None):
        c = self._c(handle.cve)
        handle.runs += 1
        k = handle.runs
        if c["status"] == "suite_unstable" and handle.category_is_reference() and k == 2:
            return SuiteRun(False, {}, 1.0, scope, error="synthetic: test run did not complete")
        names = list(c["ordinary"]) + list(c["flaky"]) + list(c["pov_tests"])
        if tests is not None:
            names = [t for t in names if t in set(tests)]
        cat, sub = handle.extra.get("category"), handle.extra.get("sub")
        res = {}
        sig = c["signature"]
        for t in names:
            if t in c["pov_tests"]:
                fails = cat in ("vulnerable", "near_miss") or (
                    cat == "indeterminate" and (sub in ("signature", "ordinary_flip") or (sub == "inconsistent" and k != 4)))
                if cat == "vulnerable" and c["status"] == "pov_unstable" and k == 3:
                    fails = False
                if fails:
                    s = dict(sig)
                    if cat == "indeterminate" and sub == "signature":
                        s = {**sig, "message": "java.lang.NullPointerException"}
                    res[t] = TestResult(t, "fail", s)
                else:
                    res[t] = TestResult(t, "pass")
            elif t in c["flaky"]:
                ok = synthworld.u("flaky", handle.cve, handle.version, t, k) >= 0.3
                res[t] = TestResult(t, "pass" if ok else "fail",
                                    None if ok else {"type": "java.lang.AssertionError",
                                                     "message": "timing", "frame": None})
            else:
                bad = (cat == "regression_fail" and t == c["ordinary"][0]) or (
                    cat == "indeterminate" and sub == "ordinary_flip" and k == 5 and t == c["ordinary"][0])
                res[t] = TestResult(t, "fail" if bad else "pass",
                                    {"type": "java.lang.AssertionError", "message": "regression",
                                     "frame": None} if bad else None)
        return SuiteRun(True, res, 1.0 + 0.01 * len(names), scope)

    def release(self, handle):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# container (real Vul4J); not exercised offline
# ---------------------------------------------------------------------------


class ContainerVul4J:
    """Vul4J CLI inside the pinned container image (`vul4j.image@image_digest`).

    Unverified offline. Each method composes one `docker run` command; the
    `run` callable is injectable so the composition is unit-testable.
    """

    name = "container"

    def __init__(self, cfg, run=None):
        v = cfg["vul4j"]
        self.image = f"{v['image']}@{v['image_digest']}"
        self.cli = v.get("cli", "vul4j")
        self.workdir = pathlib.Path(v.get("workdir", "/tmp/vul4j"))
        self.run = run or self._run
        self._meta_cache = {}   # cve -> parsed `vul4j info`
        self._refs = {}         # (cve, version) -> read-only checkout kept for read_files / list_files

    def describe(self):
        return {"runner": self.name, "image_digest": self.image}

    @staticmethod
    def _run(argv, timeout=None):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def _docker(self, ws, *cmd):
        return ["docker", "run", "--rm", "--network", "none", "-v", f"{ws}:/ws", self.image, *cmd]

    def _remove(self, ws):
        """Delete a workspace. Files written inside the container may be root-owned, so
        the contents are removed from inside the container first."""
        ws = pathlib.Path(ws)
        if not ws.exists():
            return
        self.run(self._docker(ws, "sh", "-c", "rm -rf /ws/* /ws/.[!.]*"))
        shutil.rmtree(ws, ignore_errors=True)

    def _meta(self, cve):
        if cve not in self._meta_cache:
            ws = self.workdir / f"{cve}-meta-{uuid.uuid4().hex[:8]}"
            ws.mkdir(parents=True, exist_ok=True)
            try:
                code, out, err = self.run(self._docker(ws, self.cli, "info", "--id", cve))
            finally:
                self._remove(ws)
            if code:
                raise RuntimeError(f"vul4j info {cve} failed: {err.strip()}")
            self._meta_cache[cve] = json.loads(out)
        return self._meta_cache[cve]

    def human_files(self, cve):
        return list(self._meta(cve).get("human_patch_files", []))

    def human_patch(self, cve):
        return self._meta(cve).get("human_patch", "")

    def pov_tests(self, cve):
        return list(self._meta(cve).get("failing_tests", []))

    def pov_test_files(self, cve):
        return list(self._meta(cve).get("failing_test_files", []))

    def module_tests(self, cve):
        return self._meta(cve).get("module_tests")

    def metadata(self, cve):
        m = self._meta(cve)
        return {"cve": cve, "cluster": m.get("repo_slug"), "commit_hashes": m.get("commits", []),
                "pov_tests": m.get("failing_tests", []), "pov_output": m.get("pov_output", []),
                "allowed_project_tokens": m.get("allowed_project_tokens", [])}

    def prepare(self, cve, version="vulnerable", diff=None):
        """Fresh workspace per call; removed by `release` (or here, if preparing fails)."""
        ws = self.workdir / f"{cve}-{version}-{uuid.uuid4().hex[:8]}"
        ws.mkdir(parents=True, exist_ok=True)
        try:
            self._checkout(ws, cve, version)
            if diff is not None:
                (ws / "candidate.diff").write_text(diff)
                code, _, err = self.run(self._docker(ws, "git", "-C", "/ws/src", "apply",
                                                     "/ws/candidate.diff"))
                if code:
                    raise ApplyError(err.strip())
            code, _, err = self.run(self._docker(ws, self.cli, "compile", "-d", "/ws/src"))
            if code:
                raise BuildError(err.strip())
        except BaseException:
            self._remove(ws)
            raise
        return Handle(cve, version if diff is None else "patched", diff, ws=ws)

    def _checkout(self, ws, cve, version):
        code, _, err = self.run(self._docker(ws, self.cli, "checkout", "--id", cve, "-d", "/ws/src"))
        if code:
            raise BuildError(f"checkout failed: {err.strip()}")
        if version == "fixed":
            code, _, err = self.run(self._docker(ws, self.cli, "apply", "--version", "human_patch",
                                                 "-d", "/ws/src"))
            if code:
                raise ApplyError(f"human patch failed: {err.strip()}")

    def _reference(self, cve, version):
        """Source-only checkout reused by read_files / list_files (no build, no tests)."""
        key = (cve, version)
        if key not in self._refs:
            ws = self.workdir / f"{cve}-{version}-ref-{uuid.uuid4().hex[:8]}"
            ws.mkdir(parents=True, exist_ok=True)
            try:
                self._checkout(ws, cve, version)
            except BaseException:
                self._remove(ws)
                raise
            self._refs[key] = ws
        return self._refs[key]

    def run_tests(self, handle, scope="full", tests=None):
        ws = handle.extra["ws"]
        handle.runs += 1
        cmd = [self.cli, "test", "-d", "/ws/src"]
        if tests is not None:
            cmd += ["--tests", ",".join(sorted(tests))]
        t0 = time.time()
        # clean state for every run: restore the build output, drop old reports
        self.run(self._docker(ws, "sh", "-c", "rm -rf /ws/src/target/surefire-reports"))
        code, out, err = self.run(self._docker(ws, *cmd))
        wall = time.time() - t0
        reports = sorted((ws / "src" / "target" / "surefire-reports").glob("TEST-*.xml")) \
            if (ws / "src" / "target" / "surefire-reports").exists() else []
        if not reports:
            return SuiteRun(False, {}, wall, scope, error=(err or out).strip()[-2000:])
        results = parse_surefire([p.read_text() for p in reports])
        return SuiteRun(True, results, wall, scope)

    def read_files(self, cve, paths, version="vulnerable"):
        root = self._reference(cve, version) / "src"
        return {p: (root / p).read_text() for p in paths if (root / p).is_file()}

    def list_files(self, cve, version="vulnerable"):
        root = self._reference(cve, version) / "src"
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*.java"))

    def patched_files(self, handle, paths):
        root = handle.extra["ws"] / "src"
        return {p: (root / p).read_text() for p in paths if (root / p).is_file()}

    def release(self, handle):
        ws = handle.extra.pop("ws", None)
        if ws is not None:
            self._remove(ws)

    def close(self):
        """Remove the cached reference checkouts."""
        for ws in self._refs.values():
            self._remove(ws)
        self._refs.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def runner_for(cfg):
    if cfg["vul4j"]["runner"] == "mock":
        return MockVul4J(synthworld.world_for(cfg))
    return ContainerVul4J(cfg)

