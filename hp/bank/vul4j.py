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
  container image. Its command lines and the files it reads were checked
  against the Vul4J source (see the comment above the class); the first live
  run (`study.py vul4j-check`) checks them against the pinned image. Failure
  signatures are read from the JUnit XML reports, because Vul4J's own test
  summary does not carry the stack frame (risk R1 in PLAN.md).

A failure signature is (exception type, whitespace-normalised message, first
stack frame inside the PoV test class); see PLAN.md section 10 item 14.
"""

import json
import pathlib
import shutil
import re
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from .. import synthworld
from . import difftools


class ApplyError(RuntimeError):
    pass


class BuildError(RuntimeError):
    pass


class InfraError(RuntimeError):
    """The host, Docker or the image failed, not the code under test. Never caught
    by the stages: nothing is logged for the item and a resumed run retries it."""


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
                        if line.startswith("at ") and cls and (
                                line[3:].startswith(cls + ".") or line[3:].startswith(cls + "$")):
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
# container (real Vul4J)
# ---------------------------------------------------------------------------
#
# Checked against the Vul4J source (github.com/tuhh-softsec/vul4j, main,
# commit 376411d, 2026-06-15), not yet against a running image:
#
# * `vul4j checkout --id ID -d DIR` copies the project from the image's own
#   git repository (the Dockerfile fetches every VUL4J-* branch at build time).
#   It writes DIR/VUL4J/vulnerability_info.json and the changed source files of
#   both versions to DIR/VUL4J/{vulnerable,human_patch}/ (with a paths.json
#   each), and leaves DIR at the vulnerable version.
# * `vul4j apply -d DIR -v human_patch` switches DIR to the human fix (and
#   applies the benchmark's own build patches).
# * `vul4j compile -d DIR` runs `compile_cmd` (often `mvn ... install`) and exits
#   non-zero when the build fails.
# * `vul4j test -d DIR -b all|povs` runs `test_all_cmd` or the PoV-only
#   `test_cmd + cmd_options`. It always exits 0; results are the JUnit XML
#   reports under target/surefire-reports, target/failsafe-reports or
#   build/test-results anywhere in DIR. It deletes old reports before it runs.
#   Note `-b all` does NOT append `cmd_options` (the -D...skip flags); the runner
#   therefore rewrites `test_all_cmd` in the checkout's vulnerability_info.json
#   (cmd_options appended, a missing Maven `test` goal added) and records the rule.
# * `vul4j info` logs to stderr, so metadata is read from a checkout instead.
#
# One container per checkout: checkout, apply, compile and every test run of a
# handle execute in the SAME container (`docker exec`), because `compile_cmd`
# installs modules into the container's Maven repository and the tests of a
# multi-module project read them from there. A fresh container per command would
# test against the image's stale artefacts.
#
# Model diffs are applied with `difftools.apply`, the function the review stage
# uses to show reviewers the patched code, so "applies" means the same thing
# everywhere. Infrastructure failures (Docker, out of memory, a timed-out build)
# raise InfraError: nothing is logged and a resumed run retries the item.

REPORT_DIRS = ("target/surefire-reports", "target/failsafe-reports", "build/test-results")
_VUL4J_DIR = "VUL4J"
#: exit codes that mean the host, Docker or the image failed, not the project
INFRA_EXIT = {125: "docker error", 126: "command cannot run", 127: "command not found",
              137: "killed (out of memory or SIGKILL)", 143: "terminated"}
TEST_ALL_RULE = "cmd_options appended to test_all_cmd; Maven 'test' goal added if missing"

_PATCH_INFO = r"""
import json, sys
p = '/ws/src/VUL4J/vulnerability_info.json'
d = json.load(open(p))
cmd = (d.get('test_all_cmd') or '').strip()
opts = (d.get('cmd_options') or '').strip()
if d.get('build_system') == 'Maven' and cmd.startswith('mvn') and not any(
        g in cmd.split() for g in ('test', 'verify', 'install', 'package')):
    cmd += ' test'
if opts and opts not in cmd:
    cmd += ' ' + opts
d['test_all_cmd'] = cmd
json.dump(d, open(p, 'w'), indent=2)
"""


def effective_test_all_cmd(info):
    """The `test_all_cmd` the runner makes Vul4J use (same rule as _PATCH_INFO)."""
    cmd = (info.get("test_all_cmd") or "").strip()
    opts = (info.get("cmd_options") or "").strip()
    if info.get("build_system") == "Maven" and cmd.startswith("mvn") and not any(
            g in cmd.split() for g in ("test", "verify", "install", "package")):
        cmd += " test"
    if opts and opts not in cmd:
        cmd += " " + opts
    return cmd


def find_reports(src):
    """Every JUnit XML report under a checkout, in a stable order."""
    src = pathlib.Path(src)
    if not src.is_dir():
        return []
    out = []
    for p in src.rglob("TEST-*.xml"):
        rel = p.relative_to(src).as_posix()
        if any(f"/{d}/" in f"/{rel}" for d in REPORT_DIRS):
            out.append(p)
    return sorted(out)


def _pov_class(test):
    """'pkg.Cls$Inner#method[param]' -> 'pkg.Cls'."""
    return test.split("#")[0].split("$")[0]


def _lines(text):
    """Split on '\\n' only (keeping it), as difftools.apply does; str.splitlines
    would also split on form feeds and other separators found in source files."""
    if not text:
        return []
    parts = text.split("\n")
    out = [p + "\n" for p in parts[:-1]]
    if parts[-1]:
        out.append(parts[-1])
    return out


def unified_diff(before, after):
    """{path: text} x {path: text} -> one unified diff with a/ b/ prefixes."""
    import difflib

    parts = []
    for path in sorted(set(before) | set(after)):
        a = before.get(path)
        b = after.get(path)
        if a == b:
            continue
        lines = difflib.unified_diff(
            _lines(a or ""), _lines(b or ""),
            fromfile=f"a/{path}" if a is not None else "/dev/null",
            tofile=f"b/{path}" if b is not None else "/dev/null", n=3)
        parts.append("".join(l if l.endswith("\n") else l + "\n" for l in lines))
    return "".join(parts)


class ContainerVul4J:
    """Vul4J CLI inside the pinned container image.

    The image is referenced as `image@image_digest` (a registry digest) or, for a
    locally built image (`vul4j.pin_kind = "image_id"`), by its image id. The
    `run` callable is injectable so the command lines and the parsing are
    unit-testable.
    """

    name = "container"

    def __init__(self, cfg, run=None):
        v = cfg["vul4j"]
        if v.get("pin_kind", "repo_digest") == "image_id":
            self.image = v["image_digest"]
        else:
            self.image = f"{v['image']}@{v['image_digest']}"
        self.cli = v.get("cli", "vul4j")
        self.workdir = pathlib.Path(v.get("workdir", "/tmp/vul4j"))
        self.platform = v.get("platform", "linux/amd64")
        self.network = v.get("network", "none")
        self.docker = v.get("docker", "docker")
        self.cpus = v.get("cpus_per_container")
        self.memory = v.get("memory_per_container")
        self.timeouts = {
            "checkout": v.get("checkout_timeout_s", 1800),
            "compile": v.get("compile_timeout_s", 3600),
            "test": v.get("test_timeout_s", 7200),
            "misc": 600,
        }
        self.run = run or self._run
        self._meta_cache = {}   # cve -> metadata read from a reference checkout
        self._refs = {}         # (cve, version) -> read-only checkout kept for file reads
        self._repro = None      # reproduction rows, for the PoV failure output (leak scan)
        self._lock = threading.Lock()   # guards the caches when stages run with jobs > 1
        self._key_locks = {}
        self._live = set()      # running containers (killed on interrupt / close)
        self._stopping = threading.Event()
        try:
            from .. import logs, study_config

            self._repro_path = study_config.runs_dir(cfg) / logs.FILES["reproduction"]
        except (KeyError, TypeError):
            self._repro_path = None

    def describe(self):
        return {"runner": self.name, "image_digest": self.image, "platform": self.platform,
                "network": self.network, "test_all_rule": TEST_ALL_RULE}

    def provenance(self, commit=None):
        """What the image was built from: whether /vul4j contains `commit`, whether
        the build's warm-up reproduction ran, and which CVEs it failed to reproduce."""
        script = ("git -C /vul4j log -1 --format=%H; "
                  + (f"git -C /vul4j merge-base --is-ancestor {commit} HEAD && echo COMMIT_OK; "
                     if commit else "")
                  + "test -f /root/vul4j_data/reproduction.txt && echo WARMUP_OK; "
                  "echo FAILED:; cat /root/vul4j_data/failed_vulnerabilities.txt 2>/dev/null; true")
        code, out, err = self.run([self.docker, "run", "--rm", "--platform", self.platform,
                                   "--network", "none", self.image, "sh", "-c", script],
                                  timeout=self.timeouts["misc"])
        if code:
            raise InfraError(f"cannot inspect the image ({code}): {(err or out).strip()[-300:]}")
        lines = out.splitlines()
        failed = lines[lines.index("FAILED:") + 1:] if "FAILED:" in lines else []
        return {"head": lines[0] if lines else None,
                "commit_ok": None if not commit else "COMMIT_OK" in lines,
                "warmup_ran": "WARMUP_OK" in lines,
                "warmup_failed": [f.strip() for f in failed if f.strip()]}

    # -- docker -------------------------------------------------------------

    @staticmethod
    def _run(argv, timeout=None):
        try:
            # own session: a Ctrl-C in the terminal must not reach the container
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               start_new_session=True)
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout} s (host)"
        return p.returncode, p.stdout, p.stderr

    def _start(self, ws):
        name = f"hp-{uuid.uuid4().hex[:12]}"
        argv = [self.docker, "run", "-d", "--rm", "--init", "--name", name,
                "--platform", self.platform, "--network", self.network, "-v", f"{ws}:/ws"]
        if self.cpus:
            argv += ["--cpus", str(self.cpus)]
        if self.memory:
            argv += ["--memory", str(self.memory)]
        argv += [self.image, "sleep", "infinity"]
        if self._stopping.is_set():
            raise InfraError("interrupted")
        code, out, err = self.run(argv, timeout=self.timeouts["misc"])
        if code:
            raise InfraError(f"container did not start ({code}): {(err or out).strip()[-300:]}")
        with self._lock:
            self._live.add(name)
        return name

    def _stop(self, name):
        self.run([self.docker, "rm", "-f", name], timeout=self.timeouts["misc"])
        with self._lock:
            self._live.discard(name)

    def _exec(self, name, kind, *cmd):
        """Run `cmd` in the container under an in-container timeout. Returns
        (code, out, err); a host-side timeout or an interrupt raises InfraError."""
        if self._stopping.is_set():
            raise InfraError("interrupted")
        t = self.timeouts[kind]
        argv = [self.docker, "exec", name, "timeout", "-k", "30", str(t), *cmd]
        code, out, err = self.run(argv, timeout=t + 120)
        if self._stopping.is_set():
            raise InfraError("interrupted")
        if code == 124 and "(host)" in (err or ""):
            self._stop(name)
            raise InfraError(f"docker exec did not return within {t + 120} s")
        return code, out, err

    def interrupt(self):
        """Stop everything now (Ctrl-C): kill the running containers; in-flight work
        then raises InfraError and is not logged."""
        self._stopping.set()
        with self._lock:
            live = list(self._live)
        for name in live:
            self._stop(name)

    def _new_ws(self, cve, tag):
        ws = self.workdir / f"{cve}-{tag}-{uuid.uuid4().hex[:8]}"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def _remove(self, ws, name=None):
        """Delete a workspace. Files written inside the container are root-owned, so
        the contents are removed from inside a container first."""
        ws = pathlib.Path(ws)
        if name is not None:
            try:
                self.run([self.docker, "exec", name, "sh", "-c", "rm -rf /ws/* /ws/.[!.]*"],
                         timeout=self.timeouts["misc"])
            finally:
                self._stop(name)
        elif ws.exists():
            self.run([self.docker, "run", "--rm", "--platform", self.platform, "--network", "none",
                      "-v", f"{ws}:/ws", self.image, "sh", "-c", "rm -rf /ws/* /ws/.[!.]*"],
                     timeout=self.timeouts["misc"])
        shutil.rmtree(ws, ignore_errors=True)

    # -- checkouts ------------------------------------------------------------

    def _checkout(self, name, cve, version):
        code, out, err = self._exec(name, "checkout", self.cli, "checkout", "--id", cve,
                                    "-d", "/ws/src")
        if code:
            raise InfraError(f"checkout of {cve} failed ({code}): {(err or out).strip()[-500:]}")
        if version == "fixed":
            code, out, err = self._exec(name, "misc", self.cli, "apply", "-d", "/ws/src",
                                        "-v", "human_patch")
            if code in INFRA_EXIT:
                raise InfraError(f"human patch: {INFRA_EXIT[code]}")
            if code:
                raise ApplyError(f"human patch failed: {(err or out).strip()[-500:]}")

    def _key_lock(self, key):
        with self._lock:
            return self._key_locks.setdefault(key, threading.Lock())

    def _reference(self, cve, version):
        """Source-only checkout reused for metadata and file reads (no build, no tests).
        Made once per (CVE, version), also when several threads ask at once."""
        key = (cve, version)
        with self._key_lock(("ref",) + key):
            if key not in self._refs:
                ws = self._new_ws(cve, f"{version}-ref")
                name = self._start(ws)
                try:
                    self._checkout(name, cve, version)
                except BaseException:
                    self._remove(ws, name)
                    raise
                self._stop(name)
                self._refs[key] = ws
        return self._refs[key]

    # -- metadata -------------------------------------------------------------

    def _meta(self, cve):
        with self._key_lock(("meta", cve)):
            if cve not in self._meta_cache:
                self._meta_cache[cve] = self._read_meta(cve)
        return self._meta_cache[cve]

    def _read_meta(self, cve):
        src = self._reference(cve, "vulnerable") / "src"
        vdir = src / _VUL4J_DIR
        info = json.loads((vdir / "vulnerability_info.json").read_text())
        hp_paths = json.loads((vdir / "human_patch" / "paths.json").read_text())
        vu_paths = json.loads((vdir / "vulnerable" / "paths.json").read_text())
        before = {vu_paths[b]: (vdir / "vulnerable" / b).read_text(errors="replace") for b in vu_paths}
        after = {hp_paths[b]: (vdir / "human_patch" / b).read_text(errors="replace") for b in hp_paths}
        url = info.get("project_url") or ""
        slug = url.split("github.com/")[-1].strip("/") if "github.com/" in url else None
        tokens = sorted({t.lower() for t in re.split(r"[/_.\-]+", slug or "") if len(t) >= 3})
        return {
            "info": info,
            "human_files": sorted(after),
            "human_patch": unified_diff(before, after),
            "slug": slug,
            "commits": [h for h in [info.get("fixing_commit_hash")] if h],
            "failing_tests": [t for t in info.get("failing_tests") or [] if t],
            "tokens": tokens,
            "test_all_cmd": effective_test_all_cmd(info),
        }

    def human_files(self, cve):
        return list(self._meta(cve)["human_files"])

    def human_patch(self, cve):
        return self._meta(cve)["human_patch"]

    def pov_tests(self, cve):
        return list(self._meta(cve)["failing_tests"])

    def pov_test_files(self, cve):
        classes = {_pov_class(t) for t in self.pov_tests(cve)}
        tails = {c.replace(".", "/") + ".java" for c in classes}
        return [f for f in self.list_files(cve) if any(f.endswith("/" + t) or f == t for t in tails)]

    def module_tests(self, cve):
        return None  # Vul4J runs a module's tests only as part of `test_all_cmd`

    def _pov_output(self, cve):
        with self._lock:
            if self._repro is None:
                self._repro = {}
                if self._repro_path is not None and self._repro_path.is_file():
                    for line in self._repro_path.read_text().splitlines():
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        if row.get("kind") == "reproduction":
                            self._repro[row["cve"]] = row
            sig = (self._repro.get(cve) or {}).get("signature") or {}
        return sorted({s.get("message") for s in sig.values() if s and s.get("message")})

    def metadata(self, cve):
        m = self._meta(cve)
        return {"cve": cve, "cluster": m["slug"], "commit_hashes": m["commits"],
                "pov_tests": m["failing_tests"], "pov_output": self._pov_output(cve),
                "allowed_project_tokens": m["tokens"]}

    # -- build and test -------------------------------------------------------

    def _apply_diff(self, cve, ws, name, diff):
        """Apply a model-written diff exactly as the review stage does, then copy the
        patched files into the checkout from inside the container. Files are read
        and written byte-faithfully (surrogateescape), so non-UTF-8 bytes survive."""
        try:
            parsed = difftools.parse(diff)
        except difftools.DiffError as exc:
            raise ApplyError(str(exc))
        paths = sorted({p for old, new, _ in parsed for p in (old, new) if p})
        for p in paths:
            if p.startswith("/") or ".." in pathlib.PurePosixPath(p).parts or \
                    pathlib.PurePosixPath(p).parts[:1] == (_VUL4J_DIR,):
                raise ApplyError(f"path outside the project: {p}")
        root = self._reference(cve, "vulnerable") / "src"
        base = {p: (root / p).read_text(errors="surrogateescape") for p in paths
                if (root / p).is_file()}
        try:
            patched = difftools.apply(base, diff)
        except difftools.DiffError as exc:
            raise ApplyError(str(exc))
        stage = ws / "patched"
        removed = [p for p in base if p not in patched]
        for p, text in patched.items():
            if base.get(p) == text:
                continue
            f = stage / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, errors="surrogateescape")
        script = "set -e; if [ -d /ws/patched ]; then cp -r /ws/patched/. /ws/src/; fi"
        for p in removed:
            script += f"; rm -f '/ws/src/{p}'"
        code, out, err = self._exec(name, "misc", "sh", "-c", script)
        if code:
            raise InfraError(f"copying the patched files failed ({code}): {(err or out).strip()[-300:]}")

    def prepare(self, cve, version="vulnerable", diff=None):
        """Fresh workspace and container per call; removed by `release` (or here, if
        preparing fails)."""
        ws = self._new_ws(cve, version if diff is None else "patched")
        name = None
        try:
            name = self._start(ws)
            self._checkout(name, cve, version)
            code, out, err = self._exec(name, "misc", "python3", "-c", _PATCH_INFO)
            if code:
                raise InfraError(f"rewriting test_all_cmd failed: {(err or out).strip()[-300:]}")
            if diff is not None:
                self._apply_diff(cve, ws, name, diff)
            code, out, err = self._exec(name, "compile", self.cli, "compile", "-d", "/ws/src")
            if code == 124 or code in INFRA_EXIT:
                raise InfraError(f"compile: {INFRA_EXIT.get(code, 'timeout')} ({code})")
            if code:
                log = ws / "src" / _VUL4J_DIR / "compile.log"
                tail = log.read_text(errors="replace")[-1500:] if log.is_file() else (err or out)
                raise BuildError(tail.strip())
        except BaseException:
            self._remove(ws, name)
            raise
        return Handle(cve, version if diff is None else "patched", diff, ws=ws, container=name,
                      category=version if diff is None else None)

    def run_tests(self, handle, scope="full", tests=None):
        """One test run in the handle's container, no rebuild. `tests` limited to PoV
        tests runs Vul4J's PoV-only command; any other selection runs the full
        command and filters the results. A timed-out or killed run is incomplete."""
        ws, name = handle.extra["ws"], handle.extra["container"]
        handle.runs += 1
        pov = self.pov_tests(handle.cve)
        batch = "povs" if tests is not None and set(tests) and set(tests) <= set(pov) else "all"
        t0 = time.time()
        code, out, err = self._exec(name, "test", self.cli, "test", "-d", "/ws/src", "-b", batch)
        wall = time.time() - t0
        if code in (125, 126, 127):
            raise InfraError(f"test: {INFRA_EXIT[code]} ({code})")
        reports = find_reports(ws / "src")
        if code or not reports:
            why = "timeout" if code == 124 else INFRA_EXIT.get(code) or "no test reports"
            return SuiteRun(False, {}, wall, scope,
                            error=f"{why}: " + (err or out or "").strip()[-2000:])
        results = parse_surefire([p.read_text(errors="replace") for p in reports])
        # report names that differ from the dataset's PoV names only in case
        lower = {t.lower(): t for t in pov}
        for k in list(results):
            if k not in pov and k.lower() in lower:
                r = results.pop(k)
                results[lower[k.lower()]] = TestResult(lower[k.lower()], r.outcome, r.signature)
        if tests is not None:
            keep = set(tests)
            results = {k: v for k, v in results.items() if k in keep}
        return SuiteRun(True, results, wall, scope)

    # -- files ----------------------------------------------------------------

    def read_files(self, cve, paths, version="vulnerable"):
        root = self._reference(cve, version) / "src"
        return {p: (root / p).read_text(errors="replace") for p in paths if (root / p).is_file()}

    def list_files(self, cve, version="vulnerable"):
        root = self._reference(cve, version) / "src"
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*.java")
                      if p.relative_to(root).parts[0] != _VUL4J_DIR)

    def patched_files(self, handle, paths):
        root = handle.extra["ws"] / "src"
        return {p: (root / p).read_text(errors="replace") for p in paths if (root / p).is_file()}

    def release(self, handle):
        ws = handle.extra.pop("ws", None)
        name = handle.extra.pop("container", None)
        if ws is not None:
            self._remove(ws, name)

    def close(self):
        """Kill running containers and remove the cached reference checkouts."""
        with self._lock:
            live = list(self._live)
        for name in live:
            self._stop(name)
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

