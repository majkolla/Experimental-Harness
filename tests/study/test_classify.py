"""Stage 2 classification (section 8, Q14, Q19), against a scripted runner."""

import pytest

from hp.bank import classify
from hp.bank.vul4j import ApplyError, BuildError, Handle, SuiteRun, TestResult

ORIGINAL = {"type": "java.lang.AssertionError", "message": "payload accepted", "frame": "T.pov(T.java)"}
OTHER = {"type": "java.lang.NoSuchMethodError", "message": "process(String)", "frame": "T.pov(T.java)"}
REPRO = {"ordinary_tests": ["T#a", "T#b"], "pov_tests": ["T#pov"], "signature": {"T#pov": ORIGINAL}}
DIFF = "--- a/x\n+++ b/x\n@@ -1,1 +1,2 @@\n x\n+y\n"


class Scripted:
    """run k (0 = screening) -> {test: (outcome, signature)}; `prepare` may raise."""

    def __init__(self, script, raise_on_prepare=None):
        self.script = script
        self.raise_on_prepare = raise_on_prepare
        self.calls = []

    def human_patch(self, cve):
        return DIFF

    def module_tests(self, cve):
        return ["T#a"]

    def prepare(self, cve, version="vulnerable", diff=None):
        if self.raise_on_prepare:
            raise self.raise_on_prepare
        return Handle(cve, "patched", diff)

    def run_tests(self, handle, scope="full", tests=None):
        k = handle.runs
        handle.runs += 1
        self.calls.append((scope, tuple(tests) if tests else None))
        spec = self.script(k)
        names = ["T#a", "T#b", "T#pov"] if tests is None else tests
        res = {}
        for n in names:
            o, s = spec.get(n, ("pass", None))
            res[n] = TestResult(n, o, s)
        return SuiteRun(spec.get("_completed", True), res, 1.0, scope)

    def release(self, handle):
        pass


GEN = {"status": "ok", "diff_text": DIFF, "cve": "C1"}


def _cls(runner, gen=GEN, scope="full"):
    return classify.classify(runner, gen, REPRO, reruns=10, scope=scope)


def test_near_miss_requires_the_original_signature_in_every_rerun():
    r = _cls(Scripted(lambda k: {"T#pov": ("fail", ORIGINAL)}))
    assert r["class"] == "near_miss" and r["signature_match"] is True


def test_a_pov_failure_with_a_different_signature_is_not_a_near_miss():
    """Section 18.4: the classifier rejects a PoV failure with a different signature."""
    r = _cls(Scripted(lambda k: {"T#pov": ("fail", OTHER)}))
    assert r["class"] == "indeterminate" and r["reason"] == "signature_mismatch"
    assert r["signature_match"] is False


def test_one_rerun_with_another_signature_is_enough_to_refuse():
    r = _cls(Scripted(lambda k: {"T#pov": ("fail", OTHER if k == 7 else ORIGINAL)}))
    assert r["class"] == "indeterminate"


def test_blocked_regression_and_inconsistent():
    assert _cls(Scripted(lambda k: {}))["class"] == "blocked"
    assert _cls(Scripted(lambda k: {"T#b": ("fail", OTHER)}))["class"] == "regression_fail"
    flip = Scripted(lambda k: {"T#pov": ("fail", ORIGINAL), "T#a": ("fail", OTHER) if k == 4 else ("pass", None)})
    r = _cls(flip)
    assert r["class"] == "indeterminate" and r["reason"] == "inconsistent"
    mixed = Scripted(lambda k: {"T#pov": ("pass", None) if k == 3 else ("fail", ORIGINAL)})
    assert _cls(mixed)["reason"] == "inconsistent"


def test_build_once_then_ten_clean_reruns():
    s = Scripted(lambda k: {"T#pov": ("fail", ORIGINAL)})
    _cls(s)
    assert len(s.calls) == 11  # screening + 10 reruns on one prepared handle


def test_apply_build_and_missing_diff():
    assert _cls(Scripted(lambda k: {}, ApplyError("no")))["class"] == "apply_fail"
    assert _cls(Scripted(lambda k: {}, BuildError("no")))["class"] == "build_fail"
    assert _cls(Scripted(lambda k: {}), {**GEN, "diff_text": None})["reason"] == "no_diff"


def test_context_overflow_and_unresolved_generation_are_indeterminate():
    r = _cls(Scripted(lambda k: {}), {"status": "request_error", "reason": "context_overflow", "cve": "C1"})
    assert (r["class"], r["reason"]) == ("indeterminate", "context_overflow")
    r = _cls(Scripted(lambda k: {}), {"status": "timeout", "reason": None, "cve": "C1"})
    assert (r["class"], r["reason"]) == ("indeterminate", "generation_timeout")


def test_module_fallback_runs_the_full_suite_once_then_pov_plus_module_tests():
    s = Scripted(lambda k: {"T#pov": ("fail", ORIGINAL)})
    r = _cls(s, scope="module_fallback")
    assert r["class"] == "near_miss" and r["scope"] == "module_fallback"
    assert s.calls[0] == ("full", None)
    assert all(c == ("module_fallback", ("T#pov", "T#a")) for c in s.calls[1:])


def test_incomplete_runs_are_indeterminate():
    s = Scripted(lambda k: {"_completed": k != 2, "T#pov": ("fail", ORIGINAL)})
    assert _cls(s)["reason"] == "incomplete"
