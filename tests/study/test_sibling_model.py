"""sibling.method = openweight_model: an open model drafts F from V's post-patch code;
F is returned as a complete patch against the vulnerable version."""

import pytest

from hp import providers, schema
from hp.bank import difftools, generate, sibling

PATH = "src/main/java/p/H.java"
VULN = "class H {\n  String clean(String s) {\n    return s;\n  }\n}\n"
V_DIFF = (f"--- a/{PATH}\n+++ b/{PATH}\n@@ -2,3 +2,3 @@\n   String clean(String s) {{\n"
          "-    return s;\n+    return s.trim();\n   }\n")
DRAFT = (f"```diff\n--- a/{PATH}\n+++ b/{PATH}\n@@ -3 +3 @@\n"
         "-    return s.trim();\n+    return s.trim().replace(\"<\", \"\");\n```\n")


class Runner:
    def read_files(self, cve, paths, version="vulnerable"):
        return {p: VULN for p in paths if p == PATH}

    def metadata(self, cve):
        return {"cve": cve, "cluster": "acme/widgets", "commit_hashes": [], "pov_tests": [],
                "pov_output": []}


CFG = {"sibling": {"model_ref": "Z"},
       "models": {"Z": {"provider": "openweight", "model": "open-z", "tier": "open"}},
       "_prompts": {"sibling": {"text": "{{ADVISORY}}\n{{FILES}}"}},
       "sampling": {"gen_temperature": 0.7, "gen_top_p": 1.0},
       "caps": {"gen_output_tokens": 100}, "timeouts_s": {"gen_timeout_s": 5}, "max_attempts": 2}


@pytest.fixture
def fake(monkeypatch):
    seen = {}
    monkeypatch.setattr(generate, "advisory_for",
                        lambda cfg, cve: {"cwe": "CWE-79", "summary": "script tags pass through"})

    def call(spec, prompt, cfg, contract=None, **kw):
        seen.update(spec=spec, prompt=prompt, cfg=cfg)
        return [{"status": schema.OK, "text": seen.get("reply", DRAFT), "in_tokens": 9,
                 "out_tokens": 3}]

    monkeypatch.setattr(providers, "call_with_retries", call)
    return seen


def test_the_draft_becomes_a_patch_against_the_vulnerable_version(fake):
    f_diff, draft = sibling.model_author(CFG, Runner(), "VUL4J-1", V_DIFF)
    assert draft["model_ref"] == "Z" and draft["status"] == schema.OK
    post = difftools.apply({PATH: VULN}, f_diff)[PATH]
    assert 'return s.trim().replace("<", "");' in post
    assert "return s.trim();" in fake["prompt"] and "script tags pass through" in fake["prompt"]
    assert "return s;" not in fake["prompt"]          # the model sees V, not the original
    assert fake["spec"]["_ref"] == "Z" and fake["cfg"]["max_tokens"] == 100


def test_a_draft_that_does_not_apply_is_reported_not_repaired(fake):
    fake["reply"] = DRAFT.replace("return s.trim();", "return nothing;")
    f_diff, draft = sibling.model_author(CFG, Runner(), "VUL4J-1", V_DIFF)
    assert f_diff is None and "does not apply" in draft["error"]
    fake["reply"] = "I cannot help with that."
    f_diff, draft = sibling.model_author(CFG, Runner(), "VUL4J-1", V_DIFF)
    assert f_diff is None and draft["error"] == "no unified diff in the response"


def test_a_failed_call_is_retried_later_and_a_leak_is_invalid(fake, monkeypatch):
    def failing(spec, prompt, cfg, contract=None, **kw):
        return [{"status": schema.TIMEOUT if hasattr(schema, "TIMEOUT") else "timeout",
                 "text": None}]

    monkeypatch.setattr(providers, "call_with_retries", failing)
    f_diff, draft = sibling.model_author(CFG, Runner(), "VUL4J-1", V_DIFF)
    assert f_diff is None and draft["retry"] is True

    class Leaky(Runner):
        def metadata(self, cve):
            return {**super().metadata(cve), "pov_tests": ["p.HTest#clean"]}

    f_diff, draft = sibling.model_author(CFG, Leaky(), "VUL4J-1", V_DIFF)
    assert f_diff is None and draft["status"] == "leak" and "retry" not in draft
