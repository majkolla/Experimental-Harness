"""e0: the enclosing method +-50 lines, the cap, overflow (section 11.1, Q11)."""

import inspect

from hp import synthworld
from hp.bank import difftools
from hp.review import input as I
from hp.tokens import proxy_tokens

TEMPLATE = "{{PR_DESCRIPTION}}\n```diff\n{{DIFF}}\n```\n{{CONTEXT}}\n{{EVIDENCE_SECTION}}end\n"
MAIN = synthworld._main_java("org.example.p1", "Handler7")
PATH = "src/main/java/org/example/p1/Handler7.java"


def _diff(lines_after_trim):
    lines = MAIN.split("\n")
    i = lines.index(synthworld.TRIM_LINE)
    after = "\n".join(lines[: i + 1] + lines_after_trim + lines[i + 1 :])
    return synthworld.unified(PATH, MAIN, after), after


def test_the_builder_takes_reviewer_visible_material_only():
    params = list(inspect.signature(I.build_review_input).parameters)
    assert params == ["template", "advisory_summary", "diff_text", "post_files", "cap_tokens",
                      "context_lines", "evidence"]


def test_context_is_the_enclosing_method_plus_fifty_lines():
    diff, after = _diff(["        value = value.strip();"])
    methods = {m[0]: m for m in I.java_methods(after)}
    _, s, e = methods["process"]
    ranges = I.context_ranges({PATH: after}, difftools.changed_lines(diff), 50)
    n = len(after.split("\n"))
    assert ranges[PATH] == [(max(1, s - 50), min(n, e + 50), True)]
    res = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, 8000, 50)
    assert res["status"] == "ok" and res["context_method"] == "enclosing_method"
    assert not res["truncated_context"]


def test_a_change_outside_any_method_uses_the_hunk_window():
    before = "\n".join(f"line {i}" for i in range(1, 201)) + "\n"
    after = before.replace("line 100\n", "line 100\nint added = 1;\n")
    diff = synthworld.unified("F.java", before, after)
    res = I.build_review_input(TEMPLATE, "s", diff, {"F.java": after}, 8000, 50)
    assert res["context_method"] == "hunk_window"
    assert "line 51\n" in res["text"] and "line 50\n" not in res["text"]


def test_context_is_trimmed_symmetrically_and_the_diff_never():
    diff, after = _diff(["        value = value.strip();"])
    full = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, 8000, 50)
    cap = full["proxy_tokens"] - 60
    res = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, cap, 50)
    assert res["status"] == "ok" and res["truncated_context"] and res["proxy_tokens"] <= cap
    assert difftools.for_review(diff).rstrip("\n") in res["text"]
    k = res["trimmed_lines_per_side"]
    (s, e, _), = I.context_ranges({PATH: after}, difftools.changed_lines(diff), 50)[PATH]
    assert f"(lines {s + k}-{e - k})" in res["text"]


def test_a_diff_over_the_cap_is_an_overflow():
    diff, after = _diff([f"        int v{i} = {i};" for i in range(400)])
    res = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, 1000, 50)
    assert res["status"] == "review_input_overflow" and res["text"] is None
    assert proxy_tokens(difftools.for_review(diff)) > 1000


def test_identical_material_gives_an_identical_input():
    diff, after = _diff(["        value = value.strip();"])
    a = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, 8000, 50)
    b = I.build_review_input(TEMPLATE, "summary", diff, {PATH: after}, 8000, 50)
    assert a["sha256"] == b["sha256"]


def test_java_method_scanner_skips_control_blocks_lambdas_and_strings():
    src = """class A {
  static { init(); }
  @Override
  public void run() throws IOException {
    list.forEach(v -> { use(v); });
    if (a) { b(); } else { c(); }
    String s = "{ not a brace";
  }
  A(int x) { this.x = x; }
}"""
    assert I.java_methods(src) == [("run", 3, 8), ("A", 9, 9)]
