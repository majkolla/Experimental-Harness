"""Unified-diff utilities used for review input, dedup and the twin rubric."""

import pytest

from hp.bank import difftools as D

BEFORE = "a\nb\nc\nd\ne\nf\ng\n"
DIFF = """--- a/x.java
+++ b/x.java
@@ -2,3 +2,4 @@
 b
 c
+inserted
 d
"""


def test_apply_and_changed_lines():
    out = D.apply({"x.java": BEFORE}, DIFF)["x.java"]
    assert out == "a\nb\nc\ninserted\nd\ne\nf\ng\n"
    assert D.changed_lines(DIFF) == {"x.java": {4}}


def test_apply_tolerates_an_offset_but_not_wrong_context():
    shifted = "z\n" + BEFORE
    assert "inserted" in D.apply({"x.java": shifted}, DIFF)["x.java"]
    with pytest.raises(D.DiffError):
        D.apply({"x.java": "nothing\nhere\n"}, DIFF)


def test_extract_from_fenced_block_raw_text_or_nothing():
    assert D.extract_diff("Sure.\n```diff\n" + DIFF + "```\nDone.") == DIFF
    assert D.extract_diff("prose\n" + DIFF) == DIFF
    assert D.extract_diff("I cannot help with that.") is None


def test_dedup_ignores_whitespace_only_differences():
    other = DIFF.replace("+inserted", "+   inserted   ")
    assert D.norm_sha(DIFF) == D.norm_sha(other)
    assert D.norm_sha(DIFF) != D.norm_sha(DIFF.replace("inserted", "changed"))


def test_reviewers_never_see_blob_or_commit_hashes():
    raw = "diff --git a/x.java b/x.java\nindex 3f2310f..12ac4b6 100644\n" + DIFF
    out = D.for_review(raw)
    assert "3f2310f" not in out and "diff --git" not in out
    assert out.startswith("--- a/x.java")


def test_comment_lines_and_size():
    after = BEFORE.replace("c\n", "c\n// added note\nx = \"http://y\";\n")
    assert D.added_comment_lines(BEFORE, after) == 1
    assert D.line_delta(BEFORE, after) == (2, 0)
    assert D.diff_size(DIFF) == 1


def test_similarity_is_one_for_identical_added_code():
    assert D.similarity(DIFF, DIFF) == 1.0
    assert D.similarity(DIFF, DIFF.replace("inserted", "zzz qqq")) < 1.0


def test_crlf_files_take_lf_model_diffs_and_keep_their_line_endings():
    from hp.bank import difftools as D
    files = {"A.java": "class A {\r\n  int x = 1;\r\n}\r\n"}
    diff = "--- a/A.java\n+++ b/A.java\n@@ -2 +2 @@\n-  int x = 1;\n+  int x = 2;\n"
    assert D.apply(files, diff) == {"A.java": "class A {\r\n  int x = 2;\r\n}\r\n"}
