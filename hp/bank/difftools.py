"""Unified diffs: extract, parse, apply, normalise, measure.

Pure functions, standard library only. Used to build post-patch file content
for review inputs (the mock runner also applies patches with it), to
deduplicate near-misses (whitespace-normalised, section 10), to measure the
V -> F correction (changed lines, added comment lines, section 9) and to
compute similarity to the human patch (section 5.6).
"""

import difflib
import hashlib
import re


class DiffError(ValueError):
    pass


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def extract_diff(text):
    """The unified diff in an LLM response, or None.

    First fenced ```diff block; else the text from the first '--- ' / 'diff --git'
    line, if it also has a '+++ ' header and a hunk.
    """
    if not text:
        return None
    m = re.search(r"```(?:diff|patch)?[ \t]*\n(.*?)```", text, re.S)
    if m and "@@" in m.group(1) and "+++ " in m.group(1):
        body = m.group(1)
        return body if body.endswith("\n") else body + "\n"
    lines = text.splitlines(True)
    for i, line in enumerate(lines):
        if line.startswith("--- ") or line.startswith("diff --git"):
            body = "".join(lines[i:])
            if "+++ " in body and "@@" in body:
                return body if body.endswith("\n") else body + "\n"
            break
    return None


def _strip_prefix(p):
    p = p.strip().split("\t")[0]
    if p == "/dev/null":
        return None
    return p[2:] if p[:2] in ("a/", "b/") else p


def parse(diff_text):
    """[(old_path, new_path, [hunk, ...])], hunk = (old_start, new_start, [(tag, text)])."""
    files = []
    cur = None
    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            cur = [_strip_prefix(line[4:]), _strip_prefix(lines[i + 1][4:]), []]
            files.append(cur)
            i += 2
            continue
        m = _HUNK.match(line)
        if m:
            if cur is None:
                raise DiffError("hunk before any file header")
            old_start, new_start = int(m.group(1)), int(m.group(3))
            old_len = int(m.group(2)) if m.group(2) is not None else 1
            new_len = int(m.group(4)) if m.group(4) is not None else 1
            body = []
            i += 1
            seen_old = seen_new = 0
            while i < len(lines) and (seen_old < old_len or seen_new < new_len):
                l2 = lines[i]
                if l2.startswith("\\"):
                    i += 1
                    continue
                tag, text = (l2[:1] or " "), l2[1:]
                if tag not in " +-":
                    raise DiffError(f"bad hunk line: {l2!r}")
                body.append((tag, text))
                if tag in " -":
                    seen_old += 1
                if tag in " +":
                    seen_new += 1
                i += 1
            if seen_old != old_len or seen_new != new_len:
                raise DiffError("hunk shorter than its header says")
            cur[2].append((old_start, new_start, body))
            continue
        i += 1
    if not files or not any(f[2] for f in files):
        raise DiffError("no file patch with hunks found")
    return files


def apply(files, diff_text, fuzz=60):
    """Apply a unified diff to {path: text}. Returns the updated copy. Exact context."""
    out = dict(files)
    for old_path, new_path, hunks in parse(diff_text):
        src_path = old_path or new_path
        if old_path is None:
            src = []
            had_nl = True
        else:
            if old_path not in out:
                raise DiffError(f"file not found: {old_path}")
            text = out[old_path]
            had_nl = text.endswith("\n")
            src = text.split("\n")
            if had_nl:
                src = src[:-1]
        result, pos, offset = [], 0, 0
        for old_start, _, body in hunks:
            old = [t for tag, t in body if tag in " -"]
            new = [t for tag, t in body if tag in " +"]
            want = max(0, old_start - 1 + offset) if old else max(0, old_start + offset)
            at = None
            for delta in sorted(range(-fuzz, fuzz + 1), key=abs):
                k = want + delta
                if k < pos or k + len(old) > len(src):
                    continue
                if src[k : k + len(old)] == old:
                    at = k
                    break
            if at is None:
                raise DiffError(f"hunk at line {old_start} does not apply to {src_path}")
            result += src[pos:at] + new
            pos = at + len(old)
            offset = at - (old_start - 1) if old else offset
        result += src[pos:]
        if new_path is None:
            out.pop(old_path, None)
            continue
        if old_path and old_path != new_path:
            out.pop(old_path, None)
        out[new_path] = "\n".join(result) + ("\n" if had_nl else "")
    return out


def changed_lines(diff_text):
    """{new_path: set of 1-based line numbers in the new file touched by the diff}."""
    out = {}
    for _, new_path, hunks in parse(diff_text):
        if new_path is None:
            continue
        s = out.setdefault(new_path, set())
        for _, new_start, body in hunks:
            n = new_start
            for tag, _ in body:
                if tag == "+":
                    s.add(n)
                    n += 1
                elif tag == " ":
                    n += 1
                else:  # a deletion touches the line now at this position
                    s.add(max(1, n))
    return out


def for_review(diff_text):
    """The diff as reviewers see it: headers and hunks only.

    Drops `diff --git`, `index <hash>..<hash>`, mail headers and anything else
    that is not a file header or hunk line, so no blob or commit hash reaches
    a prompt.
    """
    keep = []
    for line in diff_text.splitlines():
        if line.startswith(("--- ", "+++ ", "@@")) or line[:1] in (" ", "+", "-", "\\"):
            if line.startswith(("--- ", "+++ ")):
                keep.append(line.split("\t")[0])
            else:
                keep.append(line)
    return "\n".join(keep) + "\n"


def normalise(diff_text):
    """Whitespace-normalised change content, for deduplication (section 10)."""
    out = []
    for _, new_path, hunks in parse(diff_text):
        out.append(f"F {new_path}")
        for _, _, body in hunks:
            for tag, t in body:
                if tag == " ":
                    continue
                t = " ".join(t.split())
                if t:
                    out.append(tag + t)
    return "\n".join(out)


def norm_sha(diff_text):
    return hashlib.sha256(normalise(diff_text).encode()).hexdigest()


def sha(text):
    return hashlib.sha256((text or "").encode()).hexdigest()


def line_delta(before, after):
    """(added, removed) line counts between two texts."""
    added = removed = 0
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return added, removed


_COMMENT = re.compile(r"^\s*(//|/\*|\*|\*/)")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def is_comment_line(line):
    """A Java line that is, or ends in, a comment (string literals ignored)."""
    code = _STRING.sub('""', line)
    return bool(_COMMENT.match(code)) or "//" in code or "/*" in code


def added_comment_lines(before, after):
    """Added lines that carry a Java comment (//, /* */, Javadoc): section 9 rubric."""
    n = 0
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith("+ ") and is_comment_line(line[2:]):
            n += 1
    return n


def diff_size(diff_text):
    """Changed lines (+ and -) in a diff: the patch-size measure for RQ3 strata."""
    n = 0
    for _, _, hunks in parse(diff_text):
        for _, _, body in hunks:
            n += sum(1 for tag, _ in body if tag in "+-")
    return n


_TOKEN = re.compile(r"\w+|[^\w\s]")


def added_tokens(diff_text):
    toks = []
    for _, _, hunks in parse(diff_text):
        for _, _, body in hunks:
            for tag, t in body:
                if tag == "+":
                    toks += _TOKEN.findall(t)
    return toks


def similarity(diff_a, diff_b):
    """Token-level similarity of the added code of two diffs (section 5.6)."""
    a, b = added_tokens(diff_a), added_tokens(diff_b)
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(a=a, b=b, autojunk=False).ratio()
