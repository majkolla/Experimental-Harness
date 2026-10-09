"""The base review input e0 (section 11.1, SPEC_ANSWERS Q11 and Q12).

e0 is identical for every reviewer and built the same way for V and F:

* a PR description from a fixed template ("This patch addresses the following
  reported issue: <advisory summary>");
* the unified diff, reduced to file headers and hunks (`difftools.for_review`:
  no `index <hash>` lines, no commit headers);
* for every changed line, the post-patch content of the enclosing Java method
  plus `caps.context_lines` (50) lines either side; overlapping ranges are
  merged. Where no enclosing method is found, the changed hunk +-50 lines is
  used and `context_method` records it.

Cap (Q11): the whole input must fit `caps.review_input_tokens` (8,000) on the
provider-independent proxy (UTF-8 bytes / 4). If it does not, context lines are
trimmed symmetrically from the outer edge of every range, never from the diff,
and `truncated_context` is set. If the diff alone does not fit, the input is
`review_input_overflow` and the whole pair (V and F) is excluded.

`build_review_input` is the only builder. Its parameters are reviewer-visible
material only: there is no way to pass a CVE id, project name, commit,
generator, sibling or PoV. A leak scan (`hp.leaks`) runs on the result anyway.
"""

import hashlib
import re

from ..bank import difftools
from ..tokens import proxy_tokens

PR_TEMPLATE = "This patch addresses the following reported issue: {summary}"
NOT_METHOD = ("if", "for", "while", "switch", "catch", "synchronized", "try", "else", "do",
              "return", "new", "throw", "case", "finally")
TYPE_DECL = re.compile(r"\b(class|interface|enum|record)\s+\w+")
METHOD_HEAD = re.compile(r"(\w+)\s*\([^;{}]*\)\s*(throws\s+[\w.,\s<>]+)?$", re.S)


def java_methods(text):
    """[(name, first_line, last_line)] of every method/constructor body (1-based).

    A brace-matching scan that ignores string and char literals and comments.
    A `{` opens a method if the text since the previous `;`, `{` or `}` looks
    like a method or constructor header (not a control statement, lambda,
    anonymous class, initializer or type declaration).
    """
    out = []
    stack = []  # (is_method, name, start_line)
    header = []
    header_start = None
    line = 1
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if ch in "\"'":
            q = ch
            j = i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            header.append(q + q)
            line += text.count("\n", i, min(j + 1, n))
            i = j + 1
            continue
        if ch == "\n":
            line += 1
            header.append(" ")
            i += 1
            continue
        if ch == "{":
            head = " ".join("".join(header).split())
            head = re.sub(r"@\w+(\([^)]*\))?\s*", "", head).strip()
            words = head.split()
            is_method = bool(
                head and "->" not in head and words and words[0] not in NOT_METHOD
                and not TYPE_DECL.search(head) and "=" not in head.split("(")[0]
                and " new " not in f" {head} " and METHOD_HEAD.search(head)
            )
            name = METHOD_HEAD.search(head).group(1) if is_method else None
            stack.append((is_method, name, header_start or line))
            header, header_start = [], None
            i += 1
            continue
        if ch == "}":
            if stack:
                is_method, name, start = stack.pop()
                if is_method:
                    out.append((name, start, line))
            header, header_start = [], None
            i += 1
            continue
        if ch == ";":
            header, header_start = [], None
            i += 1
            continue
        if not ch.isspace() and header_start is None:
            header_start = line
        header.append(ch)
        i += 1
    return sorted(out, key=lambda m: (m[1], m[2]))


def context_ranges(post_files, changed, context_lines):
    """{path: [(start, end, method_found)]} merged ranges around every change."""
    out = {}
    for path in sorted(changed):
        text = post_files.get(path)
        if text is None:
            continue
        nlines = len(text.split("\n"))
        methods = java_methods(text)
        raw = []
        for ln in sorted(changed[path]):
            inner = [m for m in methods if m[1] <= ln <= m[2]]
            if inner:
                m = min(inner, key=lambda m: m[2] - m[1])
                raw.append([max(1, m[1] - context_lines), min(nlines, m[2] + context_lines), True])
            else:
                raw.append([max(1, ln - context_lines), min(nlines, ln + context_lines), False])
        merged = []
        for s, e, found in sorted(raw):
            if merged and s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
                merged[-1][2] = merged[-1][2] and found
            else:
                merged.append([s, e, found])
        out[path] = [tuple(r) for r in merged]
    return out


def render_context(post_files, ranges, trim=0):
    parts = []
    for path in sorted(ranges):
        lines = post_files[path].split("\n")
        for s, e, _ in ranges[path]:
            s2, e2 = s + trim, e - trim
            if s2 > e2:
                continue
            body = "\n".join(lines[s2 - 1 : e2])
            parts.append(f"### {path} (lines {s2}-{e2})\n\n```java\n{body}\n```")
    return "\n\n".join(parts) if parts else "(no context)"


def _fill(template, pr, diff, context, evidence):
    section = f"\n## Additional evidence\n\n{evidence}\n" if evidence else ""
    return (template.replace("{{PR_DESCRIPTION}}", pr).replace("{{DIFF}}", diff.rstrip("\n"))
            .replace("{{CONTEXT}}", context).replace("{{EVIDENCE_SECTION}}", section))


def build_review_input(template, advisory_summary, diff_text, post_files, cap_tokens,
                       context_lines, evidence=None):
    """Return {status, text, sha256, proxy_tokens, truncated_context, context_method}.

    `post_files` holds the post-patch content of the changed files. The cap
    applies to e0; an Experiment B packet (`evidence`, capped separately at
    `caps.packet_tokens`) is appended after it.
    """
    pr = PR_TEMPLATE.format(summary=" ".join(advisory_summary.split()))
    diff = difftools.for_review(diff_text)
    ranges = context_ranges(post_files, difftools.changed_lines(diff_text), context_lines)
    methods = {f for rs in ranges.values() for _, _, f in rs}
    method = "enclosing_method" if methods == {True} else (
        "hunk_window" if methods == {False} else "mixed")

    def size(trim):
        return proxy_tokens(_fill(template, pr, diff, render_context(post_files, ranges, trim), None))

    bare = proxy_tokens(_fill(template, pr, diff, "(context removed: input cap)", None))
    if bare > cap_tokens:
        return {"status": "review_input_overflow", "text": None, "sha256": None,
                "proxy_tokens": bare, "truncated_context": True, "context_method": method}
    trim = 0
    if size(0) > cap_tokens:
        longest = max((e - s + 1 for rs in ranges.values() for s, e, _ in rs), default=0)
        lo, hi = 1, (longest + 1) // 2 + 1
        while lo < hi:
            mid = (lo + hi) // 2
            if size(mid) <= cap_tokens:
                hi = mid
            else:
                lo = mid + 1
        trim = lo
    context = render_context(post_files, ranges, trim)
    if trim and context == "(no context)":
        context = "(context removed: input cap)"
    text = _fill(template, pr, diff, context, evidence)
    return {"status": "ok", "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "proxy_tokens": proxy_tokens(text), "truncated_context": trim > 0,
            "context_method": method, "trimmed_lines_per_side": trim}
