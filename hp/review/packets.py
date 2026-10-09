"""Experiment B evidence packets (section 13, SPEC_ANSWERS Q13).

Built offline, before any review, from the candidate and the project sources
only (never from labels, the PoV or review outcomes). Each packet is capped at
`caps.packet_tokens` (3,000) on the bytes/4 proxy, hashed, and appended to e0.
The method is the lightweight text finder (`method: lightweight-text`), which
is recorded with every packet.

| packet           | content                                                          |
|------------------|------------------------------------------------------------------|
| `structure`      | callers and callees of the changed methods, and the guard        |
|                  | conditions (if / while / assert) inside them                     |
| `ordinary_tests` | ordinary test files that mention a changed class, plus this      |
|                  | candidate's regression result; the WHOLE file containing the PoV |
|                  | test is excluded (Q13a)                                          |
| `contracts`      | Javadoc of the changed and the called methods                    |
"""

import hashlib
import re

from ..tokens import proxy_tokens
from .input import java_methods

METHOD = "lightweight-text"
KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "super",
            "this", "throw", "assert", "else", "try", "do", "case"}
CALL = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
GUARD = re.compile(r"^\s*(if|while|assert|else if)\b")


def _cap(items, cap_tokens):
    """Join items until the cap; record whether anything was cut."""
    out, truncated = [], False
    for item in items:
        candidate = "\n\n".join(out + [item])
        if proxy_tokens(candidate) > cap_tokens:
            truncated = True
            room = cap_tokens * 4 - len("\n\n".join(out).encode()) - 8
            if room > 200 and not out:
                out.append(item.encode()[:room].decode(errors="ignore") + "\n[...]")
            break
        out.append(item)
    return "\n\n".join(out) if out else "(nothing found)", truncated


def _methods_by_name(files):
    found = {}
    for path, text in files.items():
        lines = text.split("\n")
        for name, s, e in java_methods(text):
            found.setdefault(name, []).append((path, s, e, lines))
    return found


def _javadoc_before(lines, start):
    i = start - 2
    while i >= 0 and not lines[i].strip():
        i -= 1
    if i >= 0 and lines[i].strip().endswith("*/"):
        j = i
        while j >= 0 and "/**" not in lines[j]:
            j -= 1
        if j >= 0:
            return "\n".join(lines[j : i + 1])
    return None


def changed_methods(post_files, changed):
    out = []
    for path, lines_changed in changed.items():
        text = post_files.get(path)
        if text is None:
            continue
        for name, s, e in java_methods(text):
            if any(s <= ln <= e for ln in lines_changed):
                out.append((path, name, s, e))
    return out


def structure(post_files, main_files, changed, cap_tokens):
    items = []
    cm = changed_methods(post_files, changed)
    names = {n for _, n, _, _ in cm}
    by_name = _methods_by_name(main_files)
    callees = set()
    guards = []
    for path, name, s, e in cm:
        lines = post_files[path].split("\n")[s - 1 : e]
        for ln in lines:
            callees |= {c for c in CALL.findall(ln) if c not in KEYWORDS and c != name}
            if GUARD.match(ln):
                guards.append(f"{path}: {ln.strip()}")
    if guards:
        items.append("Guard conditions in the changed methods:\n" + "\n".join(guards))
    for c in sorted(callees):
        for path, s, e, lines in by_name.get(c, []):
            items.append(f"Callee {c} ({path}, lines {s}-{e}):\n```java\n"
                         + "\n".join(lines[s - 1 : min(e, s + 14)]) + "\n```")
    for path, text in sorted(main_files.items()):
        lines = text.split("\n")
        for name, s, e in java_methods(text):
            body = "\n".join(lines[s - 1 : e])
            if name not in names and any(re.search(r"\b%s\s*\(" % re.escape(n), body) for n in names):
                items.append(f"Caller {name} ({path}, lines {s}-{e}):\n```java\n{body}\n```")
    return _cap(items, cap_tokens)


def ordinary_tests(test_files, pov_test_files, changed_classes, regression_note, cap_tokens):
    items = [regression_note]
    for path, text in sorted(test_files.items()):
        if path in set(pov_test_files):
            continue  # Q13a: the whole file containing the PoV test is excluded
        if any(re.search(r"\b%s\b" % re.escape(c), text) for c in changed_classes):
            items.append(f"{path}:\n```java\n{text.rstrip()}\n```")
    return _cap(items, cap_tokens)


def contracts(post_files, main_files, changed, cap_tokens):
    items = []
    cm = changed_methods(post_files, changed)
    wanted = {n for _, n, _, _ in cm}
    for path, name, s, e in cm:
        for ln in post_files[path].split("\n")[s - 1 : e]:
            wanted |= {c for c in CALL.findall(ln) if c not in KEYWORDS}
    seen = set()
    for path, text in sorted({**main_files, **post_files}.items()):
        lines = text.split("\n")
        for name, s, e in java_methods(text):
            if name in wanted and (path, name) not in seen:
                doc = _javadoc_before(lines, s)
                if doc:
                    seen.add((path, name))
                    items.append(f"{path} {name}:\n{doc}\n{lines[s - 1].strip()}")
    return _cap(items, cap_tokens)


def build(kind, **kw):
    fn = {"structure": structure, "ordinary_tests": ordinary_tests, "contracts": contracts}[kind]
    text, truncated = fn(**kw)
    return {"kind": kind, "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "proxy_tokens": proxy_tokens(text), "truncated": truncated, "method": METHOD}
