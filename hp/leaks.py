"""Oracle isolation: what may never reach a model input (section 11.1, Q12).

Generator and reviewer inputs are built by functions whose signatures cannot
take an oracle field (the legacy `config.build_prompt` pattern). As a second,
independent line of defence every built input is scanned against the strict
list below before it is dispatched; a hit raises `LeakError`.

Strict list (SPEC_ANSWERS Q12):
* any CVE id (CVE-yyyy-nnnn) and any Vul4J id;
* the project's GitHub slug as a reference (owner/repo, github.com/owner/repo).
  A slug that is merely part of a Java path or package (org/apache/struts/...)
  is code, and is kept: packages, imports and paths are never rewritten;
* the fix commit hashes (full, and any 7+ character prefix);
* PoV test ids and method names, and the PoV's failure output;
* every configured model id and snapshot, and any configured identity term
  (generator identity).

The project tokens that are allowed to stay (package and path segments) are
recorded per CVE in `inputs.jsonl`.

Where each pattern applies (PLAN.md section 10 item 32). Oracle patterns (ids,
slug, commit hashes, PoV names and output) apply to the whole input. Model ids
and identity terms apply only to the lines the patch adds: that is the only
text a generator wrote, so it is the only place generator identity can come
from. Applied to the whole input they also matched the project's own code
(an import of com.google.common, a comment naming a vendor), which silently
excluded every pair of such a CVE from review. Generator inputs (advisory plus
project files) are scanned with the oracle patterns only.
"""

import re


class LeakError(ValueError):
    """Forbidden material found in a model input."""


GENERIC = [
    ("cve_id", re.compile(r"CVE-\d{4}-\d{4,}", re.I)),
    ("vul4j_id", re.compile(r"VUL4J-\d+", re.I)),
]


def patterns(meta, model_ids=(), identity_terms=()):
    """[(label, compiled regex)] for one CVE."""
    pats = list(GENERIC)
    slug = meta.get("cluster")
    if slug and "/" in slug:
        s = re.escape(slug)
        pats.append(("github_slug", re.compile(r"(?<![\w./-])" + s + r"(?![\w/-])", re.I)))
        pats.append(("github_slug", re.compile(r"github\.com[/:]" + s, re.I)))
    for h in meta.get("commit_hashes") or []:
        h = h.lower()
        pats.append(("commit_hash", re.compile(r"\b" + re.escape(h[:7]) + r"[0-9a-f]*\b", re.I)))
    for t in meta.get("pov_tests") or []:
        pats.append(("pov_test", re.compile(re.escape(t))))
        method = t.split("#")[-1]
        if method:
            pats.append(("pov_test", re.compile(r"\b" + re.escape(method) + r"\b")))
    for o in meta.get("pov_output") or []:
        o = " ".join(str(o).split())
        if len(o) >= 12:
            pats.append(("pov_output", re.compile(re.escape(o))))
    for m in model_ids:
        if m and len(m) >= 4:
            pats.append(("model_id", re.compile(re.escape(m))))
    for term in identity_terms:
        if term:
            pats.append(("identity_term", re.compile(re.escape(term), re.I)))
    return pats


def find(text, pats):
    hits = []
    for label, rx in pats:
        m = rx.search(text)
        if m:
            hits.append((label, m.group(0)))
    return hits


def scan(text, pats):
    hits = find(text, pats)
    if hits:
        raise LeakError(f"forbidden material in model input: {hits}")
    return text


def model_identity(cfg):
    """Every configured model id / snapshot, and every configured identity term."""
    ids, terms = set(), set()
    for m in cfg["models"].values():
        for k in ("model", "snapshot"):
            v = m.get(k)
            if isinstance(v, str) and v != "TO_PIN_AT_FREEZE":
                ids.add(v)
        terms |= set(m.get("identity_terms") or [])
    return sorted(ids), sorted(terms)


def oracle_patterns(meta):
    """The oracle part of the strict list (no model ids, no identity terms)."""
    return patterns(meta)


def identity_patterns(model_ids=(), identity_terms=()):
    """Model ids, and identity terms as words.

    Case-insensitive, not preceded by a letter, digit, '_' or '.', and not followed
    by a letter: "qwen", "GPT4", "Gemma3" and "Claude-generated" are caught, a
    package segment such as com.google.common is not.
    """
    pats = [p for p in patterns({}, model_ids) if p[0] == "model_id"]
    for term in identity_terms:
        if term:
            pats.append(("identity_term",
                         re.compile(r"(?<![\w.])" + re.escape(term) + r"(?![A-Za-z])", re.I)))
    return pats


def added_text(diff_text, base_files=None):
    """What the generator wrote: the lines a diff adds that are not already in the
    pre-patch files (a rewritten file re-adds its own licence header), plus any
    free text after a hunk header's second '@@'."""
    known = set()
    for text in (base_files or {}).values():
        known |= {l.strip() for l in text.split("\n")}
    out = []
    for line in (diff_text or "").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            if line[1:].strip() not in known:
                out.append(line[1:])
        elif line.startswith("@@"):
            tail = line.split("@@")[2:] if line.count("@@") >= 2 else []
            if tail and "".join(tail).strip() not in known:
                out.append("@@".join(tail))
    return "\n".join(out)


def find_review(text, diff_text, oracle, identity, base_files=None):
    """Hits in a review input: oracle patterns anywhere, identity in what the
    generator wrote (added_text)."""
    return find(text, oracle) + find(added_text(diff_text, base_files), identity)
