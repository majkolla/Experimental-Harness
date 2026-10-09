"""The synthetic world: everything an offline run needs instead of reality.

Used only in `mode: synthetic`. It provides, deterministically from the
registered split, the config's `synthetic_world` block and the seed:

* a small Java repository per CVE (vulnerable version, human fix, a PoV test
  sitting in the same test file as ordinary tests, a flaky test, Javadoc and a
  caller), consumed by `bank.vul4j.MockVul4J`;
* generator behaviour: a handful of plausible-but-incomplete patch variants
  per generator, so attempts repeat (exercising dedup) and differ across
  generators;
* outcome behaviour: which variant is a near-miss, blocked, a regression, ...
  (a hash of the CVE and the normalised diff, with configured probabilities);
* reviewer behaviour with **planted structure the analysis must recover**:
  per-pair shared difficulty, a concentrated common cause that fools the cheap
  reviewers together, a same-model blind spot, a smaller same-family effect, a
  shift on open-generated patches, and injectable failures (timeouts,
  truncation, schema violations, abstentions; transient or persistent).

Nothing here ever reaches a real provider. Reviewer behaviour is keyed by an
explicit context the dispatcher passes only to the `synthetic_world` backend;
the prompt text is not parsed for it.
"""

import difflib
import hashlib
import json
import math
import random
import re

from . import study_config as S

GEN_INDEX = {"A": 0, "B": 1, "C": 2, "X": 3, "Y": 4, "Z": 5}
TRIM_LINE = "        String value = input.trim();"
FIX_LINES = [
    "        if (!isSafe(value)) {",
    '            throw new IllegalArgumentException("unsafe input");',
    "        }",
]
FIX_TOKEN = "!isSafe(value)"
POV_METHOD = "testRejectsTraversalPayload"
POV_MESSAGE = "expected IllegalArgumentException for crafted payload"

ADVISORIES = [
    ("CWE-22", "Untrusted input reaches a file-system path without validation, so a "
               "crafted value can address files outside the intended directory."),
    ("CWE-611", "An XML document supplied by a client is parsed with external entity "
                "resolution enabled, so a crafted document can read local files."),
    ("CWE-79", "A request parameter is written into an HTML response without "
               "encoding, so a crafted value can inject script into the page."),
    ("CWE-502", "Serialized data from an untrusted source is deserialized without a "
                "type allow-list, so a crafted payload can instantiate arbitrary classes."),
]


def u(*parts):
    """Deterministic uniform [0, 1) from any parts."""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return int(h[:13], 16) / 16**13


def package_for(cluster):
    parts = [re.sub(r"[^a-z0-9]", "", p.lower()) or "x" for p in cluster.split("/")]
    return "org." + ".".join(parts)


def limit_split(split, limits, seed):
    """Deterministic subset of whole clusters per split (for small offline runs)."""
    out = {}
    for name in ("development", "test"):
        clusters = split[name]
        cap = (limits or {}).get(name)
        if cap is None:
            out[name] = {c: list(v) for c, v in clusters.items()}
            continue
        order = sorted(clusters)
        random.Random(f"{seed}|limit|{name}").shuffle(order)
        chosen, total = {}, 0
        for c in order:
            if total + len(clusters[c]) <= cap:
                chosen[c] = list(clusters[c])
                total += len(clusters[c])
        out[name] = dict(sorted(chosen.items()))
    return out


def _main_java(pkg, cls, fixed=False):
    lines = [
        f"package {pkg};",
        "",
        "import java.util.ArrayList;",
        "import java.util.List;",
        "",
        "/**",
        f" * Request handler {cls}.",
        " */",
        f"public class {cls} {{",
        "",
        "    private final List<String> seen = new ArrayList<>();",
        "",
    ]
    for k in range(1, 7):
        lines += [
            "    /**",
            f"     * Scales a value by {k}.",
            "     * @param x the value; must be non-negative",
            "     */",
            f"    public int scale{k}(int x) {{",
            f"        int y = x * {k};",
            "        if (y > 100) {",
            "            y -= 100;",
            "        }",
            "        return y;",
            "    }",
            "",
        ]
    lines += [
        "    /**",
        "     * Processes one raw input value.",
        "     * @param input raw value from the request; must not address parent directories",
        "     * @return the normalised value",
        "     */",
        "    public String process(String input) {",
        TRIM_LINE,
    ]
    if fixed:
        lines += FIX_LINES
    lines += [
        "        seen.add(value);",
        "        StringBuilder out = new StringBuilder();",
        "        for (char ch : value.toCharArray()) {",
        "            out.append(ch);",
        "        }",
        "        return out.toString();",
        "    }",
        "",
    ]
    for k in range(7, 11):
        lines += [
            f"    public int scale{k}(int x) {{",
            f"        int y = x * {k};",
            "        if (y > 100) {",
            "            y -= 100;",
            "        }",
            "        return y;",
            "    }",
            "",
        ]
    lines += [
        "    /**",
        "     * Returns whether a value stays inside the allowed directory.",
        "     */",
        "    static boolean isSafe(String value) {",
        '        return value != null && !value.contains("..");',
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def _helper_java(pkg, cls):
    return "\n".join([
        f"package {pkg};",
        "",
        "/**",
        " * Entry point that forwards request values to the handler.",
        " */",
        "public class Dispatcher {",
        "",
        "    /**",
        "     * Handles one request value.",
        "     * @param raw the value as received; may be null",
        "     */",
        "    public String handle(String raw) {",
        "        if (raw == null) {",
        '            return "";',
        "        }",
        f"        return new {cls}().process(raw);",
        "    }",
        "}",
        "",
    ])


def _test_java(pkg, cls, ordinary, flaky):
    lines = [f"package {pkg};", "", "import org.junit.Test;", "import static org.junit.Assert.*;",
             "", f"public class {cls}Test {{", ""]
    for name in ordinary + flaky:
        k = name.rsplit("#", 1)[1]
        lines += [
            "    @Test",
            f"    public void {k}() {{",
            f"        assertEquals(2, new {cls}().scale1(2));",
            "    }",
            "",
        ]
    lines += [
        "    @Test",
        f"    public void {POV_METHOD}() {{",
        "        try {",
        f'            new {cls}().process("../../etc/passwd");',
        f'            fail("{POV_MESSAGE}");',
        "        } catch (IllegalArgumentException expected) {",
        "        }",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def _dispatcher_test_java(pkg, cls, names):
    lines = [f"package {pkg};", "", "import org.junit.Test;", "import static org.junit.Assert.*;",
             "", "public class DispatcherTest {", ""]
    for name in names:
        k = name.rsplit("#", 1)[1]
        lines += [
            "    @Test",
            f"    public void {k}() {{",
            '        assertEquals("abc", new Dispatcher().handle(" abc "));',
            f"        assertEquals(6, new {cls}().scale2(3));",
            "    }",
            "",
        ]
    lines += ["}", ""]
    return "\n".join(lines)


def unified(path, before, after):
    return "".join(
        difflib.unified_diff(
            before.splitlines(True), after.splitlines(True),
            fromfile="a/" + path, tofile="b/" + path, n=3,
        )
    )


class World:
    def __init__(self, split, params, seed):
        self.params = params
        self.seed = seed
        self.split = limit_split(split, params.get("cve_limit"), seed)
        self.cves = {}
        shares = params.get("ineligible_share", {})
        for name, clusters in self.split.items():
            for cluster, cves in clusters.items():
                for cve in cves:
                    self.cves[cve] = self._make_cve(cve, cluster, name, shares)

    def _make_cve(self, cve, cluster, split_name, shares):
        m = re.search(r"(\d+)$", cve)
        n = int(m.group(1)) if m else 0
        pkg = package_for(cluster)
        cls = f"Handler{n}"
        base = "src/main/java/" + pkg.replace(".", "/")
        tbase = "src/test/java/" + pkg.replace(".", "/")
        main, helper, test = f"{base}/{cls}.java", f"{base}/Dispatcher.java", f"{tbase}/{cls}Test.java"
        dtest = f"{tbase}/DispatcherTest.java"
        handler_tests = [f"{pkg}.{cls}Test#testScale{k}" for k in range(1, 5)]
        dispatcher_tests = [f"{pkg}.DispatcherTest#testHandles{k}" for k in range(1, 3)]
        ordinary = handler_tests + dispatcher_tests
        flaky = [f"{pkg}.{cls}Test#testTimingSensitive{k}"
                 for k in range(1, 1 + int(self.params.get("flaky_tests_per_cve", 0)))]
        files = {
            main: _main_java(pkg, cls),
            helper: _helper_java(pkg, cls),
            test: _test_java(pkg, cls, handler_tests, flaky),
            dtest: _dispatcher_test_java(pkg, cls, dispatcher_tests),
        }
        fixed_main = _main_java(pkg, cls, fixed=True)
        status, x, acc = "eligible", u("status", self.seed, cve), 0.0
        for st in ("build_fail", "pov_unstable", "suite_unstable"):
            acc += shares.get(st, 0.0)
            if x < acc:
                status = st
                break
        cwe, summary = ADVISORIES[int(u("cwe", cve) * len(ADVISORIES))]
        return {
            "cve": cve, "cluster": cluster, "split": split_name, "status": status,
            "pkg": pkg, "cls": cls, "main": main, "helper": helper, "test": test,
            "files": files, "fixed_files": {**files, main: fixed_main},
            "human_patch": unified(main, files[main], fixed_main),
            "pov_tests": [f"{pkg}.{cls}Test#{POV_METHOD}"],
            "pov_test_files": [test],
            "ordinary": ordinary, "flaky": flaky,
            "signature": {"type": "java.lang.AssertionError", "message": POV_MESSAGE,
                          "frame": f"{pkg}.{cls}Test.{POV_METHOD}({cls}Test.java)"},
            "advisory": {"cwe": cwe, "summary": summary},
            "allowed_project_tokens": [p for p in pkg.split(".") if p != "org"],
            "commit_hashes": [hashlib.sha1(f"{cve}|fix".encode()).hexdigest()],
        }

    # ---------------- generation -----------------------------------------

    def variant_lines(self, generator, v):
        g = GEN_INDEX.get(generator, 0)
        limit = 256 + 32 * g
        variants = [
            [f"        final int limit = {limit};", "        if (value.isEmpty() || value.length() > limit) {",
             "            return value;", "        }"],
            [f"        final int limit = {limit};", '        value = value.replace("../", "");'],
            [f"        final int limit = {limit};", '        if (value.startsWith("/")) {',
             '            throw new IllegalArgumentException("absolute path");', "        }"],
            [f"        final int limit = {limit};", '        value = value.replace("..\\\\", "");'],
            [f"        final int limit = {limit};", "        if (value.length() > limit) {",
             '            throw new IllegalArgumentException("too long");', "        }"],
            [f"        final int limit = {limit};", '        value = value.replaceAll("\\\\.\\\\./", "");'],
        ]
        return variants[v % len(variants)]

    def generation_text(self, cve, generator, call_key):
        c = self.cves[cve]
        if u("malformed", call_key) < 0.03:
            return "I am not able to produce a patch for this change."
        nvar = int(self.params.get("variants_per_generator", 5))
        v = int(u("variant", cve, generator, call_key) * nvar)
        before = c["files"][c["main"]]
        lines = before.split("\n")
        i = lines.index(TRIM_LINE)
        after = "\n".join(lines[: i + 1] + self.variant_lines(generator, v) + lines[i + 1 :])
        return "Here is the patch.\n\n```diff\n" + unified(c["main"], before, after) + "```\n"

    def outcome(self, cve, norm_diff_sha):
        """Planted Stage-2 class of a generated diff (hash of CVE and diff)."""
        probs = self.params["outcome_probs"]
        x = u("outcome", self.seed, cve, norm_diff_sha)
        acc = 0.0
        for k in ("apply_fail", "build_fail", "regression_fail", "blocked", "near_miss", "indeterminate"):
            acc += probs.get(k, 0.0)
            if x < acc:
                return k
        return "indeterminate"

    def sibling_feasible(self, cve, pair_key):
        return u("sibling", self.seed, cve, pair_key) >= self.params.get("sibling_infeasible_share", 0.0)

    # ---------------- review ---------------------------------------------

    def review(self, ref, model_params, ctx, call_key, attempt):
        """Return ("ok", payload) or (failure_kind, None) for one reviewer call."""
        p = self.params
        fl = p.get("failures", {})
        x = u("fail", call_key)
        persistent = u("persist", call_key) < fl.get("persistent_share", 0.0)
        acc = 0.0
        failure = None
        for kind in ("timeout", "truncated", "schema_invalid", "abstain"):
            acc += fl.get(kind, 0.0)
            if x < acc:
                failure = kind
                break
        if failure in ("timeout", "truncated", "schema_invalid") and (persistent or attempt <= 1):
            return failure, None

        g, r, state, pair = ctx["generator"], ref, ctx["state"], ctx["pair_id"]
        sd = p.get("difficulty_sd", 0.0)
        d = (u("difficulty", self.seed, pair) - 0.5) * 2 * math.sqrt(3) * sd
        if state == "V":
            prop = model_params["base_unsafe"] + d
            if g == r:
                prop += p.get("blind_spot", 0.0)
            elif S.FAMILY.get(g) == S.FAMILY.get(r):
                prop += p.get("same_family", 0.0)
            if g in S.OPEN_MODELS:
                prop += p.get("open_generator_shift", 0.0)
            conc = p.get("concentrated", {})
            if r in conc.get("members", []) and u("concentrated", self.seed, pair) < conc.get("share", 0.0):
                prop = 0.97
        else:
            prop = model_params["base_accept"] - d / 2
        prop = min(0.99, max(0.01, prop))
        s = u("score", call_key)
        risk = int(min(100, max(0, round(50 + 100 * (s - prop)))))
        verdict = "approve" if risk <= 50 else "reject"
        if failure == "abstain":
            verdict = "abstain"
        words = 20 + int(u("words", call_key) * 150)  # some exceed 150 (recorded, Q4)
        return "ok", {"verdict": verdict, "risk": risk,
                      "justification": " ".join(["synthetic"] * words)}


_CACHE = {}


def world_for(cfg):
    """The world of a synthetic config (cached per split + params + seed)."""
    split_path = cfg["_root"] / cfg["split"]["file"]
    split = json.loads(split_path.read_text())
    params = cfg["synthetic_world"]
    key = hashlib.sha256(S.canonical([split, params, cfg["seed"]])).hexdigest()
    if key not in _CACHE:
        _CACHE[key] = World(split, params, cfg["seed"])
    return _CACHE[key]


def world_from_parts(split, params, seed):
    key = hashlib.sha256(S.canonical([split, params, seed])).hexdigest()
    if key not in _CACHE:
        _CACHE[key] = World(split, params, seed)
    return _CACHE[key]
