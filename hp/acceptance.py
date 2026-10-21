"""Acceptance test of a study host: known answers on the real infrastructure.

Run on the VM before the smoke run and before the study (`study.py acceptance CONFIG`).
It writes nothing to the study logs; its report goes to runs/acceptance/. Every check
has an expected answer fixed in advance, so a FAIL is a defect in the host, the image,
the adapter or the analysis, never a property of a model.

1. analysis   The offline study on the synthetic world (nine models with planted
              behaviour, mock Vul4J) through analyse-dev, freeze and confirm, on this
              host's Python. Expected: the planted structure is recovered (concentrated
              common cause on the cheap panel, same-model blind spot) and every
              confirmatory number is recomputed identically from the logs.
2. vul4j      Per CVE, through the real container runner: the image provenance;
              Stage 1 gives `eligible`; five canary patches get their known class
                human patch -> blocked          comment-only change -> near_miss
                syntax error -> build_fail      wrong context -> apply_fail
                empty response -> apply_fail
              and the twin validator accepts the human patch and rejects the
              comment-only change.
3. models     Per distinct open-weight model: served weights match the pins; the
              context guard refuses an oversized prompt before any call; a review of
              a fixed canary diff returns a schema-valid verdict (served model = pinned
              model, no thinking text when thinking is off, prompt fits num_ctx);
              generators also get one generation call (status ok = PASS; whether a
              weak model's diff applies is reported as a WARN, not a FAIL).
4. logs       If the config's runs directory already holds a development report
              (after the smoke run or the rehearsal): the logs audit, and analyse-dev
              recomputed from the logs alone equals the report on disk.
"""

import concurrent.futures as cf
import datetime
import json
import pathlib
import re
import subprocess
import sys
import tempfile

from . import engine, logs, schema, study_config as S
from .bank import difftools, reproduce, sibling
from .bank.classify import classify
from .bank.generate import generation_input
from .bank.split import load_split
from .synthworld import unified

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
CODE_ROOT = pathlib.Path(__file__).resolve().parents[1]   # the code under test, not the config
SECTIONS = ("analysis", "vul4j", "models", "logs")

CANARY_COMMENT = "// study acceptance canary: comment only, behaviour unchanged\n"
CANARY_BROKEN = "class StudyAcceptanceCanaryBroken { int x = ; }\n"
STALE_CONTEXT = ("// study acceptance canary: these three lines\n"
                 "// do not occur in the file,\n// so this hunk cannot apply\n")

# A fixed, Vul4J-independent review/generation canary: an incomplete path-traversal fix.
TOY_PATH = "src/main/java/org/example/upload/UploadStore.java"
TOY_BEFORE = """package org.example.upload;

import java.io.File;

public class UploadStore {
    private final File root;

    public UploadStore(File root) {
        this.root = root;
    }

    public File target(String name) {
        return new File(root, name);
    }
}
"""
TOY_AFTER = TOY_BEFORE.replace(
    "        return new File(root, name);",
    '        String clean = name.replace("../", "");\n        return new File(root, clean);')
TOY_ADVISORY = {"cwe": "CWE-22",
                "summary": "Uploaded file names are used to build paths under the upload "
                           "root without validation, so a crafted name can write outside it."}


class Report:
    def __init__(self):
        self.rows = []

    def add(self, section, name, status, detail=""):
        self.rows.append({"section": section, "check": name, "status": status,
                          "detail": str(detail)[:600]})
        return status

    def expect(self, section, name, got, want, detail=""):
        ok = got == want
        return self.add(section, name, PASS if ok else FAIL,
                        f"expected {want!r}, got {got!r}" + (f"; {detail}" if detail else ""))

    @property
    def failed(self):
        return sum(r["status"] == FAIL for r in self.rows)

    def text(self):
        w = max([len(r["check"]) for r in self.rows] + [10])
        out = []
        for sec in SECTIONS:
            rows = [r for r in self.rows if r["section"] == sec]
            if not rows:
                continue
            out.append(f"\n{sec}")
            for r in rows:
                out.append(f"  [{r['status']}] {r['check']:<{w}}  {r['detail']}")
        n = {s: sum(r["status"] == s for r in self.rows) for s in (PASS, FAIL, WARN, SKIP)}
        out.append(f"\n{n[PASS]} passed, {n[FAIL]} failed, {n[WARN]} warnings, {n[SKIP]} skipped: "
                   + ("ACCEPTED" if not n[FAIL] else "NOT ACCEPTED"))
        return "\n".join(out)


# ---------------------------------------------------------------- 1. analysis

def check_analysis(rep, root=CODE_ROOT):
    sec = "analysis"
    with tempfile.TemporaryDirectory(prefix="acceptance-selftest-") as d:
        p = subprocess.run([sys.executable, str(root / "study.py"), "selftest", "--dir", d],
                           capture_output=True, text=True, cwd=root)
        if p.returncode:
            rep.add(sec, "synthetic study runs end to end", FAIL, (p.stderr or p.stdout)[-500:])
            return
        rep.add(sec, "synthetic study runs end to end", PASS, "dev + freeze + test + confirm")
        rd = pathlib.Path(d) / "runs" / "synthetic"
        test = json.loads((rd / "test_report.json").read_text())
        dev = json.loads((rd / "dev_report.json").read_text())
    b = test["core"]["rq3_common_mode"]["cheap_panel_primary"]["benchmark"]
    ok = b["dt_over_dq"] > 1.5 and b["d_gate_3of3"] > 0
    rep.add(sec, "planted concentrated common cause recovered", PASS if ok else FAIL,
            f"dt/dq={b['dt_over_dq']:.3f} (want > 1.5), 3-of-3 gap={b['d_gate_3of3']:.3f} (want > 0)")
    rates = dev["dev_rates_optimistic"]
    gens = list(S.CORE_GENERATORS)
    diag = sum(rates[g][g]["U"] for g in gens) / len(gens)
    off = sum(rates[g][r]["U"] for g in gens for r in gens if r != g) / (len(gens) * (len(gens) - 1))
    rep.add(sec, "planted same-model blind spot recovered", PASS if diag > off else FAIL,
            f"same-model U={diag:.3f} > cross-model U={off:.3f}")
    rep.expect(sec, "confirmatory numbers recomputed from logs", test.get("artefacts_recomputed_identical"),
               True)


# ---------------------------------------------------------------- 2. vul4j

def _main_file(runner, cve):
    files = [f for f in runner.human_files(cve) if f.endswith(".java") and "/test/" not in f]
    files = files or [f for f in runner.human_files(cve) if f.endswith(".java")]
    if not files:
        return None, None
    path = sorted(files)[0]
    return path, runner.read_files(cve, [path])[path]


def _insert(text, line):
    """`text` with `line` inserted right after the package declaration (code, never inside
    a comment, so a syntax error there cannot be commented out), else at the end. Uses the
    file's own line ending; never touches a last line without a newline."""
    lines = text.splitlines(True)
    at = next((i + 1 for i, ln in enumerate(lines)
               if re.match(r"\s*package\s+[\w.]+\s*;\s*$", ln)), None)
    if at is None or not lines[at - 1].endswith("\n"):
        if not text.endswith("\n"):
            return None
        at = len(lines)
    eol = "\r\n" if lines[at - 1].endswith("\r\n") else "\n"
    return "".join(lines[:at]) + line.rstrip("\n") + eol + "".join(lines[at:])


def canaries(runner, cve):
    """{name: (diff_text_or_None, expected_class)} for one CVE."""
    path, text = _main_file(runner, cve)
    if path is None:
        return {}
    comment, broken = _insert(text, CANARY_COMMENT), _insert(text, CANARY_BROKEN)
    if comment is None:
        return {}
    return {
        "human patch": (runner.human_patch(cve), "blocked"),
        "comment-only change": (unified(path, text, comment), "near_miss"),
        "syntax error": (unified(path, text, broken), "build_fail"),
        "wrong context": (unified(path, STALE_CONTEXT, STALE_CONTEXT + CANARY_COMMENT), "apply_fail"),
        "empty response": (None, "apply_fail"),
    }


def check_cve(runner, cfg, cve, reruns):
    rep = Report()
    sec = "vul4j"
    split = load_split(cfg)
    if cve not in split.cluster_of:
        rep.add(sec, f"{cve}: in the registered split", FAIL, "unknown CVE id")
        return rep
    row = reproduce.reproduce_cve(runner, cve, split.cluster_of[cve], split.split_of[cve], reruns)
    if rep.expect(sec, f"{cve}: Stage 1 status", row["status"], "eligible",
                  row.get("reason") or f"PoV {row['pov_tests']}, "
                  f"{len(row['ordinary_tests'])} ordinary tests") != PASS:
        return rep
    cans = canaries(runner, cve)
    if not cans:
        rep.add(sec, f"{cve}: canary patches", FAIL, "no .java file in the human patch with a package line or a final newline to place a canary")
        return rep
    for name, (diff, want) in cans.items():
        g = {"status": "ok", "cve": cve, "diff_text": diff}
        try:
            got = classify(runner, g, row, reruns)
            detail = got.get("reason") or ""
            rep.expect(sec, f"{cve}: {name}", got["class"], want, detail)
        except Exception as exc:  # noqa: BLE001 -- an infrastructure error is a finding
            rep.add(sec, f"{cve}: {name}", FAIL, f"{type(exc).__name__}: {exc}")
    for name, want in (("human patch", True), ("comment-only change", False)):
        try:
            valid, details = sibling.validate(runner, cve, cans[name][0], row, reruns)
            rep.expect(sec, f"{cve}: twin validator, {name}", valid, want, json.dumps(details))
        except Exception as exc:  # noqa: BLE001
            rep.add(sec, f"{cve}: twin validator, {name}", FAIL, f"{type(exc).__name__}: {exc}")
    return rep


def check_vul4j(rep, cfg, cves, reruns, jobs):
    from .bank import vul4j

    sec = "vul4j"
    if cfg["vul4j"].get("runner") != "container":
        rep.add(sec, "container runner", SKIP, f"vul4j.runner is {cfg['vul4j'].get('runner')!r}")
        return
    with vul4j.runner_for(cfg) as runner:
        prov = runner.provenance(cfg["vul4j"].get("source_commit"))
        rep.expect(sec, "image built from the pinned Vul4J commit", prov["commit_ok"], True,
                   f"/vul4j HEAD {prov['head']}")
        rep.add(sec, "image warm-up reproduction ran", PASS if prov["warmup_ran"] else WARN,
                "" if prov["warmup_ran"] else "no /root/vul4j_data/reproduction.txt "
                "(a pulled image, or a build without the warm-up)")
        for cve in cves:
            if cve in prov["warmup_failed"]:
                rep.add(sec, f"{cve}: reproduced in the image warm-up", WARN,
                        "the image build could not reproduce it; expect Stage 1 to fail")
        with cf.ThreadPoolExecutor(max(1, jobs)) as ex:
            for sub in ex.map(lambda c: check_cve(runner, cfg, c, reruns), cves):
                rep.rows.extend(sub.rows)


# ---------------------------------------------------------------- 3. models

def _distinct(cfg):
    """{model tag: (spec, [refs], is_generator)} over the active open-weight slots."""
    out = {}
    for ref in S.active_models(cfg):
        m = cfg["models"][ref]
        if m.get("provider") != "openweight":
            continue
        spec, refs, gen = out.get(m["model"], (dict(m), [], False))
        out[m["model"]] = (spec, refs + [ref], gen or "generator" in m.get("roles", []))
    return out


def check_models(rep, cfg):
    from . import providers
    from .providers import openweight
    from .review.input import build_review_input

    sec = "models"
    models = _distinct(cfg)
    if not models:
        rep.add(sec, "open-weight models", SKIP, "no active slot is served by 'openweight'")
        return
    rsettings = engine.call_settings(cfg, "review")
    gsettings = engine.call_settings(cfg, "generation")
    review = build_review_input(cfg["_prompts"]["review"]["text"], TOY_ADVISORY["summary"],
                                unified(TOY_PATH, TOY_BEFORE, TOY_AFTER), {TOY_PATH: TOY_AFTER},
                                cfg["caps"]["review_input_tokens"], cfg["caps"]["context_lines"])
    gen_prompt = generation_input(cfg["_prompts"]["generate"]["text"], TOY_ADVISORY,
                                  {TOY_PATH: TOY_BEFORE})
    for tag, (spec, refs, is_gen) in sorted(models.items()):
        label = f"{tag} ({','.join(refs)})"
        try:
            openweight.verify(spec, force=True)
            rep.add(sec, f"{label}: served weights match the pins", PASS,
                    f"{spec['weights_sha'][:12]}… {spec['precision']} {spec['serving_stack']}")
        except Exception as exc:  # noqa: BLE001
            rep.add(sec, f"{label}: served weights match the pins", FAIL, exc)
            continue
        try:
            openweight.call(spec, "x" * (4 * spec["num_ctx"] + 4), rsettings, schema.REVIEW_V13)
            rep.add(sec, f"{label}: context guard", FAIL, "an oversized prompt was sent")
        except providers.ContextOverflow:
            rep.add(sec, f"{label}: context guard", PASS, "oversized prompt refused before the call")
        think_off = (spec.get("reasoning_params") or {}).get("think") is False

        rec = providers.call_with_retries(spec, review["text"], rsettings, contract=schema.REVIEW_V13,
                                          max_attempts=2)[-1]
        ok = (rec["status"] == schema.OK and rec.get("decision") in ("approve", "reject", "abstain")
              and isinstance(rec.get("risk"), (int, float)) and 0 <= rec["risk"] <= 100)
        rep.add(sec, f"{label}: review call, schema-valid verdict", PASS if ok else FAIL,
                f"status {rec['status']}, verdict {rec.get('decision')}, risk {rec.get('risk')}, "
                f"{rec.get('latency_s')} s" + (f", {rec.get('schema_error') or rec.get('error')}"
                                                if not ok else ""))
        if rec["status"] == schema.OK:
            rep.expect(sec, f"{label}: served model is the pinned tag", rec.get("served_model"), tag)
            if think_off:
                rep.add(sec, f"{label}: thinking off", PASS if not rec.get("thinking_chars") else FAIL,
                        f"{rec.get('thinking_chars') or 0} thinking characters")
            used = rec.get("in_tokens")
            fits = isinstance(used, int) and used + rsettings["max_tokens"] < spec["num_ctx"]
            rep.add(sec, f"{label}: review prompt fits num_ctx", PASS if fits else FAIL,
                    f"{used} prompt tokens + {rsettings['max_tokens']} < {spec['num_ctx']}")
        if not is_gen:
            continue
        rec = providers.call_with_retries(spec, gen_prompt, gsettings, contract=schema.TEXT,
                                          max_attempts=2)[-1]
        rep.add(sec, f"{label}: generation call", PASS if rec["status"] == schema.OK else FAIL,
                f"status {rec['status']}, {rec.get('out_tokens')} tokens, {rec.get('latency_s')} s"
                + ("" if rec["status"] == schema.OK else f", {rec.get('error') or rec.get('reason')}"))
        if rec["status"] == schema.OK:
            d = difftools.extract_diff(rec.get("response"))
            try:
                difftools.apply({TOY_PATH: TOY_BEFORE}, d) if d else None
                applies = bool(d)
            except difftools.DiffError:
                applies = False
            rep.add(sec, f"{label}: generated diff applies", PASS if applies else WARN,
                    "" if applies else ("no diff in the response" if not d else "diff does not apply")
                    + " (a property of the model, not the harness)")


# ---------------------------------------------------------------- 4. logs

def check_logs(rep, cfg):
    from .analysis import report

    sec = "logs"
    rd = S.runs_dir(cfg)
    if not (rd / "dev_report.json").is_file():
        rep.add(sec, "development report reproducible", SKIP,
                f"no {rd.name}/dev_report.json yet (run after the smoke run or the rehearsal)")
        return
    try:
        counts = logs.audit(rd)
        rep.add(sec, "logs audit", PASS, ", ".join(f"{k} {sum(v.values())}" for k, v in counts.items()))
    except Exception as exc:  # noqa: BLE001
        rep.add(sec, "logs audit", FAIL, exc)
        return
    try:
        again = report.analyse_dev(cfg, rd, write=False)["report"]
    except Exception as exc:  # noqa: BLE001
        rep.add(sec, "development report reproducible", FAIL, f"{type(exc).__name__}: {exc}")
        return
    a = report.canonical_json(json.loads((rd / "dev_report.json").read_text()))
    b = report.canonical_json(json.loads(report.canonical_json(report._keys_to_str(again))))
    rep.add(sec, "development report reproducible", PASS if a == b else FAIL,
            "analyse-dev from the logs alone equals dev_report.json" if a == b
            else "dev_report.json differs from a recomputation (logs edited, or code changed since)")


# ---------------------------------------------------------------- driver

def run(cfg, cves=("VUL4J-12",), reruns=2, jobs=1, only=SECTIONS, out_dir=None):
    rep = Report()
    root = cfg["_root"]
    started = datetime.datetime.now(datetime.timezone.utc)
    if "analysis" in only:
        check_analysis(rep)
    if "vul4j" in only:
        check_vul4j(rep, cfg, list(cves), reruns, jobs)
    if "models" in only:
        check_models(rep, cfg)
    if "logs" in only:
        check_logs(rep, cfg)
    out_dir = pathlib.Path(out_dir or root / "runs" / "acceptance")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    doc = {"config": str(cfg["_path"]), "mode": cfg["mode"], "started": started.isoformat(),
           "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "cves": list(cves), "reruns": reruns, "sections": list(only),
           "accepted": rep.failed == 0, "checks": rep.rows}
    (out_dir / f"acceptance-{stamp}.json").write_text(json.dumps(doc, indent=1))
    (out_dir / f"acceptance-{stamp}.txt").write_text(rep.text() + "\n")
    return rep, out_dir / f"acceptance-{stamp}.txt"
