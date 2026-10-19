"""Stage 3: the corrected twins F (section 9).

Default method (`sibling.method = author`): the author writes each F by hand
as a complete patch against the vulnerable version, saved as
`<inputs>/siblings/<pair_id>.diff`, in the seeded correction order (core
twins first, then extension twins). This module ingests and validates them.
In synthetic mode a synthetic author adds the planted fix to V.

Method `openweight_model` (the spec's sensitivity method, and what a rehearsal
uses): the open-weight model `sibling.model_ref` drafts the correction of V
from the advisory and V's post-patch code (prompt `prompts.sibling`), once per
pair; the draft becomes a complete patch against the vulnerable version and is
validated exactly like an author's F. A draft that fails is logged `invalid`
and is not re-drawn (no re-rolling after seeing validation). In the live study
such twins still need the author's check before they enter the bank.

Validation (10/10, Q14 protocol): F applies and builds once; one screening run
of the full suite; then 10 clean reruns in which every ordinary test and the
PoV pass. Rubric (Q15), measured on the post-patch code of V versus F:
changed lines (target <= `caps.sibling_target_lines`, flagged not enforced)
and added comment lines (flagged). An F that is missing when the author stops
ends the order: a `sibling_stop` row records the stopping point and pairs
after it are not in the bank. An F that fails validation is logged `invalid`
(the author may supply a corrected file); a pair the author declares
infeasible (`<pair_id>.infeasible`), or the synthetic author cannot correct,
is `infeasible`: the cell is dropped, with no redraw (Q15).
"""

import pathlib

from .. import synthworld
from . import difftools
from .vul4j import ApplyError, BuildError, unified_diff


def sibling_input(template, advisory, files):
    """The only builder of the twin-drafting prompt: advisory and V's post-patch code."""
    adv = f"Weakness class: {advisory['cwe']}\n\n{advisory['summary']}"
    parts = [f"### {path}\n\n```java\n{files[path].rstrip()}\n```" for path in sorted(files)]
    return template.replace("{{ADVISORY}}", adv).replace("{{FILES}}", "\n\n".join(parts))


def model_author(cfg, runner, cve, v_diff):
    """(f_diff or None, draft record). One draft by `sibling.model_ref`."""
    from .. import engine, leaks, providers, schema
    from .generate import advisory_for

    ref = cfg["sibling"]["model_ref"]
    spec = {**cfg["models"][ref], "_ref": ref}
    changed = sorted(difftools.changed_lines(v_diff))
    base = runner.read_files(cve, changed, "vulnerable")
    try:
        v_post = difftools.apply(base, v_diff)
    except difftools.DiffError as exc:
        return None, {"model_ref": ref, "status": "v_does_not_apply", "error": str(exc)[:200]}
    prompt = sibling_input(cfg["_prompts"]["sibling"]["text"], advisory_for(cfg, cve), v_post)
    hits = leaks.find(prompt, leaks.oracle_patterns(runner.metadata(cve)))
    if hits:
        return None, {"model_ref": ref, "model": spec.get("model"), "status": "leak",
                      "error": f"oracle material in the prompt: {sorted({h[0] for h in hits})}"}
    settings = engine.call_settings(cfg, "generation")
    recs = providers.call_with_retries(spec, prompt, settings, contract=schema.TEXT)
    rec = recs[-1]
    draft = {"model_ref": ref, "model": spec.get("model"), "status": rec["status"],
             "attempts": len(recs), "tokens": {"in": rec.get("in_tokens"), "out": rec.get("out_tokens")},
             "raw": (rec.get("text") or "")[:20000]}
    if rec["status"] != schema.OK:
        # a failed call says nothing about the pair: no row, a resumed run asks again
        return None, {**draft, "retry": True, "error": rec.get("reason") or rec.get("error")}
    d = difftools.extract_diff(rec.get("text"))
    if not d:
        return None, {**draft, "error": "no unified diff in the response"}
    try:
        f_post = difftools.apply(v_post, d)
    except difftools.DiffError as exc:
        return None, {**draft, "error": f"draft does not apply to V: {exc}"[:200]}
    return unified_diff(base, f_post), draft


def synthetic_author(world, cve, v_diff, pair_id):
    """F = V plus the planted fix, unless the world makes this pair infeasible."""
    if not world.sibling_feasible(cve, pair_id):
        return None
    c = world.cves[cve]
    post = difftools.apply(c["files"], v_diff)[c["main"]]
    lines = post.split("\n")
    i = lines.index(synthworld.TRIM_LINE)
    fixed = "\n".join(lines[: i + 1] + synthworld.FIX_LINES + lines[i + 1 :])
    return synthworld.unified(c["main"], c["files"][c["main"]], fixed)


def validate(runner, cve, f_diff, repro_row, reruns):
    """(valid, details). Every ordinary test and the PoV pass in every rerun."""
    try:
        h = runner.prepare(cve, "vulnerable", f_diff)
    except ApplyError as exc:
        return False, {"stage": "apply", "error": str(exc)[:200]}
    except BuildError as exc:
        return False, {"stage": "build", "error": str(exc)[:200]}
    try:
        ordinary, pov = repro_row["ordinary_tests"], repro_row["pov_tests"]
        screen = runner.run_tests(h, scope="full")
        if not screen.completed or any(screen.outcome(t) != "pass" for t in ordinary):
            return False, {"stage": "screening", "completed": screen.completed}
        runs = []
        for i in range(1, reruns + 1):
            r = runner.run_tests(h, scope="full")
            ok = r.completed and all(r.outcome(t) == "pass" for t in ordinary + pov)
            runs.append(ok)
    finally:
        runner.release(h)
    return all(runs), {"stage": "reruns", "passed": sum(runs), "of": reruns}


def rubric(runner, cve, v_diff, f_diff, target):
    files = runner.read_files(cve, sorted(set(difftools.changed_lines(v_diff)) |
                                          set(difftools.changed_lines(f_diff))))
    v_post = difftools.apply(files, v_diff)
    f_post = difftools.apply(files, f_diff)
    changed = comments = 0
    vf_parts = []
    for p in sorted(set(v_post) | set(f_post)):
        a, b = v_post.get(p, ""), f_post.get(p, "")
        add, rem = difftools.line_delta(a, b)
        changed += add + rem
        comments += difftools.added_comment_lines(a, b)
        if a != b:
            vf_parts.append(synthworld.unified(p, a, b))
    flags = []
    if changed > target:
        flags.append(f"changed_lines>{target}")
    if comments:
        flags.append("added_comments")
    return changed, comments, flags, "".join(vf_parts)


def run(cfg, runner, split_name, runs_dir):
    """Ingest (or, in synthetic mode, write) and validate twins in correction order."""
    from .. import logs
    from .split import assert_accessible

    sel = sorted((r for r in logs.read(runs_dir / logs.FILES["selection"])
                  if r["split"] == split_name), key=lambda r: r["correction_order"])
    done = logs.latest((r for r in logs.read(runs_dir / logs.FILES["siblings"])
                        if r["kind"] == "sibling"), "pair_id")
    gens = logs.latest((r for r in logs.read(runs_dir / logs.FILES["attempts"])
                        if r["kind"] == "generation"), "attempt_id")
    repro = logs.latest(logs.read(runs_dir / logs.FILES["reproduction"]), "cve")
    method = cfg["sibling"]["method"]
    in_dir = cfg["_root"] / cfg["sibling"]["input_dir"]
    world = synthworld.world_for(cfg) if cfg["mode"] == "synthetic" else None
    out, stop = [], None

    def log(row):
        """Every row is written the moment it exists (validation takes hours)."""
        logs.append(runs_dir / logs.FILES["siblings"], [row])
        out.append(row)
    for s in sel:
        prev = done.get(s["pair_id"])
        if prev and prev["status"] in ("valid", "infeasible"):
            continue
        assert_accessible(cfg, s["cve"], "correction")
        v_diff = gens[s["attempt_id"]]["diff_text"]
        base = {k: s[k] for k in ("pair_id", "cve", "cluster", "split", "generator", "block",
                                  "correction_order")}
        declared_infeasible = False
        draft = None
        if world is None and method == "openweight_model":
            if prev and prev["status"] == "invalid":
                continue  # one draft per pair, never re-drawn
            if prev and prev["status"] == "drafted":
                f_diff, draft = prev["f_diff_text"], prev.get("draft")   # validate the logged draft
            else:
                f_diff, draft = model_author(cfg, runner, s["cve"], v_diff)
                if f_diff is None and draft.get("retry"):
                    continue
                row = {"kind": "sibling", **base, "method": method,
                       "status": "drafted" if f_diff is not None else "invalid",
                       "f_diff_sha": difftools.sha(f_diff) if f_diff else None,
                       "f_diff_text": f_diff, "vf_changed_lines": None,
                       "added_comment_lines": None, "rubric_flags": [],
                       "validation": None if f_diff else {"stage": "draft"}, "draft": draft}
                log(row)   # logged before validation: a crash never re-draws this pair
                if f_diff is None:
                    continue
        elif world is not None:
            f_diff = synthetic_author(world, s["cve"], v_diff, s["pair_id"])
            declared_infeasible = f_diff is None
        else:
            p = pathlib.Path(in_dir) / f"{s['pair_id']}.diff"
            declared_infeasible = (pathlib.Path(in_dir) / f"{s['pair_id']}.infeasible").is_file()
            f_diff = p.read_text() if p.is_file() else None
            if f_diff is None and not declared_infeasible:
                stop = s["correction_order"]  # the author has not got this far yet
                break
            if (not declared_infeasible and prev and f_diff is not None
                    and prev.get("f_diff_sha") == difftools.sha(f_diff)):
                continue  # the same invalid F again: wait for a corrected file
        if declared_infeasible:
            log({"kind": "sibling", **base, "method": method, "status": "infeasible",
                 "f_diff_sha": None, "f_diff_text": None, "vf_changed_lines": None,
                 "added_comment_lines": None, "rubric_flags": [], "validation": None})
            continue
        valid, details = validate(runner, s["cve"], f_diff, repro[s["cve"]], cfg["design"]["reruns"])
        changed, comments, flags, vf = rubric(runner, s["cve"], v_diff, f_diff,
                                              cfg["caps"]["sibling_target_lines"])
        row = {"kind": "sibling", **base, "method": method,
               "status": "valid" if valid else "invalid",
               "f_diff_sha": difftools.sha(f_diff), "f_diff_text": f_diff, "vf_diff": vf,
               "vf_changed_lines": changed, "added_comment_lines": comments,
               "rubric_flags": flags, "validation": details}
        if draft is not None:
            row["draft"] = draft
        log(row)
    corrected = len([r for r in out if r["status"] == "valid"]) + sum(
        1 for r in done.values() if r["split"] == split_name and r["status"] == "valid")
    log({"kind": "sibling_stop", "split": split_name,
         "stopped_at_order": stop, "pairs_corrected": corrected})
    return out
