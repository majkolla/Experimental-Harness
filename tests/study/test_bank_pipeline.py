"""Stages 1-4 on the synthetic world: reproduction, generation, selection, twins, lock."""

import collections
import inspect
import json

import pytest

from hp import logs, study_config as S
from hp.bank import assemble, generate, reproduce, select, sibling, split, vul4j
from hp.bank.vul4j import parse_surefire
from tests.study.helpers import build_bank, synthetic_cfg


@pytest.fixture(scope="module")
def dev(tmp_path_factory):
    cfg = synthetic_cfg(tmp_path_factory.mktemp("bank"))
    runner = build_bank(cfg, "development")
    return cfg, runner, S.runs_dir(cfg)


# --- Stage 1 -------------------------------------------------------------------


def test_reproduction_rows_and_statuses(dev):
    cfg, runner, rd = dev
    rows = list(logs.read(rd / "reproduction.jsonl"))
    assert {r["cve"] for r in rows} == set(split.load_split(cfg).split_of)
    eligible = [r for r in rows if r["status"] == "eligible"]
    assert eligible
    r = eligible[0]
    assert r["ordinary_tests"] and not set(r["ordinary_tests"]) & set(r["pov_tests"])
    assert not set(r["flaky_tests"]) & set(r["ordinary_tests"])
    assert all(len(r["runs"][v]) == 10 for v in ("vulnerable", "fixed"))
    assert set(r["signature"]) == set(r["pov_tests"])


@pytest.mark.parametrize("status", ["build_fail", "pov_unstable", "suite_unstable"])
def test_every_ineligible_status_is_produced(tmp_path, status):
    def force(o):
        o["synthetic_world"]["ineligible_share"] = {status: 1.0}
        o["synthetic_world"]["cve_limit"] = {"development": 2, "test": 1}

    cfg = synthetic_cfg(tmp_path, edits=force)
    rows = reproduce.run(cfg, vul4j.runner_for(cfg), S.runs_dir(cfg))
    assert rows and {r["status"] for r in rows} == {status}


def test_status_rule():
    assert reproduce.status_for(True, True, ["t"]) == "eligible"
    assert reproduce.status_for(False, True, ["t"]) == "suite_unstable"
    assert reproduce.status_for(True, True, []) == "suite_unstable"
    assert reproduce.status_for(True, False, ["t"]) == "pov_unstable"


def test_timing_pilot_reports_wall_clock_per_run(dev):
    cfg, runner, rd = dev
    cve = split.load_split(cfg).cves("test")[0]  # reproduction-type work: allowed on test
    rows = reproduce.timing_pilot(runner, [cve], runs=3, reruns=10)
    assert {r["version"] for r in rows} == {"vulnerable", "fixed"}
    assert all(len(r["run_wall_s"]) == 3 and r["projected_stage1_s"] > 0 for r in rows)


def test_surefire_reports_give_signatures():
    xml = """<testsuite name="p.T">
      <testcase classname="p.T" name="ok"/>
      <testcase classname="p.T" name="pov"><failure type="java.lang.AssertionError"
        message="expected  exception">java.lang.AssertionError: expected exception
        at org.junit.Assert.fail(Assert.java:89)
        at p.T.pov(T.java:42)</failure></testcase>
      <testcase classname="p.T" name="skip"><skipped/></testcase>
    </testsuite>"""
    res = parse_surefire([xml])
    assert res["p.T#ok"].passed and res["p.T#skip"].outcome == "skipped"
    sig = res["p.T#pov"].signature
    assert sig == {"type": "java.lang.AssertionError", "message": "expected exception",
                   "frame": "p.T.pov(T.java)"}


# --- Stage 2 ---------------------------------------------------------------------


def test_ten_attempts_per_cell_for_six_generators(dev):
    cfg, runner, rd = dev
    gens = [r for r in logs.read(rd / "attempts.jsonl") if r["kind"] == "generation"]
    cells = collections.Counter((r["cve"], r["generator"]) for r in gens)
    assert set(c[1] for c in cells) == {"A", "B", "C", "X", "Y", "Z"}
    assert set(cells.values()) == {10}
    assert {r["block"] for r in gens if r["generator"] in "XYZ"} == {"extension"}


def test_generator_input_has_no_channel_for_the_pov(dev):
    params = list(inspect.signature(generate.generation_input).parameters)
    assert params == ["template", "advisory", "files"]
    cfg, runner, rd = dev
    cve = split.load_split(cfg).cves("development")[0]
    text = generate.generation_input(cfg["_prompts"]["generate"]["text"],
                                     generate.advisory_for(cfg, cve),
                                     runner.read_files(cve, runner.human_files(cve)))
    meta = runner.metadata(cve)
    for forbidden in meta["pov_tests"] + meta["pov_output"] + [cve]:
        assert forbidden not in text
        assert forbidden.split("#")[-1] not in text


def test_generation_resume_adds_nothing(dev):
    cfg, runner, rd = dev
    before = sum(1 for _ in logs.read(rd / "attempts.jsonl"))
    s = generate.run(cfg, runner, "development", rd / "attempts.jsonl")
    assert s["dispatched"] == 0
    assert sum(1 for _ in logs.read(rd / "attempts.jsonl")) == before


def test_every_attempt_is_kept_and_classified(dev):
    cfg, runner, rd = dev
    rows = list(logs.read(rd / "attempts.jsonl"))
    gen_ids = {r["attempt_id"] for r in rows if r["kind"] == "generation"}
    cls = [r for r in rows if r["kind"] == "classification"]
    assert {r["attempt_id"] for r in cls} == gen_ids
    assert {r["class"] for r in cls} <= set(("apply_fail", "build_fail", "regression_fail",
                                             "blocked", "near_miss", "indeterminate"))
    assert "near_miss" in {r["class"] for r in cls}


# --- Stage 4 selection ----------------------------------------------------------------


def test_one_pair_per_cell_with_inclusion_probability(dev):
    cfg, runner, rd = dev
    sel = list(logs.read(rd / "selection.jsonl"))
    cells = collections.Counter((r["cve"], r["generator"]) for r in sel)
    assert set(cells.values()) == {1}
    for r in sel:
        assert r["inclusion_prob"] == pytest.approx(1 / r["n_distinct"])
        assert r["n_distinct"] <= r["n_near_miss"]
        assert not any(g in r["pair_id"] for g in ("VUL4J", r["cve"]))


def test_dedup_and_seeded_choice():
    diff = "--- a/x\n+++ b/x\n@@ -1,1 +1,2 @@\n x\n+{}\n"
    rows = [{"cve": "C", "generator": "A", "attempt_id": f"a{i}", "cluster": "o/r",
             "split": "development", "diff_sha": str(i),
             "diff_text": diff.format("y" if i < 3 else "z" + " " * i)} for i in range(5)]
    sel = select.select_pairs(rows, seed=1)
    assert len(sel) == 1 and sel[0]["n_distinct"] == 2 and sel[0]["inclusion_prob"] == 0.5
    assert select.select_pairs(rows, seed=1) == sel


def test_selection_does_not_change_when_review_outcomes_are_permuted(dev, tmp_path):
    """Section 18.4: selection is independent of reviews."""
    cfg, runner, rd = dev
    assert "review" not in " ".join(inspect.signature(select.select_pairs).parameters)
    rows = list(logs.read(rd / "attempts.jsonl"))
    cls = {r["attempt_id"]: r for r in rows if r["kind"] == "classification"}
    nm = [r for r in rows if r["kind"] == "generation" and cls[r["attempt_id"]]["class"] == "near_miss"]
    base = select.select_pairs(nm, cfg["seed"])
    fake_reviews = [{"pair_id": s["pair_id"], "approve": i % 2} for i, s in enumerate(base)]
    (rd / "reviews.jsonl").write_text("\n".join(json.dumps(r) for r in fake_reviews[::-1]) + "\n")
    again = select.run(cfg, "development", rd)
    assert [r["pair_id"] for r in again] == [r["pair_id"] for r in base]
    (rd / "reviews.jsonl").unlink()


def test_correction_order_core_first_and_seeded(dev):
    cfg, runner, rd = dev
    sel = sorted(logs.read(rd / "selection.jsonl"), key=lambda r: r["correction_order"])
    blocks = [r["block"] for r in sel]
    assert blocks == sorted(blocks, key=lambda b: b != "core")
    assert sorted(r["correction_order"] for r in sel) == list(range(len(sel)))


# --- Stage 3 twins ----------------------------------------------------------------------


def test_twins_are_validated_and_measured(dev):
    cfg, runner, rd = dev
    sib = [r for r in logs.read(rd / "siblings.jsonl") if r["kind"] == "sibling"]
    valid = [r for r in sib if r["status"] == "valid"]
    assert valid
    for r in valid:
        assert r["validation"]["passed"] == 10
        assert r["vf_changed_lines"] == 3 and r["added_comment_lines"] == 0
        assert r["rubric_flags"] == []
    stops = [r for r in logs.read(rd / "siblings.jsonl") if r["kind"] == "sibling_stop"]
    assert stops and stops[-1]["stopped_at_order"] is None


def test_bank_holds_only_pairs_with_a_valid_twin(dev):
    cfg, runner, rd = dev
    pairs = assemble.pairs(rd, "development")
    sib = logs.latest((r for r in logs.read(rd / "siblings.jsonl") if r["kind"] == "sibling"), "pair_id")
    assert pairs and all(sib[p["pair_id"]]["status"] == "valid" for p in pairs)
    assert all(p["cand"]["V"] != p["cand"]["F"] for p in pairs)


def test_live_author_stops_and_invalid_twins_can_be_replaced(tmp_path, dev):
    cfg, runner, rd = dev
    sel = sorted(logs.read(rd / "selection.jsonl"), key=lambda r: r["correction_order"])
    live = dict(cfg)
    live["mode"] = "live_test"  # not synthetic: read author files
    live["_root"] = tmp_path
    live["sibling"] = {"method": "author", "input_dir": "sib"}
    (tmp_path / "sib").mkdir()
    out = tmp_path / "runs"
    out.mkdir()
    for name in ("selection.jsonl", "attempts.jsonl", "reproduction.jsonl"):
        (out / name).write_text((rd / name).read_text())
    gens = logs.latest((r for r in logs.read(rd / "attempts.jsonl") if r["kind"] == "generation"), "attempt_id")
    first, second = sel[0], sel[1]
    good = sibling.synthetic_author(vul4j_world(cfg), first["cve"], gens[first["attempt_id"]]["diff_text"], "force")
    (tmp_path / "sib" / f"{first['pair_id']}.diff").write_text(good or "")
    (tmp_path / "sib" / f"{second['pair_id']}.diff").write_text(gens[second["attempt_id"]]["diff_text"])
    rows = sibling.run(live, runner, "development", out)
    by = {r.get("pair_id"): r for r in rows}
    assert by[first["pair_id"]]["status"] == "valid"
    assert by[second["pair_id"]]["status"] == "invalid"  # V itself is not a fix
    assert rows[-1]["kind"] == "sibling_stop" and rows[-1]["stopped_at_order"] == sel[2]["correction_order"]
    (tmp_path / "sib" / f"{second['pair_id']}.infeasible").write_text("")
    rows = sibling.run(live, runner, "development", out)
    assert {r.get("pair_id"): r for r in rows}[second["pair_id"]]["status"] == "infeasible"


def vul4j_world(cfg):
    from hp import synthworld

    w = synthworld.world_for(cfg)

    class Always:
        def __getattr__(self, k):
            return getattr(w, k)

        def sibling_feasible(self, cve, key):
            return True

    return Always()


# --- the test-set lock ---------------------------------------------------------------------


def test_test_split_is_locked_until_freeze(dev):
    """Section 18.4: the test split is inaccessible without the freeze flag."""
    cfg, runner, rd = dev
    test_cve = split.load_split(cfg).cves("test")[0]
    dev_cve = split.load_split(cfg).cves("development")[0]
    for purpose in ("generation", "correction", "review", "selection"):
        with pytest.raises(split.SplitLockError, match="locked until the study is frozen"):
            split.assert_accessible(cfg, test_cve, purpose)
        assert split.assert_accessible(cfg, dev_cve, purpose) == "development"
    assert split.assert_accessible(cfg, test_cve, "reproduction") == "test"
    with pytest.raises(split.SplitLockError):
        generate.run(cfg, runner, "test", rd / "attempts.jsonl")
    with pytest.raises(split.SplitLockError, match="not in the registered split"):
        split.assert_accessible(cfg, "VUL4J-999", "review")


def test_the_lock_opens_only_with_a_valid_freeze(tmp_path):
    cfg = synthetic_cfg(tmp_path, with_code=True)
    test_cve = split.load_split(cfg).cves("test")[0]
    S.freeze(cfg["_path"], [])
    cfg = S.load(cfg["_path"])
    assert split.assert_accessible(cfg, test_cve, "review") == "test"
    # an edited config after freeze is refused at load, so the lock never opens
    text = cfg["_path"].read_text().replace('"workers": 8', '"workers": 7')
    cfg["_path"].write_text(text)
    with pytest.raises(S.ConfigError, match="config changed since freeze"):
        S.load(cfg["_path"])


def test_container_runner_composes_pinned_offline_commands(tmp_path):
    """The real runner is unverified offline; this pins how its commands are built."""
    seen = []

    def fake(argv, timeout=None):
        seen.append(argv)
        return 0, "", ""

    cfg = {"vul4j": {"image": "img", "image_digest": "sha256:" + "ab" * 32, "cli": "vul4j",
                     "workdir": str(tmp_path)}}
    r = vul4j.ContainerVul4J(cfg, run=fake)
    h = r.prepare("VUL4J-1", "fixed", diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    run = r.run_tests(h, tests=["p.T#pov"])
    assert all(a[:5] == ["docker", "run", "--rm", "--network", "none"] for a in seen)
    assert all(f"img@sha256:{'ab' * 32}" in a for a in seen)
    cmds = [" ".join(a[a.index(f"img@sha256:{'ab' * 32}") + 1:]) for a in seen]
    assert cmds[0].startswith("vul4j checkout --id VUL4J-1")
    assert any(c.startswith("vul4j apply --version human_patch") for c in cmds)
    assert any(c.startswith("git -C /ws/src apply") for c in cmds)
    assert any(c.startswith("vul4j compile") for c in cmds)
    assert cmds[-1] == "vul4j test -d /ws/src --tests p.T#pov"
    assert run.completed is False  # no surefire reports were produced by the fake
