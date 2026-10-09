"""WP2: the nine-model synthetic world plants the structure the analysis must find."""

import statistics

import pytest

from hp import providers, schema, study_config as S, synthworld
from hp.schema import OK, SCHEMA_INVALID, TIMEOUT, TRUNCATED
from tests.study.helpers import make_study_dir

CFG = {"timeout_s": 5, "temperature": 0.7, "top_p": 1.0, "max_tokens": 50, "max_attempts": 4}


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    d = make_study_dir(tmp_path_factory.mktemp("w"))
    cfg = S.load(d / "study.synthetic.jsonc")
    return cfg, synthworld.world_for(cfg)


def _spec(cfg, world, ref, ctx, key):
    return {**cfg["models"][ref], "_ref": ref, "_world": world, "_context": ctx, "_call_key": key}


def _rate(cfg, world, ref, gen, state="V", n=600):
    approvals = 0
    for i in range(n):
        ctx = {"cve": "c", "generator": gen, "state": state, "pair_id": f"p{i}", "trial": 1}
        rec = providers.call_once(_spec(cfg, world, ref, ctx, f"k{i}"), "prompt", CFG, schema.REVIEW_V13)
        approvals += rec["status"] == OK and rec["decision"] != "abstain" and rec["risk"] <= 50
    return approvals / n


def test_all_nine_models_answer_with_a_v13_verdict(setup):
    cfg, world = setup
    for ref in S.ALL_MODELS:
        ctx = {"cve": "c", "generator": "A", "state": "F", "pair_id": "p", "trial": 2}
        rec = providers.call_with_retries(_spec(cfg, world, ref, ctx, f"key-{ref}"), "x", CFG,
                                          contract=schema.REVIEW_V13, sleep=lambda s: None)
        assert rec[-1]["status"] in (OK, SCHEMA_INVALID, TRUNCATED, TIMEOUT)


def test_behaviour_never_depends_on_the_prompt_text(setup):
    cfg, world = setup
    ctx = {"cve": "c", "generator": "B", "state": "V", "pair_id": "p9", "trial": 1}
    a = providers.call_once(_spec(cfg, world, "b", ctx, "k"), "one prompt", CFG, schema.REVIEW_V13)
    b = providers.call_once(_spec(cfg, world, "b", ctx, "k"), "another prompt", CFG, schema.REVIEW_V13)
    assert (a["status"], a.get("risk")) == (b["status"], b.get("risk"))


def test_same_model_blind_spot_is_planted(setup):
    cfg, world = setup
    own = _rate(cfg, world, "A", "A")
    cross = statistics.mean([_rate(cfg, world, "A", "B"), _rate(cfg, world, "A", "C")])
    assert own - cross > 0.08


def test_failures_are_transient_or_persistent(setup):
    cfg, world = setup
    seen_retry_success = seen_unresolved = False
    for i in range(3000):
        ctx = {"cve": "c", "generator": "A", "state": "V", "pair_id": f"p{i}", "trial": 1}
        recs = providers.call_with_retries(_spec(cfg, world, "a", ctx, f"f{i}"), "x", CFG,
                                           contract=schema.REVIEW_V13, sleep=lambda s: None)
        if len(recs) > 1 and recs[-1]["status"] == OK:
            seen_retry_success = True
        if len(recs) == 4 and recs[-1]["status"] == TIMEOUT:
            seen_unresolved = True
    assert seen_retry_success and seen_unresolved


def test_generation_repeats_variants_so_dedup_has_work(setup):
    cfg, world = setup
    cve = next(c for c, v in world.cves.items() if v["split"] == "development")
    texts = [world.generation_text(cve, "A", f"gen|{cve}|A|{k}") for k in range(10)]
    assert len(set(texts)) < 10
    assert any("```diff" in t for t in texts)


def test_generators_write_different_patches(setup):
    cfg, world = setup
    cve = next(iter(world.cves))
    a = {world.generation_text(cve, "A", f"g{k}") for k in range(20)}
    x = {world.generation_text(cve, "X", f"g{k}") for k in range(20)}
    assert not (a & x - {"I am not able to produce a patch for this change."})


def test_world_respects_the_split_and_the_limits(setup):
    cfg, world = setup
    limits = cfg["synthetic_world"]["cve_limit"]
    for name in ("development", "test"):
        n = sum(len(v) for v in world.split[name].values())
        assert 0 < n <= limits[name]
    assert {v["split"] for v in world.cves.values()} == {"development", "test"}
