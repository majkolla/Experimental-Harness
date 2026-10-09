"""WP1: the study config and its refusal conditions (the gauntlet)."""

import json

import pytest

from hp import study_config as S
from hp.config import ConfigError
from tests.study.helpers import ROOT, edit, make_study_dir, pin_all, read_cfg


@pytest.fixture
def sdir(tmp_path):
    return make_study_dir(tmp_path)


def _live_pinned(sdir):
    return edit(sdir / "study.jsonc", pin_all)


def test_shipped_synthetic_config_loads(sdir):
    cfg = S.load(sdir / "study.synthetic.jsonc")
    assert cfg["mode"] == "synthetic"
    assert set(cfg["models"]) == set(S.ALL_MODELS)


def test_live_config_refuses_every_placeholder(sdir):
    with pytest.raises(ConfigError) as exc:
        S.load(sdir / "study.jsonc")
    msg = str(exc.value)
    assert "live mode refuses placeholder values" in msg
    for path in ("models.A.model", "models.C.snapshot", "models.X.weights_sha",
                 "prices_usd_per_mtok.b.input", "vul4j.image_digest",
                 "openweight_cost.gpu_hour_usd"):
        assert path in msg


def test_live_config_loads_once_everything_is_pinned(sdir):
    cfg = S.load(_live_pinned(sdir))
    assert cfg["mode"] == "live"


def test_a_single_remaining_placeholder_is_enough_to_refuse(sdir):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["models"]["b"].__setitem__("snapshot", S.PLACEHOLDER))
    with pytest.raises(ConfigError, match=r"models\.b\.snapshot"):
        S.load(p)


def test_synthetic_mode_refuses_a_real_provider(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["models"]["A"].__setitem__("provider", "anthropic"))
    with pytest.raises(ConfigError, match="can never make a paid call"):
        S.load(p)


def test_live_mode_refuses_synthetic_providers_and_the_mock_runner(sdir):
    p = _live_pinned(sdir)

    def f(o):
        o["models"]["a"]["provider"] = "synthetic_world"
        o["vul4j"]["runner"] = "mock"

    edit(p, f)
    with pytest.raises(ConfigError) as exc:
        S.load(p)
    assert "not allowed in live mode" in str(exc.value)
    assert "vul4j.runner must be 'container'" in str(exc.value)


def test_missing_values_are_refused_never_defaulted(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o.pop("acceptance_target"))
    with pytest.raises(ConfigError, match="no silent defaults.*acceptance_target"):
        S.load(p)


def test_extension_enabled_must_be_explicit(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["extension"].pop("enabled"))
    with pytest.raises(ConfigError, match="extension.enabled must be set explicitly"):
        S.load(p)


def test_model_set_follows_the_extension_flag(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["models"].pop("Y"))
    with pytest.raises(ConfigError, match=r"models missing: \['Y'\]"):
        S.load(p)

    def off(o):
        o["extension"]["enabled"] = False

    edit(p, off)
    assert S.load(p)["extension"]["enabled"] is False


@pytest.mark.parametrize(
    "ref, key, value, message",
    [
        ("a", "roles", ["generator", "reviewer"], "a cheap model is a reviewer only"),
        ("B", "family", 1, "the design fixes 2"),
        ("X", "tier", "cheap", "the design fixes 'open'"),
        ("C", "roles", ["reviewer"], "roles must be generator and reviewer"),
    ],
)
def test_roles_families_and_tiers_are_fixed_by_the_design(sdir, ref, key, value, message):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["models"][ref].__setitem__(key, value))
    with pytest.raises(ConfigError, match=message):
        S.load(p)


def test_strong_and_cheap_model_of_a_family_share_a_provider(sdir):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["models"]["b"].__setitem__("provider", "anthropic"))
    with pytest.raises(ConfigError, match="family 2 but use different providers"):
        S.load(p)


@pytest.mark.parametrize(
    "key, value, message",
    [
        ("gen_temperature", 0, "trials are copies"),
        ("review_temperature", -1, "trials are copies"),
        ("review_top_p", 1.5, r"review_top_p must be in \(0, 1\]"),
        ("reasoning", "", "sampling.reasoning must be set"),
    ],
)
def test_sampling_rules(sdir, key, value, message):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["sampling"].__setitem__(key, value))
    with pytest.raises(ConfigError, match=message):
        S.load(p)


def test_omitting_a_sampling_parameter_needs_a_recorded_deviation(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["models"]["B"].__setitem__("send_temperature", False))
    with pytest.raises(ConfigError, match="needs a non-empty deviation_note"):
        S.load(p)
    edit(p, lambda o: o["models"]["B"].__setitem__("deviation_note", "provider rejects temperature with reasoning on"))
    S.load(p)


def test_three_trials_and_a_two_of_three_gate_are_required(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["design"].__setitem__("trials", 5))
    with pytest.raises(ConfigError, match="36 = 3! x 3!"):
        S.load(p)


def test_max_attempts_is_one_call_plus_at_most_three_retries(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o.__setitem__("max_attempts", 6))
    with pytest.raises(ConfigError, match="max_attempts must be 1..4"):
        S.load(p)


def test_live_mode_enforces_the_bootstrap_draw_counts(sdir):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["bootstrap"].__setitem__("confirm_draws", 500))
    with pytest.raises(ConfigError, match="confirm_draws=500 below the live minimum 10000"):
        S.load(p)


def test_rq2o_mode_and_promotion_margins(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["extension"].__setitem__("rq2o_mode", "always"))
    with pytest.raises(ConfigError, match="rq2o_mode must be one of"):
        S.load(p)


def test_the_registered_split_cannot_change(sdir):
    split = sdir / "docs" / "spec" / "proposed_split.json"
    obj = json.loads(split.read_text())
    obj["test"]["apache/camel"].append("VUL4J-26")
    split.write_text(json.dumps(obj))
    with pytest.raises(ConfigError, match="registered split must not change"):
        S.load(sdir / "study.synthetic.jsonc")


def test_prompt_slots_are_required(sdir):
    (sdir / "prompts" / "review_v13.md").write_text("no slots here")
    with pytest.raises(ConfigError, match=r"prompts.review is missing the slot \{\{DIFF\}\}"):
        S.load(sdir / "study.synthetic.jsonc")


def test_experiment_b_takes_cheap_reviewers_only(sdir):
    p = sdir / "study.synthetic.jsonc"
    edit(p, lambda o: o["experiment_b"].__setitem__("reviewers", ["a", "X"]))
    with pytest.raises(ConfigError, match="cheap reviewers only"):
        S.load(p)


def test_pin_rule_refuses_a_floating_alias(sdir):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["models"]["A"].update(model="test-model-latest", snapshot="test-model-latest"))
    with pytest.raises(ConfigError, match="floating alias"):
        S.load(p)


@pytest.mark.parametrize(
    "key, value, message",
    [
        ("weights_sha", "not-a-sha", "64-hex SHA-256"),
        ("precision", "fp4", "not in allowed_precisions"),
        ("serving_stack", " ", "serving_stack is empty"),
        ("num_ctx", 4096, "must exceed review input"),
    ],
)
def test_open_weight_pins(sdir, key, value, message):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["models"]["Z"].__setitem__(key, value))
    with pytest.raises(ConfigError, match=message):
        S.load(p)


@pytest.mark.parametrize("name", ["study.jsonc", "study.synthetic.jsonc"])
def test_every_spec_default_carries_a_default_comment(name):
    text = (ROOT / name).read_text()
    found = S.default_annotations(text)
    for key in S.DEFAULT_KEYS:
        assert key in found, f"{name}: {key} not present"
        assert "default" in found[key], f"{name}: {key} has no [default ...] comment"


def test_comments_never_change_the_hash_and_urls_survive():
    text = '{"a": "http://x//y", /* c */ "b": 1} // tail\n'
    obj = S.parse_jsonc(text)
    assert obj == {"a": "http://x//y", "b": 1}
    assert S.config_hash(obj) == S.config_hash(json.loads('{"b":1,"a":"http://x//y"}'))


def test_config_hash_ignores_the_freeze_block(sdir):
    a = read_cfg(sdir / "study.synthetic.jsonc")
    b = json.loads(json.dumps(a))
    b["freeze"] = {"frozen": True, "config_sha256": "x", "code_sha256": "y"}
    assert S.config_hash(a) == S.config_hash(b)
    b["seed"] = 1
    assert S.config_hash(a) != S.config_hash(b)


def test_freeze_round_trip_and_every_way_to_break_it(tmp_path, monkeypatch):
    d = make_study_dir(tmp_path, with_code=True)
    monkeypatch.setattr(S, "CODE_ROOT", d)  # hash the copy, so editing it is a code change
    cfg_path = d / "study.synthetic.jsonc"
    cfg = S.load(cfg_path)
    rd = S.runs_dir(cfg)
    rd.mkdir(parents=True)
    (rd / "thresholds.json").write_text('{"A": 40}')

    rec = S.freeze(cfg_path, ["thresholds.json"])
    cfg = S.load(cfg_path)
    assert cfg["freeze"]["frozen"] is True
    assert S.freeze_status(cfg) == (True, "frozen")
    assert rec["config_sha256"] == cfg["_config_sha256"]

    # a frozen artefact changes
    (rd / "thresholds.json").write_text('{"A": 41}')
    with pytest.raises(ConfigError, match="frozen artefact thresholds.json"):
        S.load(cfg_path)
    (rd / "thresholds.json").write_text('{"A": 40}')
    S.load(cfg_path)

    # the code changes
    (d / "hp" / "estimators.py").write_text("# edited after freeze\n")
    with pytest.raises(ConfigError, match="code changed since freeze"):
        S.load(cfg_path)


def test_freeze_detects_a_config_edit(tmp_path):
    d = make_study_dir(tmp_path, with_code=True)
    cfg_path = d / "study.synthetic.jsonc"
    S.runs_dir(S.load(cfg_path)).mkdir(parents=True)
    S.freeze(cfg_path, [])
    text = cfg_path.read_text().replace('"seed": 20260930', '"seed": 20260931')
    cfg_path.write_text(text)
    with pytest.raises(ConfigError, match="config changed since freeze"):
        S.load(cfg_path)


def test_the_code_hash_covers_the_running_package_not_the_config_folder(tmp_path):
    d = make_study_dir(tmp_path)  # no hp/ next to this config
    assert any(rel.startswith("hp/") for _, rel in S.code_files(d))
    assert S.CODE_ROOT == ROOT


def test_freezing_again_after_test_split_work_is_refused(tmp_path):
    d = make_study_dir(tmp_path, with_code=True)
    cfg_path = d / "study.synthetic.jsonc"
    rd = S.runs_dir(S.load(cfg_path))
    rd.mkdir(parents=True)
    S.freeze(cfg_path, [])
    S.freeze(cfg_path, [])  # no test work yet: allowed, and recorded in the history
    assert len((rd / "freeze_history.jsonl").read_text().splitlines()) == 2
    (rd / "reviews.jsonl").write_text(json.dumps({"kind": "review", "split": "test"}) + "\n")
    with pytest.raises(ConfigError, match="already hold test-split work"):
        S.freeze(cfg_path, [])


def test_edited_advisories_break_the_freeze(tmp_path):
    d = make_study_dir(tmp_path, with_code=True)
    cfg_path = d / "study.synthetic.jsonc"
    cfg = S.load(cfg_path)
    adv = cfg["_root"] / cfg["paths"]["inputs"] / "advisories"
    adv.mkdir(parents=True)
    (adv / "VUL4J-2.json").write_text('{"cwe": "CWE-22", "summary": "x"}')
    S.runs_dir(cfg).mkdir(parents=True, exist_ok=True)
    S.freeze(cfg_path, [])
    S.load(cfg_path)
    (adv / "VUL4J-2.json").write_text('{"cwe": "CWE-22", "summary": "edited"}')
    with pytest.raises(ConfigError, match="advisories"):
        S.load(cfg_path)


def test_live_mode_requires_identity_terms_for_the_leak_scan(sdir):
    p = _live_pinned(sdir)
    edit(p, lambda o: o["models"]["c"].__setitem__("identity_terms", []))
    with pytest.raises(ConfigError, match="identity_terms must be a non-empty list"):
        S.load(p)

