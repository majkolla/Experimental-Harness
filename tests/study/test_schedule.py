"""The crossed review schedule at the spec's maxima (sections 11.4, 13, 17)."""

import collections
import json

import pytest

from hp import study_config as S
from hp.bank.select import candidate_id
from hp.review import schedule
from tests.study.helpers import ROOT, read_cfg

SPLIT = json.loads((ROOT / "docs" / "spec" / "proposed_split.json").read_text())


def _cfg(enabled=True, paid=True):
    cfg = read_cfg(ROOT / "study.synthetic.jsonc")
    cfg["extension"]["enabled"] = enabled
    cfg["extension"]["paid_block_on_test"] = paid
    return cfg


def _pairs(split_name, generators):
    out = []
    for cluster, cves in SPLIT[split_name].items():
        for cve in cves:
            for g in generators:
                pid = f"pair-{cve}-{g}"
                out.append({"pair_id": pid, "cve": cve, "cluster": cluster, "split": split_name,
                            "generator": g, "block": "core" if g in "ABC" else "extension",
                            "cand": {"V": candidate_id(pid, "V"), "F": candidate_id(pid, "F")}})
    return out


CORE = list(S.CORE_GENERATORS)
ALL = CORE + list(S.OPEN_MODELS)


@pytest.mark.parametrize("split_name, gens, enabled, expected", [
    ("development", CORE, False, 2484),     # 69 pairs x 2 states x 6 reviewers x 3 trials
    ("test", CORE, False, 6048),            # 168 pairs
    ("development", ALL, True, 7452),       # 138 pairs x 2 x 9 x 3
    ("test", ALL, True, 18144),             # 336 pairs
])
def test_schedule_sizes_at_the_maxima(split_name, gens, enabled, expected):
    pairs = _pairs(split_name, gens)
    calls = schedule.build(_cfg(enabled), pairs, split_name)
    assert len(calls) == expected
    assert len({c["call_id"] for c in calls}) == expected


def test_core_counts_inside_the_extension_schedule():
    calls = schedule.build(_cfg(True), _pairs("development", ALL), "development")
    by = collections.Counter(c["block"] for c in calls)
    assert by["core"] == 2484 and by["extension"] == 7452 - 2484


def test_experiment_b_is_at_most_1944_calls_and_development_only():
    cfg = _cfg(True)
    pairs = _pairs("development", ALL)
    calls = schedule.build(cfg, pairs, "development", blocks=(), expb=True)
    assert len(calls) == 1944  # 12 CVEs x 3 core pairs x 2 x 3 cheap x 3 packets x 3
    assert {c["reviewer"] for c in calls} == {"a", "b", "c"}
    assert {c["generator"] for c in calls} <= set(CORE)
    assert len({c["cve"] for c in calls}) == 12
    with pytest.raises(ValueError, match="development data only"):
        schedule.build(cfg, _pairs("test", CORE), "test", expb=True)


def test_core_calls_are_identical_with_and_without_the_extension():
    core_only = schedule.build(_cfg(False), _pairs("test", CORE), "test")
    with_ext = schedule.build(_cfg(True), _pairs("test", ALL), "test")
    a = {c["call_id"] for c in core_only}
    b = {c["call_id"] for c in with_ext if c["block"] == "core"}
    assert a == b


def test_paid_block_on_test_false_moves_commercial_reviewers_off_extension_test_pairs():
    test_calls = schedule.build(_cfg(True, paid=False), _pairs("test", ALL), "test")
    ext_pairs = [c for c in test_calls if c["generator"] in S.OPEN_MODELS]
    assert {c["reviewer"] for c in ext_pairs} == set(S.OPEN_MODELS)
    assert len(test_calls) == 18144 - 168 * 6 * 2 * 3
    dev_calls = schedule.build(_cfg(True, paid=False), _pairs("development", ALL), "development")
    assert len(dev_calls) == 7452


def test_every_candidate_gets_three_fresh_trials_per_reviewer():
    calls = schedule.build(_cfg(True), _pairs("development", ALL), "development")
    per = collections.Counter((c["candidate_id"], c["reviewer"]) for c in calls)
    assert set(per.values()) == {3}
    assert all(c["panel_key"] == c["candidate_id"] for c in calls)


def test_the_schedule_is_globally_shuffled_and_seeded():
    pairs = _pairs("development", CORE)
    a = schedule.build(_cfg(False), pairs, "development")
    b = schedule.build(_cfg(False), pairs, "development")
    assert [c["call_id"] for c in a] == [c["call_id"] for c in b]
    run = max_run = 1
    for x, y in zip(a, a[1:]):
        run = run + 1 if x["candidate_id"] == y["candidate_id"] else 1
        max_run = max(max_run, run)
    assert max_run < 6  # not grouped by candidate
