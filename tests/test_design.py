"""The design guarantees, and the failure modes they exist to catch."""

import collections

import pytest

from hp import config, design


def test_schedule_size(write_cfg):
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    assert len(calls) == 4 * 4 * 2 * 6 * 3  # tasks x panels x regimes x reps x n


def test_b1_b2_b3_hold(write_cfg):
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    assert design.assert_balanced(calls, cfg)


def test_shared_arm_coincides_and_diverse_arm_does_not(write_cfg):
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    by_rep = collections.defaultdict(set)
    for c in calls:
        by_rep[(c["task"], c["panel"], c["regime"], c["replicate"])].add(c["packet_id"])
    for (_, _, regime, _), pkts in by_rep.items():
        assert len(pkts) == (1 if regime == "shared" else 3)


def test_both_arms_use_every_packet_equally_often(write_cfg):
    """B1 across regimes: the arms differ in coupling, not in context quality."""
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    counts = collections.Counter(
        (c["task"], c["regime"], c["packet_id"]) for c in calls
    )
    per_regime = collections.defaultdict(set)
    for (task, regime, _), v in counts.items():
        per_regime[(task, regime)].add(v)
    assert all(len(v) == 1 for v in per_regime.values())
    assert len({next(iter(v)) for v in per_regime.values()}) == 1


def test_channel_is_model_stable_but_seat_is_not(write_cfg):
    """The distinction the first implementation collapsed.

    `for seat, ref in enumerate(seats)` welds model identity to seat position.
    Under rotation, a channel keeps its model across replicates while visiting
    every seat, which is what B3 requires.
    """
    cfg = config.load(write_cfg())
    calls = [c for c in design.build_schedule(cfg) if c["panel"] == "ABC"]

    by_channel = collections.defaultdict(set)
    by_seat = collections.defaultdict(set)
    for c in calls:
        by_channel[c["channel"]].add(c["model_ref"])
        by_seat[c["seat"]].add(c["model_ref"])
    assert all(len(v) == 1 for v in by_channel.values()), "channel must pin the model"
    assert all(len(v) == 3 for v in by_seat.values()), "every model must visit every seat"


def test_seat_welded_design_fails_b3(write_cfg):
    """Regression guard: the natural implementation must not pass the checks."""
    cfg = config.load(write_cfg())
    bad = []
    for task in cfg["_tasks"]:
        for panel, seats in cfg["panels"].items():
            for regime in cfg["regimes"]:
                for rep in range(cfg["replicates"]):
                    for seat, ref in enumerate(seats):  # the bug
                        pkt = design.packet_index(regime, rep, seat, 6, 3)
                        bad.append(
                            {
                                "task": task.task_id,
                                "panel": panel,
                                "regime": regime,
                                "replicate": rep,
                                "seat": seat,
                                "channel": seat,
                                "model_ref": ref,
                                "packet_index": pkt,
                            }
                        )
    with pytest.raises(design.BalanceError, match="B3"):
        design.assert_balanced(bad, cfg)


def test_unbalanced_packet_bank_is_caught(write_cfg):
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    calls[0]["packet_index"] = (calls[0]["packet_index"] + 1) % 6
    with pytest.raises(design.BalanceError):
        design.assert_balanced(calls, cfg)


def test_execution_order_is_shuffled_not_grouped(write_cfg):
    """B4: a panel is a grouping in the design, not an event in time."""
    cfg = config.load(write_cfg())
    calls = design.build_schedule(cfg)
    adjacent = sum(
        calls[i]["panel_key"] == calls[i + 1]["panel_key"] for i in range(len(calls) - 1)
    )
    n_panels = len({c["panel_key"] for c in calls})
    grouped = 2 * n_panels  # what a per-panel launch would produce
    assert adjacent < grouped / 10, (adjacent, grouped)
    assert [c["dispatch_index"] for c in calls] == list(range(len(calls)))


def test_schedule_is_deterministic_given_the_seed(write_cfg):
    cfg = config.load(write_cfg())
    a = [c["call_id"] for c in design.build_schedule(cfg)]
    b = [c["call_id"] for c in design.build_schedule(config.load(write_cfg()))]
    assert a == b


def test_cost_table_reports_clusters_not_calls(write_cfg):
    cfg = config.load(write_cfg())
    t = design.cost_table(cfg, design.build_schedule(cfg))
    assert t["calls"] == 576
    assert t["independent_clusters"] == 2  # C1, C2 -- siblings share a cluster
