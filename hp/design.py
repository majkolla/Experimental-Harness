"""Schedule construction: a pure function of the config, auditable before spending.

Vocabulary, because two different indices are easy to conflate:

seat
    A *position* in the panel, 0..n-1. The seat determines which context
    packet the call receives.
channel
    A *fixed model identity*, 0..n-1, indexing into the panel's model list.
    Channel c is the same model in every replicate.

They are deliberately not the same thing. If seat and channel were welded
together -- as `for seat, ref in enumerate(seats)` does -- then in an ABC panel
model A would always sit in seat 0, which violates B3 and confounds model
identity with whatever the seat position carries. Rotating channels across
seats by replicate fixes that, and it is why the analysis indexes reviewers by
channel while the packet design indexes by seat.

Four guarantees, all asserted mechanically on the constructed schedule rather
than argued from the construction:

B1  Within each regime every packet is used the same number of times, *and*
    that count is equal across regimes. This is what makes shared-vs-diverse a
    contrast about coupling rather than about context quality.
B2  Within each regime every packet appears in every seat -- and in every
    channel -- equally often.
B3  In heterogeneous panels every model occupies every seat equally often.
B4  Execution order is randomised across the entire schedule, and panel-mates
    are never in flight simultaneously (the second half is enforced by the
    runner's dispatcher; see runner.eligible_order).
"""

import collections
import random


class BalanceError(AssertionError):
    """A design guarantee does not hold. Raised before any model call."""


def packet_index(regime, replicate, seat, n_packets, n_seats):
    """Cyclic packet assignment.

    diverse: seat s gets packet (r + step*s) mod P with step = P/n, so the n
             seats of one replicate hold n distinct packets, and over P
             replicates each seat has seen each packet exactly once.
    shared:  every seat of a replicate gets packet r mod P.

    Both arms therefore use each packet exactly n*R/P times in total and
    exactly R/P times per seat. The *only* difference between the arms is
    whether the three draws within a replicate coincide -- which is precisely
    the causal contrast the paper needs, with the marginal distribution of
    context quality held fixed by construction.
    """
    if regime == "shared":
        return replicate % n_packets
    if regime == "diverse":
        step = n_packets // n_seats
        return (replicate + step * seat) % n_packets
    raise ValueError(f"unknown regime {regime!r}")


def build_schedule(cfg):
    """Return the full list of call descriptors. No I/O, no network."""
    n = cfg["gate"]["n"]
    P = cfg["packets_per_task"]
    R = cfg["replicates"]
    calls = []

    for task in cfg["_tasks"]:
        for panel, seats in cfg["panels"].items():
            for regime in cfg["regimes"]:
                for rep in range(R):
                    for seat in range(n):
                        channel = (seat + rep) % n
                        ref = seats[channel]
                        pkt = packet_index(regime, rep, seat, P, n)
                        pid, _, phash = task.packets[pkt]
                        calls.append(
                            {
                                "call_id": f"{task.task_id}|{panel}|{regime}|r{rep}|s{seat}",
                                "panel_key": f"{task.task_id}|{panel}|{regime}|r{rep}",
                                "task": task.task_id,
                                "panel": panel,
                                "regime": regime,
                                "replicate": rep,
                                "seat": seat,
                                "channel": channel,
                                "model_ref": ref,
                                "packet_index": pkt,
                                "packet_id": pid,
                                "packet_hash": phash,
                                **cfg["models"][ref],
                            }
                        )

    assert_balanced(calls, cfg)

    # A panel is a grouping in the design, not an event in time. Launching a
    # panel's n reviewers together makes them share vendor cache state, load
    # and any service-side condition, manufacturing panel-level coupling that
    # is indistinguishable from the coupling under study. Interleave globally.
    random.Random(cfg["seed"]).shuffle(calls)
    for i, c in enumerate(calls):
        c["dispatch_index"] = i
    return calls


def assert_balanced(calls, cfg):
    """B1-B3, checked on the constructed schedule. Raises, never warns."""
    n = cfg["gate"]["n"]
    P = cfg["packets_per_task"]
    R = cfg["replicates"]

    # group by (task, panel, regime) -- balance is a within-cell property
    cells = collections.defaultdict(list)
    for c in calls:
        cells[(c["task"], c["panel"], c["regime"])].append(c)

    expected_per_packet = n * R // P
    expected_per_slot = R // P

    per_regime_counts = collections.defaultdict(set)
    for (task, panel, regime), group in cells.items():
        if len(group) != R * n:
            raise BalanceError(f"{task}/{panel}/{regime}: {len(group)} calls, want {R*n}")

        # B1 -- packet use within the cell
        pkt = collections.Counter(c["packet_index"] for c in group)
        if set(pkt) != set(range(P)) or set(pkt.values()) != {expected_per_packet}:
            raise BalanceError(
                f"B1 violated in {task}/{panel}/{regime}: packet counts {dict(pkt)}"
            )
        per_regime_counts[(task, panel)].add((regime, expected_per_packet))

        # B2 -- packet x seat, and packet x channel
        for field in ("seat", "channel"):
            cross = collections.Counter((c[field], c["packet_index"]) for c in group)
            if len(cross) != n * P or set(cross.values()) != {expected_per_slot}:
                raise BalanceError(
                    f"B2 violated in {task}/{panel}/{regime}: "
                    f"packet x {field} counts are not uniform ({sorted(set(cross.values()))})"
                )

        # B3 -- every model occupies every seat equally often. Requiring all n
        # seats is the point: a design that welds model identity to seat
        # position satisfies "uniform counts" trivially, because each model
        # appears in exactly one seat.
        cross = collections.Counter((c["model_ref"], c["seat"]) for c in group)
        for ref in {c["model_ref"] for c in group}:
            counts = [cross.get((ref, s), 0) for s in range(n)]
            if 0 in counts or len(set(counts)) != 1:
                raise BalanceError(
                    f"B3 violated in {task}/{panel}/{regime}: model {ref} "
                    f"occupies seats with counts {counts}; every model must "
                    f"appear in every seat equally often"
                )

        # regime semantics: shared means the replicate's seats coincide
        by_rep = collections.defaultdict(set)
        for c in group:
            by_rep[c["replicate"]].add(c["packet_index"])
        for rep, pkts in by_rep.items():
            if regime == "shared" and len(pkts) != 1:
                raise BalanceError(f"{task}/{panel}/shared r{rep}: packets {pkts}")
            if regime == "diverse" and len(pkts) != n:
                raise BalanceError(f"{task}/{panel}/diverse r{rep}: packets {pkts}")

    # B1, second half: the per-packet count is equal *across* regimes
    for (task, panel), seen in per_regime_counts.items():
        counts = {c for _, c in seen}
        if len(counts) != 1:
            raise BalanceError(
                f"B1 violated across regimes in {task}/{panel}: {seen}. Unequal "
                "packet use across arms confounds coupling with context quality."
            )
    return True


def cost_table(cfg, calls):
    """Preflight summary: what this run will cost before it runs."""
    by_model = collections.Counter(c["model_ref"] for c in calls)
    return {
        "calls": len(calls),
        "tasks": len(cfg["_tasks"]),
        "panels": len(cfg["panels"]),
        "regimes": len(cfg["regimes"]),
        "replicates": cfg["replicates"],
        "by_model": dict(by_model),
        "by_provider": dict(
            collections.Counter(
                cfg["models"][c["model_ref"]]["provider"] for c in calls
            )
        ),
        "independent_clusters": len({t.cluster for t in cfg["_tasks"]}),
    }
