"""Execution: resume, concurrency, provenance, append-only log.

The log is the experiment's only durable artefact. It is append-only, one JSON
object per line, and every derived quantity is recomputed from it offline -- so
an aggregation bug is fixable without re-running a single model.

Two things here are corrections of real defects in the first implementation.

**Resume.** `done_ids` previously collected every `call_id` present in the log,
regardless of status. A single 429 or timeout therefore retired that call
permanently: the analysis saw an incomplete panel and dropped it. Because error
rates differ systematically by provider and by response length, that made
missingness correlated with the composition factor under study -- the one thing
the design cannot tolerate. Only `status == "ok"` counts as done.

**Concurrency without manufacturing coupling.** The obvious speed-up is a
thread pool per panel. That is precisely wrong: it puts a panel's n reviewers
at the vendor in the same instant, sharing cache state, load and any
service-side condition, so panel-level coupling appears by construction and is
indistinguishable from the coupling being measured. The dispatcher below runs
workers over the *globally shuffled* schedule while refusing to have two calls
from the same panel in flight at once. Throughput without temporal collocation.
"""

import concurrent.futures as cf
import json
import pathlib
import random
import sys
import time
import zlib

from . import HARNESS_VERSION, config, design, providers
from .schema import COMPLETE, OK


def read_log(log_path):
    """Yield records, tolerating a truncated final line from a killed run."""
    if not pathlib.Path(log_path).exists():
        return
    with open(log_path) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"warning: {log_path}:{i} is not valid JSON, skipping",
                      file=sys.stderr)


def done_ids(log_path):
    """Call ids that reached a schema-valid verdict. Failures are *not* done."""
    return {r["call_id"] for r in read_log(log_path) if r.get("status") in COMPLETE}


def eligible_order(pending, busy_panels, limit):
    """Pick up to `limit` calls whose panels have nothing in flight.

    Preserves the shuffled order otherwise: this is a local admission rule, not
    a reordering of the schedule.
    """
    picked, seen = [], set()
    if limit <= 0:
        return picked
    for i, c in enumerate(pending):
        key = c["panel_key"]
        if busy_panels.get(key) or key in seen:
            continue
        picked.append(i)
        seen.add(key)
        if len(picked) == limit:
            break
    return picked


def _provenance(cfg):
    return {
        "experiment": cfg["name"],
        "harness_version": HARNESS_VERSION,
        "config_hash": cfg["_config_hash"],
        "prompt_hash": cfg["_prompt_hash"],
        "temperature": cfg["temperature"],
        "max_tokens": cfg["max_tokens"],
        "gate_k": cfg["gate"]["k"],
        "gate_n": cfg["gate"]["n"],
    }


class ModelDriftError(RuntimeError):
    """The provider served a snapshot other than the pinned one."""


def run(cfg_path, dry_run=False, limit=None):
    cfg = config.load(cfg_path)
    tasks = {t.task_id: t for t in cfg["_tasks"]}
    schedule = design.build_schedule(cfg)  # asserts B1-B3, then shuffles (B4)

    log_path = cfg["_root"] / cfg["log"]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    already = done_ids(log_path)
    todo = [c for c in schedule if c["call_id"] not in already]
    if limit:
        todo = todo[:limit]

    table = design.cost_table(cfg, schedule)
    print(json.dumps(table, indent=2))
    print(
        f"\n{len(schedule)} calls in design, {len(already)} complete, "
        f"{len(todo)} to run"
    )
    print(
        f"balance B1-B3 asserted; {table['independent_clusters']} independent "
        f"clusters (this, not the call count, is the inferential n)"
    )
    if dry_run:
        print("\ndry run: nothing dispatched")
        return table

    prov = _provenance(cfg)
    served = {}
    rng = random.Random(cfg["seed"])
    workers = max(1, int(cfg["workers"]))
    pending = list(todo)
    busy = {}
    inflight = {}
    written = 0
    t0 = time.time()

    def work(call):
        task = tasks[call["task"]]
        pi = task.prompt_inputs(call["packet_index"])
        prompt = config.build_prompt(cfg["_prompt"], pi["patch_text"], pi["packet_text"])
        spec = dict(cfg["models"][call["model_ref"]])
        spec["_call_key"] = call["call_id"]
        spec["_packet_id"] = call["packet_id"]
        # Stable per-call seed for retry jitter: `hash()` on a str is salted
        # per process, and nothing in the apparatus should be irreproducible.
        seed = zlib.crc32(call["call_id"].encode()) ^ cfg["seed"]
        return providers.call_with_retries(spec, prompt, cfg, rng=random.Random(seed))

    with open(log_path, "a") as log, cf.ThreadPoolExecutor(workers) as ex:
        while pending or inflight:
            for i in reversed(eligible_order(pending, busy, workers - len(inflight))):
                call = pending.pop(i)
                busy[call["panel_key"]] = busy.get(call["panel_key"], 0) + 1
                inflight[ex.submit(work, call)] = call
            if not inflight:
                # Every remaining call belongs to a panel already in flight;
                # wait for a slot rather than spinning.
                continue
            done, _ = cf.wait(inflight, return_when=cf.FIRST_COMPLETED)
            for fut in done:
                call = inflight.pop(fut)
                busy[call["panel_key"]] -= 1
                attempts = fut.result()
                for rec in attempts:
                    row = {**call, **prov, **rec}
                    if rec["status"] == OK and rec.get("served_model"):
                        want, got = call["model"], rec["served_model"]
                        row["served_model_mismatch"] = got != want
                        served.setdefault(call["model_ref"], got)
                    log.write(json.dumps(row, default=str) + "\n")
                    written += 1
                log.flush()
                final = attempts[-1]
                rate = written / max(1e-9, time.time() - t0)
                print(
                    f"[{written} written, {len(pending)} left, {rate:.1f}/s] "
                    f"{call['call_id']} {final['status']}"
                    + (f" x{len(attempts)}" if len(attempts) > 1 else "")
                )
                if (
                    cfg["strict_model_pinning"]
                    and final["status"] == OK
                    and final.get("served_model")
                    and final["served_model"] != call["model"]
                ):
                    raise ModelDriftError(
                        f"pinned {call['model']!r} but provider served "
                        f"{final['served_model']!r}. The subject of the "
                        f"experiment changed mid-run; stopping."
                    )
    return table
