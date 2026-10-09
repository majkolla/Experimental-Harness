"""Dispatch a list of model calls: resume, attempt budget, admission, pins, cost.

Shared by generation (Stage 2) and review (Stage 5). The legacy runner
(`hp/runner.py`, Experiment 1) is unchanged; this reuses its pieces:

* `runner.eligible_order`: the admission rule. Calls carry a `panel_key`; for
  review it is the candidate id, so no two calls on one candidate are ever in
  flight together. Order is otherwise the globally shuffled schedule.
* `providers.call_with_retries` with the attempt budget continued across
  resumes (SPEC_ANSWERS Q1). A call is *closed* once it has an `ok` record,
  or `max_attempts` (4) logged attempts, or a last attempt with a
  non-retryable status (schema_invalid, truncated, request_error: the same
  retry policy as within a run). A resume continues only calls that were cut
  off while still retryable (timeout, transport_error) with budget left, so
  the outcome never depends on how often a run was resumed. A closed call
  without `ok` is never re-dispatched; the analysis codes it fail-closed.
* Pins: a served model that differs from the pinned snapshot raises
  `PinViolation` after its row is written, which stops the run. Open-weight
  models are verified at start and end of every dispatch (and on reload, in
  the backend).

Only the `synthetic_world` backend receives the explicit `_context` (what is
being generated or reviewed). Real backends receive the model spec and the
prompt; nothing else from the call.
"""

import collections
import concurrent.futures as cf
import random
import zlib

from . import HARNESS_VERSION, logs, providers
from .providers import openweight
from .runner import eligible_order
from .schema import OK, RETRYABLE


class LocalFault(RuntimeError):
    """A missing API key or SDK: our configuration, not the model. Stops the run."""


def call_settings(cfg, kind):
    s, c, t = cfg["sampling"], cfg["caps"], cfg["timeouts_s"]
    if kind == "generation":
        return {"temperature": s["gen_temperature"], "top_p": s["gen_top_p"],
                "max_tokens": c["gen_output_tokens"], "timeout_s": t["gen_timeout_s"],
                "max_attempts": cfg["max_attempts"]}
    return {"temperature": s["review_temperature"], "top_p": s["review_top_p"],
            "max_tokens": c["review_output_tokens"], "timeout_s": t["review_timeout_s"],
            "max_attempts": cfg["max_attempts"]}


def cost_of(cfg, ref, rec):
    """(primary, sensitivity) cost of one attempt. Sensitivity only for open models."""
    pr = cfg["prices_usd_per_mtok"].get(ref) or {}
    tin = rec.get("in_tokens") or 0
    tout = rec.get("out_tokens") or 0
    primary = tin / 1e6 * float(pr.get("input", 0)) + tout / 1e6 * float(pr.get("output", 0))
    sens = None
    if cfg["models"][ref].get("tier") == "open":
        gpu_h = cfg["openweight_cost"].get("gpu_hour_usd")
        if isinstance(gpu_h, (int, float)):
            sens = (rec.get("gpu_seconds") or 0.0) / 3600.0 * float(gpu_h)
    return round(primary, 10), (round(sens, 10) if sens is not None else None)


def call_seed(cfg, call_id):
    """Derived per-call seed (retry jitter, synthetic draws); logged with every row."""
    return zlib.crc32(call_id.encode()) ^ int(cfg["seed"])


def provenance(cfg, prompt_kind):
    return {
        "harness_version": HARNESS_VERSION,
        "spec_version": cfg["spec_version"],
        "config_sha256": cfg["_config_sha256"],
        "prompt_sha": cfg["_prompts"][prompt_kind]["sha256"],
        "mode": cfg["mode"],
    }


def attempt_counts(log_path, kind):
    """(attempts per call, calls with ok, last status per call) from the log."""
    counts, ok, last = collections.Counter(), set(), {}
    for r in logs.read(log_path):
        if r.get("kind") != kind:
            continue
        cid = r.get("call_id") or r.get("attempt_id")
        counts[cid] += 1
        last[cid] = r.get("status")
        if r.get("status") == OK:
            ok.add(cid)
    return counts, ok, last


def closed_calls(log_path, kind, max_attempts):
    counts, ok, last = attempt_counts(log_path, kind)
    return {cid for cid in counts
            if cid in ok or counts[cid] >= max_attempts or last[cid] not in RETRYABLE}


def run_calls(cfg, calls, log_path, row_kind, contract, make_prompt, make_row,
              settings_kind, world=None, sleep=None, on_progress=None):
    """Dispatch `calls`; append one row per attempt. Returns a summary dict.

    Each call needs: call_id, panel_key, model_ref, and `_context` when the
    model is synthetic. `make_prompt(call) -> (prompt, input_sha)`;
    `make_row(call, rec, extra) -> row`.
    """
    max_att = cfg["max_attempts"]
    counts, ok, _ = attempt_counts(log_path, row_kind)
    closed = closed_calls(log_path, row_kind, max_att)
    pending = [c for c in calls if c["call_id"] not in closed]
    summary = {"calls": len(calls), "already_closed": len(calls) - len(pending),
               "dispatched": len(pending)}
    if not pending:
        return _finish(summary, calls, log_path, row_kind, max_att)

    settings = call_settings(cfg, settings_kind)
    if sleep is None and cfg.get("mode") == "synthetic":
        sleep = lambda s: None  # noqa: E731 -- synthetic backends cannot be rate-limited
    used = sorted({c["model_ref"] for c in pending})
    open_specs = [cfg["models"][r] for r in used if cfg["models"][r]["provider"] == "openweight"]
    openweight.verify_all(open_specs)  # start of run

    def work(call):
        ref = call["model_ref"]
        spec = dict(cfg["models"][ref])
        spec["_call_key"] = call["call_id"]
        if spec["provider"] == "synthetic_world":
            spec.update(_world=world, _context=call["_context"], _ref=ref)
        prompt, input_sha = make_prompt(call)
        done = counts[call["call_id"]]
        want = cfg["models"][ref].get("snapshot") or cfg["models"][ref]["model"]

        def log_attempt(rec):
            # Written the moment the attempt ends: nothing is lost if the run is
            # killed, and the four-attempt budget holds across resumes.
            if rec.get("local_fault"):
                raise LocalFault(
                    f"{ref}: {rec.get('error')} -- a local configuration fault (missing key or "
                    "SDK), not a model failure; nothing was logged for this call"
                )
            primary, sens = cost_of(cfg, ref, rec)
            logs.append(log_path, [make_row(call, rec, {
                "input_sha": input_sha, "cost": primary, "cost_sensitivity": sens,
                "seed": call_seed(cfg, call["call_id"])})])
            got = rec.get("served_model")
            if rec["status"] == OK and got and got != want:
                raise providers.PinViolation(
                    f"{ref}: pinned {want!r} but the provider served {got!r}; "
                    "the subject of the experiment changed mid-run, stopping"
                )

        kwargs = {"sleep": sleep} if sleep else {}
        return providers.call_with_retries(
            spec, prompt, settings, rng=random.Random(call_seed(cfg, call["call_id"])),
            contract=contract, max_attempts=max_att - done, attempt_offset=done,
            on_attempt=log_attempt, **kwargs)

    workers = max(1, int(cfg["workers"]))
    queue = list(pending)
    busy, inflight = {}, {}
    with cf.ThreadPoolExecutor(workers) as ex:
        while queue or inflight:
            for i in reversed(eligible_order(queue, busy, workers - len(inflight))):
                call = queue.pop(i)
                busy[call["panel_key"]] = busy.get(call["panel_key"], 0) + 1
                inflight[ex.submit(work, call)] = call
            if not inflight:
                continue
            done, _ = cf.wait(inflight, return_when=cf.FIRST_COMPLETED)
            for fut in done:
                call = inflight.pop(fut)
                busy[call["panel_key"]] -= 1
                # A PinViolation or LocalFault propagates and stops the run; calls
                # already in flight finish (their attempts are logged as they end).
                recs = fut.result()
                if on_progress:
                    on_progress(call, recs[-1])
    openweight.verify_all(open_specs)  # end of run
    return _finish(summary, calls, log_path, row_kind, max_att)


def _finish(summary, calls, log_path, kind, max_att):
    _, ok, _ = attempt_counts(log_path, kind)
    closed = closed_calls(log_path, kind, max_att)
    ids = {c["call_id"] for c in calls}
    summary["ok"] = len(ids & ok)
    summary["closed_without_ok"] = len((ids & closed) - ok)
    summary["open"] = len(ids - closed)
    return summary
