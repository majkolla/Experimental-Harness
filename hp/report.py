"""Offline analysis CLI. Reads the frozen log, writes tables and a JSON blob.

LEGACY (Experiment 1). Kept runnable and unchanged; the v1.3 study does not use
this module (see docs/study.html).

Reporting discipline enforced here:

* D (percentage points) is primary; A (amplification) is secondary, never
  called a correlation, and suppressed when its denominator is near zero.
* R_unan and the pairwise gap dq are the primary *detectors* of coupling.
  R_2/3 is reported because it is what a deployment experiences, not because it
  is sensitive -- for n = 3, D(2/3) = 3 dq - 2 dt, so its sign is decided by
  whether dt/dq exceeds 3/2 and is not determined by the marginals and the
  pairwise rates. The concentrated/diffuse column exists so that sign is never
  read without its third-order statistic.
* the naive pooled-marginal reference appears only as a labelled cautionary
  row, because pure task heterogeneity fabricates a penalty against it with no
  reviewer dependence in the data-generating process at all.
"""

import argparse
import collections
import json

from . import bootstrap, config, dataset, estimators, runner


def _fmt(v, nd=3, sign=False):
    if v is None:
        return "n/a"
    if isinstance(v, tuple):
        return f"[{v[0]:+.{nd}f}, {v[1]:+.{nd}f}]"
    return f"{v:+.{nd}f}" if sign else f"{v:.{nd}f}"


def _sanitize(obj):
    """JSON cannot key a dict by a tuple; q/delta/C are keyed by channel pairs."""
    if isinstance(obj, dict):
        return {
            ("-".join(map(str, k)) if isinstance(k, tuple) else str(k)): _sanitize(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    return obj


def naive_pooled_reference(cells, k):
    """The trap curve: pool tasks, then recombine / plug in across them.

    Fails to condition on difficulty. Two equally frequent strata with
    conditionally independent reviewers (p = 0.05 easy, p = 0.70 hard) give
    Delta = +10.6 pp, C = 1.75 and an apparent gate penalty of +7.9 pp with zero
    coupling in the process. Reported so the paper can show how much of the
    intuitive "correlated LLM errors" story is just heterogeneity.
    """
    pooled = collections.defaultdict(list)
    for (_, panel, regime), cell in cells.items():
        pooled[(panel, regime)].extend(cell["trials"])
    out = {}
    for key, trials in pooled.items():
        if len(trials) < len(trials[0]):
            continue
        ps = estimators.marginals(trials)
        out[key] = {
            "R_obs_pooled": estimators.gate_risk(trials, k),
            "R_naive_ind": estimators.poisson_binomial_ge_k(ps, k),
        }
        out[key]["apparent_penalty"] = (
            out[key]["R_obs_pooled"] - out[key]["R_naive_ind"]
        )
    return out


def analyse(cfg_path, draws=2000, abstain_as_approval=False, seed=7):
    cfg = config.load(cfg_path)
    log_path = cfg["_root"] / cfg["log"]
    records, attempts, status_by_model = dataset.load_records(
        log_path, runner.read_log
    )
    cells = dataset.build_cells(cfg, records, abstain_as_approval)
    k = cfg["gate"]["k"]

    prim = dataset.primary(cells)
    per_task, clusters = bootstrap.per_task_stats(prim, k)
    agg = bootstrap.aggregate(per_task)

    stats = {**bootstrap.CONFIRMATORY, **bootstrap.EXPLORATORY}
    boot = bootstrap.cluster_bootstrap(per_task, clusters, stats, draws=draws, seed=seed)
    holm = bootstrap.holm(
        {name: boot[name]["p"] for name in bootstrap.CONFIRMATORY}
    )

    sec = dataset.secure_controls(cells)
    sec_rates = {}
    for (_, panel, regime), cell in sec.items():
        if cell["trials"]:
            sec_rates.setdefault((panel, regime), []).extend(
                estimators.marginals(cell["trials"])
            )

    return {
        "config_hash": cfg["_config_hash"],
        "prompt_hash": cfg["_prompt_hash"],
        "records_ok": len(records),
        "attempts_total": sum(attempts.values()),
        "missingness": dataset.missingness_table(status_by_model),
        "cells_primary": len(prim),
        "clusters": len(set(clusters.values())),
        "aggregate": {f"{p}/{r}": v for (p, r), v in sorted(agg.items())},
        "per_task": {
            f"{p}/{r}": {t: s for t, s in sorted(bt.items())}
            for (p, r), bt in sorted(per_task.items())
        },
        "bootstrap": boot,
        "holm": holm,
        "naive_pooled": {
            f"{p}/{r}": v for (p, r), v in sorted(naive_pooled_reference(prim, k).items())
        },
        "secure_approval": {
            f"{p}/{r}": sum(v) / len(v) for (p, r), v in sorted(sec_rates.items())
        },
        "saturation_warnings": bootstrap.saturation_check(agg),
        "incomplete_panels": sum(c["incomplete"] for c in cells.values()),
    }


def print_report(res):
    print(f"config {res['config_hash']}  prompt {res['prompt_hash']}")
    print(
        f"{res['records_ok']} valid calls from {res['attempts_total']} attempts; "
        f"{res['incomplete_panels']} incomplete panels dropped (not counted as rejections)"
    )
    print(f"{res['cells_primary']} primary cells, {res['clusters']} independent clusters\n")

    print("missingness by model (non-uniformity here is a confound):")
    for row in res["missingness"]:
        extras = " ".join(
            f"{k}={v}" for k, v in row.items()
            if k not in ("model_ref", "total", "loss_rate") and v
        )
        print(f"  {row['model_ref']:<6} total={row['total']:<6} loss={row['loss_rate']} {extras}")

    print("\nprimary population (vulnerable & functionally passing)")
    hdr = (
        f"{'panel/regime':<16}{'tasks':>6}{'p_bar':>8}{'R_obs':>8}{'R_rec':>8}"
        f"{'D':>8}{'R_un':>8}{'D_un':>8}{'dq':>8}{'dt':>8}{'shape':>13}"
    )
    print(hdr)
    for key, row in res["aggregate"].items():
        dq, dt = row.get("dq"), row.get("dt")
        ratio = (dt / dq) if dq not in (None, 0) and dt is not None and abs(dq) > 1e-6 else None
        shape = "n/a" if ratio is None else ("concentrated" if ratio > 1.5 else "diffuse")
        print(
            f"{key:<16}{row['n_tasks']:>6}{_fmt(row['p_bar']):>8}{_fmt(row['R_obs']):>8}"
            f"{_fmt(row['R_recomb']):>8}{_fmt(row['D'], sign=True):>8}"
            f"{_fmt(row['R_unan_obs']):>8}{_fmt(row['D_unan'], sign=True):>8}"
            f"{_fmt(dq, sign=True):>8}{_fmt(dt, sign=True):>8}{shape:>13}"
        )

    print("\nconfirmatory contrasts (task-cluster bootstrap)")
    print(f"{'hypothesis':<26}{'estimate':>10}{'95% CI':>22}{'p':>8}{'p_holm':>9}")
    for name in bootstrap.CONFIRMATORY:
        b = res["bootstrap"][name]
        print(
            f"{name:<26}{_fmt(b['estimate']):>10}{_fmt(b['ci']):>22}"
            f"{_fmt(b['p'], 4):>8}{_fmt(res['holm'].get(name), 4):>9}"
        )
    print("\nexploratory (not corrected)")
    for name in bootstrap.EXPLORATORY:
        b = res["bootstrap"][name]
        print(f"  {name:<24}{_fmt(b['estimate']):>10}{_fmt(b['ci']):>22}")

    print("\nnaive pooled reference -- CAUTIONARY, not an estimate of coupling")
    for key, row in res["naive_pooled"].items():
        print(
            f"  {key:<14} R_obs_pooled={row['R_obs_pooled']:.3f} "
            f"R_naive_ind={row['R_naive_ind']:.3f} "
            f"apparent_penalty={row['apparent_penalty']:+.3f}"
        )

    if res["secure_approval"]:
        print("\nsecure siblings (approval here is correct behaviour)")
        for key, v in res["secure_approval"].items():
            print(f"  {key:<14} approval={v:.3f}")

    for w in res["saturation_warnings"]:
        print(f"\nWARNING {w}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="analyse a review-harness log")
    ap.add_argument("config", nargs="?", default="experiment.json")
    ap.add_argument("--draws", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument(
        "--abstain-as-approval",
        action="store_true",
        help="sensitivity coding: under a permissive gate abstain is not "
        "obviously safe, so both codings are reported, never chosen",
    )
    ap.add_argument("--json", help="write the full result object here")
    a = ap.parse_args(argv)

    res = analyse(a.config, draws=a.draws, abstain_as_approval=a.abstain_as_approval,
                  seed=a.seed)
    print_report(res)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(_sanitize(res), fh, indent=2, default=str)
        print(f"\nwrote {a.json}")
    return res


if __name__ == "__main__":
    main()
