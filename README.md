# Review-Harness

Apparatus for measuring **correlated false approval** in multi-reviewer LLM code
review: does a panel of n AI reviewers deliver the reliability a k-of-n gate
implies, or only the appearance of redundancy?

Two studies live in this repository:

* **The v1.3 study (current)**: *Choosing Reviewers for LLM Security Review*,
  Experiment Specification v1.3 (`docs/spec/`). Exploit-confirmed near-miss
  patches from real Vul4J CVEs, written by six generators, reviewed by nine
  reviewers; routing policies (RQ1), cheap panels (RQ2, RQ2o), common mode
  (RQ3), evidence screen (RQ4), interactions (RQ5, RQ6). Driven by `study.py`.
* **Experiment 1 (legacy)**: panel compositions x shared/diverse context on a
  placeholder bank. Merged into v1.3 and never run with paid calls; kept
  runnable and unchanged (`main.py`, `analyze.py`, section below).

The implementation map (spec section -> module -> test), the invariants, the
provisional items and what is still a placeholder are in **`docs/study.html`**.

## The v1.3 study

```
python study.py validate      study.jsonc                    # live config: refused while any pin is TO_PIN_AT_FREEZE
python study.py selftest      [--full]                        # the whole study offline: 9 synthetic models, mock Vul4J
python -m pytest tests -q                                     # 355 tests, no network, no paid calls

# a real run, in order (live config, once every pin is set)
python study.py timing-pilot  study.jsonc --cves VUL4J-51,VUL4J-15,VUL4J-3 --runs 3
python study.py reproduce     study.jsonc                    # Stage 1, all 79 CVEs
python study.py generate      study.jsonc --split development  # Stage 2
python study.py classify      study.jsonc --split development
python study.py select        study.jsonc --split development  # Stage 4 selection, correction order
python study.py sibling       study.jsonc --split development  # Stage 3 twins (author-written F)
python study.py review        study.jsonc --split development --expb   # Stage 5 + Experiment B
python study.py analyse-dev   study.jsonc                    # thresholds, policies, regret, promotion
python study.py freeze        study.jsonc                    # opens the test split
python study.py generate|classify|select|sibling|review study.jsonc --split test
python study.py confirm       study.jsonc                    # RQ1/RQ2(/RQ2o) with Holm, RQ3-RQ6, report
python study.py audit-logs    study.jsonc
```

| Path | Role |
|---|---|
| `study.jsonc` / `study.synthetic.jsonc` | live config (every pin a placeholder) / offline config |
| `hp/study_config.py` | JSONC loader, config and code hashes, freeze, the refusal conditions |
| `hp/providers/` | Anthropic, OpenAI, Google, open-weight (Ollama + pins), synthetic world, legacy synthetic |
| `hp/engine.py` | dispatcher: admission per candidate, four-attempt budget across resumes, pins, cost |
| `hp/bank/` | Vul4J runner, Stage 1 reproduction, generation, classification, selection, twins, split lock |
| `hp/review/` | e0 builder, Experiment B packets, crossed schedule, dispatch |
| `hp/analysis/` | rates, thresholds, policies, regret, common mode, confirm, extension, Experiment B, report |
| `hp/logs.py`, `hp/leaks.py`, `hp/synthworld.py` | log schemas, oracle deny list, synthetic world |
| `docs/spec/` | SPEC_ANSWERS.md, the registered split; spec v1.3 and the 9 Oct notes go here |

Invariants (each enforced in code and pinned by a test; see `docs/study.html`):
oracle isolation (builders without oracle parameters + a deny-list scan of every
input); fail-closed coding (abstain, invalid, timeout, truncation, unresolved);
snapshot / weights pinning with abort on mismatch; only `ok` counts as done;
global shuffle + no two calls on one candidate in flight; append-only logs from
which every number is recomputed; the test split locked until freeze; one
threshold per reviewer for every policy; trials -> candidate -> CVE -> row ->
equal-generator average; the core analysis never reads an extension row
(bit-identical with and without the extension, tested two ways).

---

# Experiment 1 (legacy)

The original design: panel compositions AAA/BBB/CCC/ABC x shared/diverse
context regimes on a placeholder bank, three confirmatory hypotheses with Holm.
Merged into the v1.3 study (SPEC_ANSWERS Q0, spec v1.0 section 5.3); everything
below still runs exactly as before. The harness produces one artefact — an append-only JSONL log of reviewer calls —
and the analysis recomputes everything from it offline. Companion theory:
*Formalisms and Modelling Choices* and *Harness Design and Instrumentation*.

```
python main.py    experiment.json --dry-run     # validate, check balance, print cost. spends nothing
python main.py    experiment.json               # run or resume
python analyze.py experiment.json --json out.json
python -m pytest  tests -q                      # whole suite (355), no network required
```

An offline self-test exercises the whole path with a synthetic provider, so the
wiring is verified without a budget:

```
python main.py experiment.offline.json && python analyze.py experiment.offline.json
```

## Layout

| Path | Role |
|---|---|
| `hp/schema.py` | verdict contract, status taxonomy, strict parsing |
| `hp/config.py` | config + task-bank validation; every design-invalidating misconfiguration raises |
| `hp/design.py` | pure schedule construction, B1–B4 asserted mechanically |
| `hp/providers/` (was `hp/providers.py`) | one call in, one status-tagged record out; provider-native structured output |
| `hp/runner.py` | execution, resume, concurrency, provenance, append-only log |
| `hp/dataset.py` | log → analysis cells; missingness accounting |
| `hp/estimators.py` | p, q, t, pattern table, recombination null, D, A, Fréchet bounds, n_eff |
| `hp/bootstrap.py` | two-stage aggregation, task-cluster bootstrap, contrasts, Holm |
| `hp/report.py` | tables + JSON |
| `tools/make_demo_tasks.py` | offline packet/manifest builder for the demo bank |

Nothing below imports from above.

## The harness boundary

| Side | Owns |
|---|---|
| Harness | task selection, panel composition, packet assignment, seat assignment, execution order, isolation, dispatch, schema validation, provenance |
| Reviewer | one stateless map (prompt, patch, context) → vote |
| Oracle | independent ground truth, never on the reviewer's input path |
| Analysis | offline, from the frozen log — including the k-of-n gate |

Three invariants, enforced structurally rather than by convention:

1. **The reviewer never learns the gate rule and never sees a peer's output.** A
   reviewer told "two of three merges this" is answering a different question.
   The gate lives in `hp/bootstrap.py`, applied to the log.
2. **The oracle never reaches the prompt.** Manifests carry `label`, `cwe`,
   `oracle_notes` and `exploit_path`; `config.build_prompt(template, patch_text,
   packet_text)` has no parameter through which any of it could arrive.
   `tests/test_oracle_isolation.py` asserts the strings are absent from every
   prompt the schedule builds.
3. **The log is append-only and every derived quantity is recomputed.** An
   aggregation bug is fixable without re-running a single model.

## Design guarantees

Asserted on the constructed schedule before any model call; the builder raises
rather than warns.

- **B1** Within each regime every packet is used the same number of times, *and
  that count is equal across regimes.* This is what makes shared-vs-diverse a
  contrast about coupling rather than about context quality.
- **B2** Within each regime every packet appears in every seat — and in every
  channel — equally often.
- **B3** Every model occupies every seat equally often.
- **B4** Execution order is randomised across the whole schedule, and the
  dispatcher never has two calls from one panel in flight at once.

**Seat vs channel.** A *seat* is a position in the panel and determines the
context packet. A *channel* is a fixed model identity. They are deliberately
distinct: welding them (`for seat, ref in enumerate(seats)`) puts model A in seat
0 forever, which violates B3. Channels rotate across seats by replicate, so a
channel keeps its model while visiting every seat — and the analysis indexes
reviewers by channel, because recombining by seat would pair reviewer A's
outcome with reviewer B's.

**Why B4 matters.** The obvious speed-up is a thread pool per panel. That is
precisely wrong: it puts a panel's reviewers at the vendor in the same instant,
sharing cache state, load and any service-side condition, so panel-level
coupling appears *by construction* and is indistinguishable from the coupling
under study. A panel is a grouping in the design, not an event in time.

## Reporting discipline

- **`D` (percentage points) is primary; `A` (amplification) is secondary,** is
  never called a correlation, and is suppressed when its denominator is near
  zero. Reporting only `A` overstates rare-event coupling; reporting only `D`
  hides the collapse of the redundancy argument.
- **`R_unan` and the pairwise gap `dq` are the primary detectors.** `R_2/3` is
  reported because it is what a deployment experiences, not because it is
  sensitive: for n = 3, `D(2/3) = 3·dq − 2·dt`, so its *sign* turns on whether
  `dt/dq` exceeds 3/2 and is therefore **not determined by the marginals and the
  pairwise rates**. The report's `shape` column (concentrated / diffuse) exists
  so that sign is never read without its third-order statistic.
- **The null is within-task cross-replicate recombination.** The plug-in
  alternative leaks a `1/R` fraction of the true dependence into the baseline
  (`E[p̂ⱼp̂ₖ] = (1/R)q_same + (1−1/R)pⱼpₖ`); it appears as `R_plugin`, a
  robustness display only.
- **The pooled-marginal reference is a labelled cautionary row.** Pure task
  heterogeneity fabricates a +7.9 pp penalty against it with zero coupling in
  the process — reproduced as a test.
- **Missingness is tabulated per model.** Non-uniform loss across model families
  is a confound on the composition factor, not noise.
- **Abstention coding is a reported sensitivity**, never a choice:
  `--abstain-as-approval` produces the other coding.
- **The inferential n is the number of independent clusters, not calls.** Every
  interval comes from a bootstrap that resamples whole clusters with siblings,
  configurations, seats and replicates intact.

## What the tests pin

`tests/test_dgp.py` is the load-bearing file: an estimator bug is silent and
fatal, so every claim the analysis makes is checked against a process whose
dependence structure is known by construction.

- conditionally independent reviewers → `D`, `dq`, `dt` all ≈ 0
- a planted shared packet state → recovered on `dq` and `D_unan`
- **task heterogeneity alone** → task-conditioned `D` ≈ 0 while the pooled null
  shows the +7.9 pp artefact, with `Δ = +10.6 pp` and `C = 1.75`
- **concentrated** common cause → `dt/dq > 3/2`, `D(2/3) < 0`, `D_unan > 0`
- **diffuse** common cause → `dt/dq ≈ 1`, `D(2/3) > 0`
- total coupling → `dt/dq = 1 + p`, crossover at `p = 1/2` (Condorcet)
- the plug-in null understates the 9.0 pp pairwise penalty by exactly 1/5 at R=5
- the non-identifiability construction: identical marginals, identical pairwise
  joints, `R_2/3 ∈ {0.25, 0.75}`
- the closed-form O(2ⁿ·Bell(n)·R) recombination estimator against O(Rⁿ) brute force
- end-to-end recovery of a planted regime contrast through the bootstrap path,
  plus a negative control that must look null

`tests/test_runner.py` pins the resume bug specifically: a call that timed out
is **not** done, because treating it as done retires it permanently and makes
missingness correlated with the composition factor.

## Configuration

```jsonc
{
  "temperature": 0.7,        // must be > 0: at 0 the replicates are one
                             // measurement copied R times and q_recomb degenerates
  "replicates": 6,           // multiple of packets_per_task AND of n
  "packets_per_task": 6,     // divisible by n; the cyclic design uses step P/n
  "gate": { "k": 2, "n": 3 },
  "regimes": ["shared", "diverse"],
  "strict_model_pinning": true,   // reject floating aliases; an alias that
                                  // updates mid-run changes the subject of the
                                  // experiment undetectably
  "workers": 4,
  "max_attempts": 4          // operational retries, logged with `attempt`,
                             // never scientific replicates
}
```

Cost is `tasks × panels × regimes × replicates × n`. The shipped demo config is
4 × 4 × 2 × 6 × 3 = 576 calls with **2 independent clusters** — which is the
number that governs the standard errors.

## Task bank

```
tasks/<task-id>/
  manifest.json      # task_id, cluster, label, functional, cwe, sibling_of,
                     # oracle_notes, exploit_path
  patch.diff
  packets/00..05.md  # ≥6 equal-budget, oracle-blinded context packets
```

`label ∈ {vulnerable, secure, indeterminate}`. The confirmatory population is
**vulnerable ∧ functionally passing** — the top-left cell of the oracle 2×2.
Secure siblings are required: with defective patches only, a reviewer that
rejects everything scores perfectly. `indeterminate` is excluded from
confirmatory analysis, because forcing a binary label puts label noise into `Y`,
and label noise on the *task* is shared by all n reviewers — manufacturing
exactly the correlated failure under study.

Packets are built offline by `tools/make_demo_tasks.py`, hashed at load, and
committed. A packet builder that runs per panel — especially an LLM one — sits
upstream of all n reviewers and becomes an unmeasured common cause.

> **The shipped four tasks are structurally correct placeholders.** Real
> manifests, real sibling pairing, six equal-budget packets each — but the patch
> and packet *content* is illustrative and must be replaced with real CVE
> material before anything is claimed from a run.

## Not yet done

- **Real task bank.** The single biggest remaining item, and the one that decides
  whether the paper has a result. Needs near-miss patches (vulnerable ∧
  functionally passing) with independently adjudicated labels and an
  `indeterminate` class.
- **Verify the pinned model ids in `experiment.json`** against the providers'
  current snapshot lists before the first paid run.
- **Power simulation.** A closed-form Bernoulli calculation assumes independent
  calls and would claim adequate power at a fraction of the true requirement.
  The procedure is to resample complete pilot tasks, then simulate the exact
  blocked design at 30/60/100 tasks × 6/12/24 replicates through the *planned*
  estimator, bootstrap and correction end to end.
- **Preregistration.** Three confirmatory hypotheses, Holm, and a smallest
  effect of practical interest (e.g. 5 pp on `R_2/3`) fixed before the run. A
  null result is only publishable if the interval excludes that effect.
- **Agentic reviewer arm** as a second treatment, not the baseline: if a reviewer
  can grep the repo and run tests, its tool trajectory becomes part of its
  context, a reviewer assigned one packet re-acquires the others, and two
  reviewers exploring the same snapshot converge on the same evidence — a genuine
  but *unmodelled* harness-mediated common cause. Requires a fresh workspace per
  call, redirected `HOME`, a pinned CLI version and network off.
- **General-n LP bound** on gate risk from moment constraints, if the paper
  generalises past n = 3.

## Install

```
pip install -r requirements.txt        # pytest only; provider SDKs are optional
pip install anthropic openai ollama    # whichever backends the config uses
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=...
```

Provider SDKs are imported lazily inside each backend, so the test suite runs
with none of them installed.
