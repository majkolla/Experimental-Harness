# review-harness

A minimal experimental controller for measuring **correlated false approval** in
multi-reviewer LLM code review. It treats reviewers as instruments being
measured, keeps the experiment strictly outside them, and recomputes every
derived quantity from an append-only raw log.

Stage 1 runs end to end with no API keys and no model calls.

```bash
pip install -r requirements.txt
python3 -m pytest tests -q                              # 32 tests, ~2s
python3 bin/build_schedule.py config/stage1-synthetic.yaml
python3 bin/run.py           config/stage1-synthetic.yaml
python3 bin/analyze.py       config/stage1-synthetic.yaml
```

---

## 1. What a harness actually is

A harness is the boundary between the experiment and the thing being
experimented on. Everything on one side is under your control and must be
recorded; everything on the other side is the subject and must not be touched.

```
YOUR HARNESS                                    │  THE SUBJECT
                                                │
  design      which task, which panel, which    │
              packet, which seat, which order   │
  isolation   fresh session, fresh workspace,   │   the reviewer:
              no cross-reviewer channel         │   a stateless function
  dispatch    one call, one input, one output   │   (prompt, patch, context)
  validation  schema-checked structured vote    │       -> vote
  aggregation the k-of-n gate, computed here    │
  provenance  hashes, versions, timings, usage  │
                                                │
  ORACLE (independent ground truth)  ──────────►│  never visible to reviewer
  ANALYSIS (offline, from frozen raw log)       │
```

Three rules follow from that picture, and almost every mistake in this kind of
study is a violation of one of them.

**The reviewer never learns the aggregation rule and never sees another
reviewer's output.** A reviewer told "two of three approvals merges this" is
answering a different question. A reviewer that can see a peer's verdict makes
the panel one reviewer with extra steps.

**The oracle never touches the reviewer's input path.** Task manifests here hold
`label`, `cwe`, `oracle_notes` and exploit script paths, and the loader passes
*only* `patch_text` and the packet into the prompt. That is enforced by the code
path (`Runner._build_request`), not by remembering to be careful.

**The raw log is append-only and derived quantities are recomputed every time.**
`results/*.jsonl` is one line per reviewer call and is never rewritten;
`bin/analyze.py` reads it and writes a separate report. If the aggregation has a
bug you fix the code, not the data.

---

## 2. What this repository contains

```
config/     experiment definitions -- the ONLY place the apparatus is described
tasks/      task manifests (oracle-side fields live here, never reach a prompt)
patches/    candidate patches under review
packets/    per-task bank of >=6 oracle-blinded, equal-budget context packets
prompts/    the fixed reviewer instruction
schemas/    JSON Schema for the structured vote
harness/    ids, design, reviewers, runner, store, vote  <- the apparatus
analysis/   estimators                                   <- the statistics
tests/      32 tests, including recovery of planted dependence
bin/        build_schedule.py, run.py, analyze.py
results/    append-only raw logs + derived reports
```

| Module | Does |
|---|---|
| `harness/ids.py` | Content hashes for prompt/patch/packet/apparatus; per-decision derived RNGs |
| `harness/design.py` | Builds and **verifies** the counterbalanced schedule before any call |
| `harness/reviewers.py` | Backend adapters: deterministic, synthetic, API (3 providers), CLI |
| `harness/runner.py` | One isolated call at a time; separates `decision` from `run_status` |
| `harness/store.py` | Append-only JSONL, resume by `call_id` |
| `harness/vote.py` | Schema validation and the k-of-n gate |
| `analysis/estimators.py` | Marginals, `q_same`, `q_recomb`, third-order `t`, `D`, `A`, `n_eff`, task-cluster bootstrap |

The recombination estimators are closed-form O(R) inclusion-exclusion rather
than O(R^3) enumeration, checked against brute force in
`test_closed_form_recomb_matches_brute_force`. That turns a 2000-draw cluster
bootstrap over six statistics from minutes into ~2 seconds, which is the
difference between exploring the analysis and avoiding it.

### Design guarantees, asserted not assumed

`verify_balance()` runs before every execution and raises rather than warns:

- **B1** Within each context regime, every packet is used in the same number of
  calls — **and the count is equal across the two regimes**. This is what makes
  shared-vs-diverse a contrast about *coupling* rather than about *context
  quality*.
- **B2** Within each regime, every packet appears in every seat equally often.
- **B3** In `ABC` panels every model occupies every seat equally often.
- **B4** Execution order is randomised across the whole schedule, so treatment is
  not confounded with wall-clock era.

Balance is exact by construction (a cyclic packet design with step `P/3`), not by
rejection sampling — and `replicates` must be a multiple of 6 or the builder
refuses to run.

---

## 3. Stage 1: prove the apparatus before spending money

Two fake backends, and the second is the important one.

`DeterministicBackend` — always-approve / always-reject / alternating / timeout.
Checks gate arithmetic, panel grouping, resume, and that an infrastructure
failure does not become a vote.

`SyntheticBackend` — a reviewer whose false-approval probability follows a
**known** logit model:

```
logit P(approve | defective) = beta0
                             + task_difficulty[task]      # stable, no coupling
                             + role_susceptibility[role]  # stable, no coupling
                             + packet_effect[packet]      # couples ONLY when packet is shared
                             + panel_shock                # couples regardless of regime
                             + call_noise
```

This separates the three things the paper must keep apart, and lets the tests
check both directions:

| Injected | Test expectation |
|---|---|
| Nothing (`packet_sd=0`, `panel_shock_sd=0`) | dependence gap ≈ 0 in **both** regimes |
| `packet_sd > 0` | gap clearly positive in shared, near zero in diverse |
| `panel_shock_sd > 0` | gap positive in **both** regimes, and the regime contrast correctly reports ~no effect |
| Task heterogeneity only, then pooled | naive `p_j p_k` baseline invents dependence; task-conditioned one does not |

The last row is worth dwelling on. A harness that reports dependence when none
was injected produces the paper's headline result for free — so the null tests
matter more than the positive ones.

Observed on the shipped Stage-1 config (2 tasks × 4 panels × 2 regimes × 24
replicates = 1152 calls):

```
H1_D_unanimous                     +0.0252   95% task-cluster CI [+0.0191, +0.0314]
H3_shared_minus_diverse_R3         +0.0990   95% task-cluster CI [+0.0625, +0.1354]
H3_shared_minus_diverse_pairwise   +0.0757   95% task-cluster CI [+0.0556, +0.0959]
H3_shared_minus_diverse_R2         +0.0052   95% task-cluster CI [-0.0729, +0.0833]
```

The planted packet-coupling effect is recovered cleanly by the pairwise and
unanimity statistics — and is **invisible on the 2-of-3 gate**. That is not
noise. See §5.

---

## 4. Backends: why raw APIs, and why not fork Codex

Wrapping rather than forking is right, for the reasons your draft gives. But the
more consequential decision is *what to wrap*.

**A Codex-only harness cannot run your design.** The composition factor needs
`AAA`, `BBB`, `CCC`, `ABC` over three model *families* — that is the whole point
of asking whether family diversity buys independence. One vendor's CLI gives you
one family. Wrap the APIs of three providers instead: `ApiBackend` here is ~40
lines per provider, requests a schema-constrained vote at the API level, and
gives you decoding control, real concurrency, and per-call token accounting.

**Agentic review is a second experiment, not the first one.** If a reviewer can
run tests and grep the repo, its tool trajectory becomes part of its context —
and two reviewers exploring the same snapshot may converge on the same evidence.
That is a genuine, interesting, *harness-mediated* common cause. It is also not
in your design matrix, and it partially defeats the packet-assignment
manipulation: a reviewer given packet P3 that then reads the whole repo has
effectively re-acquired P4 and P5. Start with fixed packets and no tool use, so
"context" means exactly what the design says it means. Add the agentic arm second
(`CliBackend` is here for that), and treat it as a treatment, not as the
baseline.

If you do use a CLI: fresh workspace copy per call, `HOME` pointed at a temp dir
so no personal config, memory, skills or MCP servers leak in, pinned CLI version,
and network disabled unless network access is the treatment. A new *thread* in a
*shared directory* is not isolation — reviewers then interact through build
caches. Verify the exact flag names against your installed version and pin them
in the config; do not trust flag names from memory, including mine.

Fork only if the released interface cannot expose something essential
(internal state, decoding control, a genuinely new reviewer tool). Then the
subject becomes "modified Codex" and you owe readers the commit, the diff and a
container digest.

---

## 5. Five things I would change in your plan

**(a) The 2-of-3 gate is the wrong primary detector.** For three reviewers, with
`q̄` the mean pairwise joint approval and `t` the triple joint approval,

```
P(>= 2 approve) = 3*q̄ - 2*t          P(all 3 approve) = t
```

The coefficient on `t` is *negative*. Coupling raises both `q̄` and `t`, but they
push the majority gate in opposite directions: probability mass drains out of
"exactly two approve" and into "all three approve" and "at most one". So a panel
can become strictly more correlated — pairwise co-failure up, unanimous false
approval up sharply — while its measured 2-of-3 failure rate *falls*. This
happens in the shipped Stage-1 run and there is a test pinning it
(`test_coupling_can_lower_2of3_risk_while_raising_unanimity_risk`).

Consequence: report the 2-of-3 rate because it is what a deployment experiences,
but detect coupling with the pairwise gap and the unanimity gate, and report the
third-order statistic explicitly. Marginals plus all pairwise rates do **not**
determine majority-gate risk — which is exactly your project's stated
non-identifiability contribution, now with a worked demonstration.

**(b) Do not launch a panel's three reviewers simultaneously.** Your flowchart
fans out to three parallel reviewers per panel. Parallel launch means the three
calls hit the vendor in the same instant, sharing cache state, load, and any
service-side condition — which manufactures panel-level coupling *by
construction*, indistinguishable from the coupling you want to measure.
`build_schedule` therefore randomises execution order across the entire schedule
and `test_execution_order_interleaves_treatments` asserts panels are not
contiguous. You lose nothing: a panel is a grouping in the design, not an event
in time.

**(c) Freeze the packets offline; never build them per panel.** The packet
builder is a shared component sitting upstream of all three reviewers. If it runs
once per panel — and especially if it is itself an LLM — it becomes an
unmeasured common cause. Build the bank once, hash each packet, commit it, and
have the harness only ever read files.

**(d) Add the secure sibling patches.** With defective patches only, a reviewer
that rejects everything scores perfectly. `label: vulnerable` is in the manifest
and `build_cells(defective_only=True)` filters on it precisely so the secure
siblings can be run through the same apparatus as a permissiveness control.
Your project docs have this; the harness plan dropped it.

**(e) Replicates need `temperature > 0`.** At temperature 0 twelve replicates are
one measurement copied twelve times, `q_recomb` has nothing to recombine, and
every dependence estimate collapses. Whatever you choose, pin it in the config —
it is part of the apparatus, and `Apparatus.fingerprint()` records it.

Two smaller ones. `confidence` in the schema is fine as a covariate but must
never enter the gate. And a retried call is an *operational* retry, not a
scientific replicate — `attempts` is recorded per call and `run_status` is kept
strictly separate from `decision`, so a crash can never be silently read as a
rejection (`test_infrastructure_failure_is_not_a_vote`).

---

## 6. Going live

`config/pilot-api.yaml` is the three-family pilot. Two things before you run it.

**Pin exact model snapshots, never aliases.** An alias that updates mid-run
changes the subject of the experiment while it is being measured, and nothing
downstream can detect it. `Apparatus.fingerprint()` records what you pinned.

**Do the arithmetic first.**

```
calls = tasks × panel_configs × regimes × replicates × 3
```

2 tasks × 4 configs × 2 regimes × 24 replicates × 3 = **1152 calls**. A pilot at
8 tasks and 24 replicates is 4608. Multiply by your per-call token cost before
you find out empirically.

Then the staging your draft already has right: Stage 1 fakes → Stage 2 two-task
smoke test with every event log read by hand → Stage 3 pilot for rates, cost,
timeout frequency and schema reliability → Stage 4 freeze everything (tasks,
patches, oracle, packets, prompt, model ids, decoding, retry rules, exclusion
rules, seed, analysis code) → preregister → confirmatory run.

The pilot's job is not to produce results. It is to tell you whether the
marginal false-approval rate lands in a band where your gate can move at all —
near 0 or near 1 the gate saturates and no dependence effect of any size is
detectable. Check that before freezing.

---

## 7. What each record stores

One line per reviewer call: `call_id`, `panel_id`, design coordinates (`task_id`,
`panel_config`, `context_regime`, `replicate`, `seat`, `model_role`, `model_id`,
`packet_id`, `exec_order`), apparatus fingerprint (prompt hash, schema hash,
role→model map, decoding, harness version, python, platform), content hashes
(`prompt_payload_hash`, `patch_hash`, `packet_hash`), outcome (`run_status`,
`vote`, `schema_error`, `attempts`), and provenance (`usage`, `latency_s`,
`started_at`, `finished_at`, `backend_meta`, `raw`).

Derived panel records and all estimates are recomputed by `bin/analyze.py`.
