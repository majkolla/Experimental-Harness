# PLAN: implement Experiment Specification v1.3 in `Experimental-Harness`

Step 0 deliverable, written 2026-10-09; **revised the same day after `docs/spec/SPEC_ANSWERS.md`** (see §9 and §10). Approved: "if nothing new conflicts, proceed with WP1". Work happens on branch `study-v1.3`.

**Progress (2026-10-10): WP0-WP8 done**, one commit each on `study-v1.3`, plus one commit of fixes from an independent review (section 10, items 21-31); 355 tests (79 legacy + 276 new), about 36 s, Python 3.9 and 3.13, no network. Implementation map: `docs/study.html`.

**Source of truth for this revision:** `SPEC_ANSWERS.md` + spec v1.0 + the brief. `Experiment_Specification_v1_3.md` and the 9 Oct `experiment_notes.tex` were not delivered (not in the repo, the project or the chat), so the few details that only v1.3 itself fixes are filled in provisionally and listed in §10.

Companion file: `SPEC_QUESTIONS.md` (22 open items, Q0–Q21). Section numbers (§) refer to the spec.

---

## 0. What the survey found before planning

| # | Finding | Consequence for this plan |
|---|---|---|
| P1 | `docs/spec/` did not exist and no v1.2 was available. | **Resolved 2026-10-09:** `docs/spec/` now holds `SPEC_ANSWERS.md` and `proposed_split.json` (copied byte-for-byte from the project; SHA-256 `b0ffb4cf…445d7`, pinned in the config). `Experiment_Specification_v1_3.md` and the 9 Oct notes have still not arrived; see §10. |
| P2 | **Most of the code is not in git.** `hp/`, `tests/`, `docs/`, `tasks/`, `tools/` and `requirements.txt` are untracked; the 19 commits contain only the top-level scripts, configs and prompt. | Proposed **WP0**: one baseline commit of the current tree, so that every later work package is a reviewable diff. |
| P3 | Git in the connected folder needs delete permission (git removes its own lock files). | I will ask for it once, just before WP0. |
| P4 | **Baseline:** `pytest tests -q` gives **79 passed in 3.0 s** (Python 3.10.12, pytest 9.1.1, Linux VM, no provider SDKs). Your `.venv` is Python **3.9.6** with `anthropic` and `ollama` only (no `openai`, no Google SDK, no pytest). | New code stays **Python 3.9-compatible and standard-library only**; SDKs are imported lazily, as now. |
| P5 | `test_a_missing_api_key_is_our_fault_and_is_not_retried` calls the real Anthropic backend. On a machine with the SDK installed and `ANTHROPIC_API_KEY` exported (as the README tells you to do), it sends a real request (to a model named `"m"`, so it fails, but it is a network call). | This breaks the no-network rule in principle. WP7 adds an autouse guard in `conftest.py` that clears provider keys and blocks sockets. The test itself stays unchanged. |
| P6 | **Fail-closed coding is not an existing invariant.** The current code drops non-`ok` calls as *missing* ("incomplete panels dropped and counted, never imputed": `dataset.build_cells`, internals §11.1) and argues against coding a timeout as a rejection. Only *abstain → non-approval* exists today. | The new study path implements fail-closed exactly as the spec says. The legacy path stays as it is. See Q1. |
| P7 | The six statuses in code are `ok, schema_invalid, truncated, timeout, transport_error, request_error`. Spec v1.0 §11.6 lists `schema_violation` and `reject` instead. | I keep the code's names. See Q2. |
| P8 | Snapshot pinning exists (`config._PINNED` shape check, plus `runner.ModelDriftError` when the served model differs from the pinned one). For Ollama the served id is just the requested id, so drift is **not** detectable there today. | Open-weight pinning needs a new weights-checksum check (WP2). |

---

## 1. Module map: §18.2 (+ the brief) → existing code

### 1.1 Proposed layout

New code goes into subpackages of `hp/`, keeping the rule "nothing below imports from above".

```
hp/
  schema.py            extend: add the v1.3 review contract next to the legacy one
  config.py            LEGACY (Experiment 1), unchanged
  study_config.py      NEW  WP1  config loader + validation ("gauntlet")
  logs.py              NEW  WP6  row schemas, append-only writer, readers
  providers/           hp/providers.py moved here as __init__.py (needs approval, §7)
    __init__.py        current code, plus a `contract` parameter (default = legacy)
    google.py          NEW  WP2
    openweight.py      NEW  WP2  wraps the Ollama backend
    synthetic.py       NEW  WP2  nine-model synthetic world
  bank/                NEW  WP3  vul4j, reproduce, generate, classify, sibling, select, split
  review/              NEW  WP4  input, packets, schedule, dispatch
  analysis/            NEW  WP5  rates, thresholds, policies, regret, commonmode,
                                 confirm, extension, report
  design.py dataset.py estimators.py bootstrap.py report.py runner.py
                       LEGACY (Experiment 1); estimators and some runner/bootstrap
                       helpers are reused, never edited
study.py               NEW  CLI: reproduce | generate | classify | sibling | select |
                            review | analyse-dev | freeze | confirm | report
study.jsonc            NEW  live config; every pin = "TO_PIN_AT_FREEZE"
study.synthetic.jsonc  NEW  offline config: nine synthetic models, mock Vul4J
tests/study/           NEW  all new tests; legacy tests stay where they are
```

Import order: `schema → config / study_config → logs → bank.split → providers → bank.vul4j → bank.{reproduce, generate, classify, sibling, select} → review.* → estimators → analysis.* → study.py`.

### 1.2 Table

| Spec module | Job | Existing code it builds on | Decision | WP |
|---|---|---|---|---|
| `bank/vul4j.py` | Checkout, compile and test in the pinned container; per-test results | none | **New.** A `Vul4JRunner` interface; `MockVul4J` for tests (driven by a synthetic world: flaky tests, signatures, per-attempt outcomes); `ContainerVul4J` shells out to the Vul4J CLI in a pinned container (not exercised offline; image digest is a placeholder). Failure signatures come from the surefire XML reports (exception type, or assertion message and location), because Vul4J's own summary may not carry them (risk R1). | WP3 |
| `bank/reproduce.py` | Stage 1, `reproduction.jsonl` | none | **New.** 10/10 rule; signature capture; ordinary tests = the set passing on both versions in all 10 runs; flaky tests listed; statuses `eligible / build_fail / pov_unstable / suite_unstable`. | WP3 |
| `bank/generate.py` | Stage 2, `attempts.jsonl` | `providers.call_with_retries`, the status taxonomy, `runner.read_log` / `done_ids`, `ModelDriftError` | **New.** Generation input built by a function whose signature cannot take the PoV (same pattern as `config.build_prompt`); identical for all generators; 10 fresh calls per (c, g); needs a text-output mode in the providers (diff, not JSON). Test-split CVEs refused before freeze. | WP3 |
| `bank/classify.py` | The six classes | none | **New.** `apply_fail, build_fail, regression_fail, blocked, near_miss, indeterminate`; `near_miss` needs a signature match in 10/10; `context_overflow` → `indeterminate` with that reason. | WP3 |
| `bank/sibling.py` | V→F | none | **New.** Ingests author-written F diffs from a directory; validates F 10/10 (ordinary tests and PoV); records the V→F diff and its size; rubric checks (no added comment lines, changed-line count). In synthetic mode the mock writes F. | WP3 |
| `bank/select.py` | Dedup and selection | the `random.Random(seed)` convention | **New.** Whitespace-normalised dedup within (c, g); seeded uniform pick; inclusion probability 1/k; signature takes no review data; seeded correction order (core twins first, then extension; stopping point logged; SPEC_ANSWERS Q21). | WP3 |
| `bank/split.py` | Split and test lock | `config._sha12` | **New.** Loads `docs/spec/proposed_split.json` read-only and checks its SHA-256 against the value pinned in the config. `assert_accessible(cve, cfg)` raises for test CVEs unless `freeze.frozen` is true **and** the frozen config hash and code hash both match. Called by `generate`, `sibling`, `review.schedule` and `review.dispatch`. | WP3 |
| `review/input.py` | e₀; hashing; stripping | `config.build_prompt` (isolation by signature), `Task.prompt_inputs` | **New, same pattern.** The builder only receives reviewer-visible fields (advisory summary, diff, post-patch method context). It never receives the CVE ID, project, commit, generator, sibling or PoV. A deny-list scan runs on the built text before dispatch. Every input is SHA-256 hashed. | WP4 |
| `review/packets.py` | Experiment B packets | `tools/make_demo_tasks.py` (offline-built, hashed packets) | **New.** Three packet kinds, 3,000-token cap, built offline, hashed. Builder fidelity is an open question (Q13). | WP4 |
| `review/schedule.py` | Crossed schedule x × r × j | `design.build_schedule` (global shuffle), `runner.eligible_order` | **New schedule.** Core table; extension when enabled; Experiment B. `panel_key := candidate_id`, so `eligible_order` enforces "no two calls on one candidate in flight" unchanged. Call IDs and seeds derive from content, not position, so core calls are identical with and without the extension. | WP4 |
| `review/dispatch.py` | Run and resume | `runner.run` (pattern), `done_ids`, `read_log`, `eligible_order`, `ModelDriftError`, `call_with_retries` | **New runner reusing those helpers.** Legacy `runner.run` unchanged. | WP4 |
| `analysis/rates.py` | U, A, C per cell | `bootstrap._mean`, the two-stage aggregation idea | **New.** Trials → candidate → CVE → generator row → equal-generator average; never pools calls; fail-closed coding. | WP5 |
| `analysis/thresholds.py` | t_r, t_p, t_o | none | **New.** Smallest observed cut-off with A ≥ 0.90; `infeasible` if none; one threshold per reviewer, shared by every policy. | WP5 |
| `analysis/policies.py` | Fixed, Generator-aware, Exclusion | `bootstrap.contrast_composition` (legacy only, not reused) | **New.** Core table only; ties broken by cost, then model ID. | WP5 |
| `analysis/regret.py` | Primary-contrast rule | `bootstrap.cluster_bootstrap` draw convention | **New.** 2,000 cluster resamples of development; thresholds refit inside each resample; writes the primary choice to a frozen file. | WP5 |
| `analysis/commonmode.py` | q, t, gaps, dt/dq, 36 matchings | `estimators.marginals, pairwise, joint_all, gate_risk, recomb_stat, poisson_binomial_ge_k, frechet_triple_bounds, cell_stats, gate_gap_sign_note` | **Extend by wrapping.** `estimators.py` is not edited; the wrapper renames outputs (`D` → `d_gate_2of3`, …). Within-patch reference only within a candidate. Which reference is meant is Q5/Q6. | WP5 |
| `analysis/confirm.py` | Test-set inference | `bootstrap.holm`, the percentile and p-value conventions | **New.** 10,000 cluster resamples; §15.3 decision rules; Holm over {RQ1, RQ2} or {RQ1, RQ2, RQ2o}; refuses to run unless the frozen config hash matches. | WP5 |
| `analysis/extension.py` | RQ2o, D_diag (open block), Δ₆, promotion check, pipeline risk by group | none | **New** (definitions from SPEC_ANSWERS Q21). | WP5 |
| `analysis/report.py` | Full report | `report.py` (legacy formatting helpers `_fmt`, `_sanitize`) | **New;** legacy report untouched. | WP5 |
| `providers/openweight.py` | Open-weight serving with pins | `providers._ollama` | **New wrapper** (§3). | WP2 |
| Google adapter | Family 3 | none | **New** (§3). | WP2 |
| Study config + gauntlet | All of WP1 | `config.ConfigError`, `_PINNED`, `_sha12`, the temperature rule | **New module.** Legacy `config.load` unchanged. | WP1 |
| Logs (§18.3) | `attempts.jsonl`, `reviews.jsonl` (+ extension fields) | the runner's append-only writer | **New** `hp/logs.py`. | WP6 |
| `schema.py` | verdict / risk / justification | `parse_verdict`, `_json_candidates` (balanced-brace fallback), the status taxonomy | **Extend.** A `ReviewContract` object; `parse_verdict(payload, contract=LEGACY)` keeps legacy behaviour by default. | WP2/WP4 |

---

## 2. Experiment 1 pieces, and what to do with each

Recommended labelling: **Option A**. Leave the files where they are (no import churn; all 79 tests untouched), put a `LEGACY: Experiment 1` banner in each docstring and in the README, and add `"mode": "legacy_exp1"` to `experiment.json` and `experiment.offline.json` (a missing `mode` is still read as legacy, so old configs keep loading). Option B would move them to `hp/legacy/` with re-export shims at the old paths; that is more churn for no functional gain.

| Piece | Where it lives | Proposal |
|---|---|---|
| Panel compositions AAA/BBB/CCC/ABC | `config` (panels), `design.build_schedule`, `bootstrap.contrast_composition`, `dataset.build_cells` (`homogeneous`) | **Keep as legacy.** The new study has fixed panels (cheap a/b/c; open X/Y/Z) and no composition factor. |
| Context regimes shared/diverse, cyclic packet map, B1–B3, seat/channel rotation | `design.packet_index`, `design.assert_balanced`, `config` divisibility rules | **Keep as legacy.** There is no regime factor in v1.3. Experiment B is fully crossed (reviewer × packet), so no rotation is needed. |
| Packet rotation | same | **Keep as legacy.** |
| Holm over three hypotheses | `bootstrap.CONFIRMATORY`, `bootstrap.holm`, `test_holm_corrects_across_exactly_three_confirmatory_tests` | **Keep the legacy dict and its test.** Reuse the `holm()` function in `analysis/confirm.py` with the new family. |
| Placeholder bank `tasks/<id>/manifest.json`, `tools/make_demo_tasks.py` | `tasks/`, `tools/` | **Keep as the legacy demo bank.** The new bank is built by the pipeline under `runs/<study>/bank/`; the synthetic bank is generated by test fixtures. |
| Missing-as-missing coding | `dataset.build_cells`, `report.analyse` | **Keep for legacy.** The new path is fail-closed (Q1). |
| Legacy runner, CLI and configs | `runner.run`, `main.py`, `analyze.py`, `experiment*.json` | **Keep runnable.** Optional: make a non-synthetic legacy run require an explicit `--legacy-paid` flag, since `experiment.json` holds real-looking model IDs for a design that has been merged away. |
| `harness.py` shim | top level | **Keep.** It imports `hp.providers`, which still works after the package move. |

**Reused unchanged from legacy:** `estimators.*` (all functions listed in §1.2), `bootstrap.holm`, `runner.eligible_order`, `runner.read_log`, `runner.done_ids`, `runner.ModelDriftError`, `providers.call_with_retries` / `_classify` / `_record`, `schema` status constants and `_json_candidates`, `config.ConfigError` / `_sha12` / `_PINNED`.

**Legacy tests to retire: none.**

---

## 3. Provider adapters

| Provider | Exists? | Structured output | Truncation signal | Drift check | Gap to close in WP2 |
|---|---|---|---|---|---|
| `anthropic` | yes | forced `tool_use` | `stop_reason == "max_tokens"` | `r.model` echo → abort | pass the contract (v1.3 schema); text mode for generation; top-p and reasoning settings passed through from config, never hard-coded |
| `openai` | yes (Responses API) | `json_schema`, strict | `incomplete_details.reason == "max_output_tokens"` | `r.model` echo → abort | same; strict schema for v1.3 (range limits checked locally, as now); reasoning effort passed through |
| `ollama` | yes | `format=<schema>` | `done_reason == "length"` | none (echoes the requested id) | becomes the base of `openweight` |
| **`google`** | **no** (confirmed: not in code or docs; the status doc lists only Anthropic, OpenAI, Ollama) | JSON response with a response schema | finish reason = max tokens | served model version echo → abort | **new adapter** on the `google-genai` SDK, lazily imported; error classification by class name and the SDK's status-code attribute; credentials from an env var named in config. Exact SDK fields to be checked against its documentation when I write it; tested only with a fake client. |
| `synthetic` | yes (3 models, packet lift) | dict | n/a | echo | **new nine-model world**, see below |

Families 1–3 (strong and cheap each) are six API models over three adapters: A/a, B/b, C/c. Families 4–6 are X, Y, Z (tier `open`) via `openweight`.

**`providers/openweight.py`**
- At start-up: read the server version, the model digest and the quantisation from the serving stack; compare with `weights_sha`, `precision` and `serving_stack` in the config; raise `ModelDriftError` on any mismatch. Proposed addition: re-check at the end of each run, and every N calls (N in config).
- Set the context length explicitly from config. Ollama silently truncates prompts to its context length, so overflow is detected by comparing the reported prompt token count with a pre-count. On overflow: status `request_error` with `reason: "context_overflow"` (this keeps the six statuses). In review that means fail-closed non-approval; in generation the attempt is classed `indeterminate (context_overflow)`.
- Log `weights_sha`, `precision`, `serving_stack`, `gpu_seconds` (from the reported eval durations × the configured GPU count).
- Cost: primary = hosted-provider price per token; sensitivity = GPU-seconds × GPU-hour price. Both prices are placeholders.

**Synthetic world (nine models: A, B, C, a, b, c, X, Y, Z).** Deterministic and hash-based (as now). Per-call approval and risk score depend on:
- the reviewer's base rate, separately on V and F;
- a per-candidate shared difficulty (common to all reviewers);
- a concentrated common cause (with probability w a candidate fools a chosen set of reviewers together);
- a same-model blind spot (generator == reviewer) and an optional same-family term;
- injectable failures (timeout, truncation, schema violation, abstain) at set rates.

To keep oracle isolation intact even in tests, the synthetic provider never reads the generator from the prompt. It looks up an opaque `candidate_id` in a world file that only the synthetic config and fixtures can load.

---

## 4. Naming collisions and the identifiers I will use

| Symbol | Legacy meaning | Spec meaning | Identifier in new code |
|---|---|---|---|
| `D` | gate excess R_obs − R_recomb (k-of-n) | D(2/3), D(3/3) gate excess; **D_diag** for the RQ5 contrast (§14.4) | `d_gate_2of3`, `d_gate_3of3`, `d_diag`. Legacy keys `D` / `D_unan` stay inside `estimators.py`; the wrapper translates them. |
| `A` | amplification R_obs / R_recomb | corrected acceptance; also **model A** | `amp_gate_2of3`; `accept_rate`; `"A"` used only as a model reference |
| `U` | — | unsafe approval | `unsafe_rate` |
| `C` | co-failure ratio q / q_recomb | paired discrimination C_r; also **model C** | `cofail_ratio`; `discrimination` (+ `tie_rate`) |
| `t` | triple co-approval | thresholds t_r, t_p, t_o | `triple_t`; `thr[r]`, `thr_panel_cheap`, `thr_panel_open` |
| `R` | replicate count; R_{k/n} | R₂, R₃; three trials | `gate_2of3`, `gate_3of3`; `n_trials` |
| `attempt` | operational retry index (log field) | one generated repair | `reviews.jsonl` keeps `attempt` = operational retry (as §18.3 lists it); a generated repair is `attempt_id`; operational retries inside `attempts.jsonl` are `call_attempt` |
| replicate / trial | panel replicate | trial j per (x, r) | `trial` |
| panel | composition template | cheap panel a/b/c; open panel X/Y/Z | `panel_cheap`, `panel_open` |
| `p` | marginal rate | — | marginals `p_j`; p-values always `p_value` |
| status names | `schema_invalid`, `request_error` | `schema_violation`, `reject` | keep the code's names (Q2) |
| `A` vs `a`, `B` vs `b`, `C` vs `c` | — | model references that differ only in case | **never used as file or directory names**: the default macOS file system is case-insensitive, so `runs/A.jsonl` and `runs/a.jsonl` would be the same file. File names use slugs such as `fam1-strong`, `fam1-cheap`, `fam4-open`. |

---

## 5. Spec ambiguities

All 22 items in `SPEC_QUESTIONS.md` are answered in `docs/spec/SPEC_ANSWERS.md`. §9 maps each answer to the code that implements it.

---

## 6. Work packages: content

**WP0: baseline.** Commit the current untracked tree unchanged ("baseline: Experiment 1 harness, 79 tests"). No code changes.

**WP1: config and validation.** `study.jsonc` (JSON with `//` comments, parsed by a small standard-library comment stripper; the config hash is taken over the parsed canonical JSON, so comments never change it). Every value the spec marks **[default …]** carries a `// [default §n]` comment, and a test checks that the shipped file has such a comment on each registered default key. The loader **never** fills in spec values with `setdefault`: if one is missing, it refuses.

```jsonc
{
  "mode": "synthetic",                 // "synthetic" | "live"
  "seed": 20260930,                    // §6 global seed
  "split": {"file": "docs/spec/proposed_split.json", "sha256": "TO_PIN_AT_FREEZE"},
  "models": {
    "A": {"roles": ["generator", "reviewer"], "family": 1, "tier": "strong",
          "provider": "anthropic", "model": "TO_PIN_AT_FREEZE", "snapshot": "TO_PIN_AT_FREEZE"},
    "a": {"roles": ["reviewer"], "family": 1, "tier": "cheap", "provider": "anthropic",
          "model": "TO_PIN_AT_FREEZE", "snapshot": "TO_PIN_AT_FREEZE"},
    "X": {"roles": ["generator", "reviewer"], "family": 4, "tier": "open", "provider": "openweight",
          "model": "TO_PIN_AT_FREEZE", "weights_sha": "TO_PIN_AT_FREEZE",
          "precision": "TO_PIN_AT_FREEZE", "serving_stack": "TO_PIN_AT_FREEZE"}
    // … B, b, C, c, Y, Z
  },
  "sampling": {"temperature": 0.7, "top_p": 1.0, "reasoning": "medium_or_equivalent"},  // [default §6]
  "caps": {"gen_output_tokens": 8000, "review_input_tokens": 8000, "review_output_tokens": 2000},
  "timeouts_s": {"review": 120, "generation": 300},          // [default §6]
  "max_attempts": 4,                                          // 1 call + ≤3 retries (§6)
  "prices": {"A": {"in_per_mtok": "TO_PIN_AT_FREEZE", "out_per_mtok": "TO_PIN_AT_FREEZE"}},
  "openweight_cost": {"primary": "hosted_price", "sensitivity": "gpu_seconds",
                      "gpu_hour_price": "TO_PIN_AT_FREEZE"},
  "acceptance_target": 0.90,
  "margins": {"sesoi_unsafe": 0.10, "ni_accept": 0.10, "ni_unsafe": 0.10},
  "bootstrap": {"regret_draws": 2000, "confirm_draws": 10000},
  "regret": {"delta": 0.05, "stability_share": 0.80},
  "extension": {"enabled": false, "paid_block_on_test": true,
                "rq2o_mode": "promotion_rule"},             // [extension default]; enabled must be explicit (Q21)
  "vul4j": {"runner": "mock", "image_digest": "TO_PIN_AT_FREEZE"},
  "freeze": {"frozen": false, "config_sha256": null, "code_sha256": null}
}
```

Refusal conditions added to the gauntlet:
1. A required key is missing (no silent defaults for spec values).
2. Model set is not {A, B, C, a, b, c}, or not ∪ {X, Y, Z} when the extension is on.
3. Roles, families and tiers are inconsistent: a cheap model listed as generator; fam(A) ≠ fam(a); strong and cheap of one family on different providers; X, Y, Z not in distinct families 4–6.
4. Temperature ≤ 0 (the existing rule), or top-p outside (0, 1].
5. **Live mode with any `TO_PIN_AT_FREEZE`** anywhere in models, prices, Vul4J image, open-weight pins or the split SHA.
6. Live mode with any synthetic provider or the mock Vul4J; **synthetic mode with any non-synthetic provider** (so a synthetic config can never spend money).
7. Pin shape: API models need a snapshot; open models need a 64-hex SHA-256, a precision from an allowed list, and a non-empty serving stack.
8. Caps not positive integers, or an open model's context length too small for the review input cap plus prompt overhead.
9. Acceptance target or regret parameters outside (0, 1]; margins ≤ 0; in live mode, fewer than 2,000 regret or 10,000 confirmatory draws.
10. `rq2o_mode` not in {`promotion_rule`, `fixed_sequence`}; `paid_block_on_test` not boolean.
11. Split file SHA-256 differs from the pinned value.
12. `freeze.frozen` is true but the recomputed config hash (config without its `freeze` block), the code hash (`hp/` tree) or the frozen artefacts (primary choice, thresholds) do not match.
13. A prompt template is missing a required slot; template hashes are logged.

**WP2: providers.** Move `hp/providers.py` → `hp/providers/__init__.py` (`git mv`, content unchanged); add the `contract` parameter; add text mode; Google adapter; `openweight.py`; nine-model synthetic world. Tests use fake clients only.

**WP3: task-bank pipeline.** As in §1.2. Test-split lock wired in from the first commit of this package.

**WP4: review.** `review/input.py` (e₀, stripping, hashing, deny-list scan), `review/packets.py`, `review/schedule.py`, `review/dispatch.py`. Output schema verdict / risk 0–100 / justification ≤ 150 words. Experiment B schedule: cheap reviewers × 3 packets × 12 seeded development CVEs.

**WP5: analysis.** As in §1.2. Core analysis reads only rows with generator ∈ {A, B, C} and reviewer ∈ {A, B, C, a, b, c}. The filter is applied at log load, so no downstream function can see extension rows.

**WP6: logs.** `reproduction.jsonl`, `attempts.jsonl`, `reviews.jsonl` with every §18.3 field, extension fields empty for commercial calls, plus the extra logs proposed in Q18. A `recompute` check rebuilds the full report from the logs alone and compares it byte for byte.

**WP7: tests.** All under `tests/study/`; the 79 legacy tests unchanged.

| Test | File |
|---|---|
| Classifier rejects a PoV failure with a different signature | `test_classify.py` |
| Selection unchanged when review outcomes are permuted | `test_select.py` |
| Threshold = smallest cut-off meeting 0.90 on a known score set; infeasible case | `test_thresholds.py` |
| Exclusion = Fixed in every row except fam(r\*)'s | `test_policies.py` |
| The same threshold is used for a reviewer under every policy | `test_policies.py` |
| Regret rule passes two tied reviewers and fails a clearly worse one | `test_regret.py` |
| Within-patch gap ≈ 0 under conditional independence | `test_commonmode.py` |
| dt/dq > 3/2 recovered from a planted concentrated common cause (reference: Q6) | `test_commonmode.py` |
| 0 / 0.216 / 0.30 / 0.45 for three reviewers at 30% (exact multisets via `tests/dgp.py`) | `test_commonmode.py` |
| D_diag recovers a planted diagonal bump exactly and ignores additive generator and reviewer effects | `test_diag.py` |
| Test split unreachable without the freeze flag and a matching hash | `test_split.py` |
| No generator identity, CVE ID, project name, commit hash or PoV token in any review input | `test_review_isolation.py` |
| Schedule sizes: 2,484 / 6,048; 7,452 / 18,144 with the extension; Experiment B ≤ 1,944; core calls identical with and without the extension | `test_schedule.py` |
| RQ2o promotion fires only when all three §15.7 conditions hold | `test_extension.py` |
| Core estimates bit-identical with and without extension rows in the logs | `test_extension_isolation.py` |
| Live mode refuses placeholder pins; synthetic mode refuses real providers | `test_study_config.py` |
| Reproduction statuses, 10/10 rule, flaky-test exclusion; `context_overflow` → `indeterminate`; sibling validation | `test_reproduce.py`, `test_classify.py`, `test_sibling.py` |
| Fail-closed coding of abstain, invalid, timeout, truncation, unresolved | `test_rates.py` |
| Admission rule keyed on the candidate | `test_dispatch.py` |
| Open-weight checksum, precision or server mismatch aborts | `test_openweight.py` |
| Google adapter: schema, truncation, drift abort (fake client) | `test_google.py` |
| Synthetic world: planted shared difficulty, concentrated cause, same-model blind spot are recovered | `test_synthetic_world.py` |
| End to end: development and test, nine models, freeze, confirm, full report; re-derived from logs alone | `test_study_e2e.py` |

Runtime: schedule-size tests only build schedules (no calls). The end-to-end test in pytest uses a reduced synthetic bank (about 8 development and 12 test CVEs) so that the suite stays well under a minute; `study.py selftest --full` runs the same path at the spec's maxima outside pytest.

**WP8: docs.** README section for the new study; a new `docs/study.html` (or a section in `docs/internals.html`) with a table spec § → module → test; `CHANGELOG.md`; a "still placeholder" list.

---

## 7. Approvals (granted 2026-10-09 by "proceed with WP1")

Items 2–8 are taken as approved together with the plan. Item 1 is superseded by SPEC_ANSWERS.

1. **Proceed now on v1.0 + brief, or wait for v1.2** in `docs/spec/`. My recommendation: wait for v1.2 before WP1; WP0 can go ahead now.
2. **WP0 baseline commit** of the untracked tree, and the one-time git delete permission it needs.
3. **Moving `hp/providers.py` to `hp/providers/__init__.py`** (content unchanged, `git mv`; every existing import keeps working). Alternative: keep the file and put the new adapters in `hp/backends/`.
4. **Legacy Option A** (keep in place and label) rather than B (move to `hp/legacy/`).
5. **Adding the network guard to `tests/conftest.py`** (an addition; no test changes).
6. **JSONC** as the config format (alternatives: TOML needs a dependency on Python < 3.11; YAML needs a dependency).
7. **No legacy tests retired.**
8. The reduced-size end-to-end test in pytest, with the full-size run as a script.

---

## 8. Risks I can already see

- **R1 Failure signatures.** Vul4J's test summary may not include the exception type or assertion message; the plan parses the surefire XML reports. Must be confirmed against the real container.
- **R2 Silent truncation** of prompts by Ollama (handled in WP2, but worth knowing).
- **R3 Java method boundaries** without a parser: a hand-written brace and comment-aware scanner; fallback to changed hunk ±50 lines; which path was used is logged per input.
- **R4 Runtime of 10/10 full-suite runs** on some Vul4J projects (Q19).
- **R5 Advisory summaries** (the neutral, CVE-free description used by both generator and reviewer) are hand-written inputs; the code can check them for forbidden tokens but cannot write them.
- **R6 Synthetic success is not real success.** The end-to-end run proves the wiring, not that real Vul4J, real providers or real yields behave.

---

## 9. SPEC_ANSWERS → where each decision lives in code

| Q | Decision | Implemented in | Tested in |
|---|---|---|---|
| Q1 | Fail-closed on the new path only; unresolved = no `ok` after 4 attempts **across resumes**; unresolved counts per (reviewer, state) | `review/dispatch.py` (attempt budget counted from the log), `analysis/data.py` (coding), `analysis/report.py` | `test_dispatch.py`, `test_rates.py` |
| Q1 | C uses valid trials only; pairs without a valid V or F trial excluded and counted | `analysis/rates.py::discrimination` | `test_rates.py` |
| Q1 | Worst-case sensitivity: abstain/invalid/unresolved = approve on V, reject on F | `analysis/data.py` coding `worst_case` | `test_rates.py` |
| Q2 | Keep the code's status names | `schema.py` (unchanged) | legacy `test_schema.py` |
| Q3 | Literal rule (a reject verdict with risk ≤ t approves); verdict–threshold disagreement rate per reviewer | `analysis/data.py`, `analysis/report.py` | `test_rates.py` |
| Q4 | Risk: any number in [0, 100]; long justification valid; `justification_words` recorded | `schema.py` v1.3 contract | `test_schema_v13.py` |
| Q5 | Within-patch gap = plug-in, labelled "design check, expectation 0"; distinct-trial recombination reported next to it | `analysis/commonmode.py` | `test_commonmode.py` |
| Q6 | Benchmark-level reference is primary for dq, dt, dt/dq; within-patch versions logged and labelled | `analysis/commonmode.py` | `test_commonmode.py` |
| Q7 | Hierarchical aggregation; feasibility per reviewer; row-level A reported; panel primary = mean over 36 matchings = h(p̂(x)); identity matching is the check | `analysis/rates.py`, `analysis/thresholds.py`, `analysis/commonmode.py` | `test_thresholds.py`, `test_commonmode.py` |
| Q8 | Two-sided 95% percentile intervals reported; one-sided bootstrap p per component at 0.025; hypothesis p = max; cost ratio a component; Holm at one-sided 0.025 with adjusted bounds; RQ1 equivalence outside Holm | `analysis/confirm.py` (reuses `bootstrap.holm`) | `test_confirm.py` |
| Q9 | Core bootstrap frame = clusters with ≥ 1 evaluable core pair, from core rows only; extension uses its own list | `analysis/confirm.py`, `analysis/extension.py` | `test_extension_isolation.py` |
| Q10 | **All** thresholds (nine reviewers, t_p, t_o) fit on core development rows only | `analysis/thresholds.py` | `test_thresholds.py`, `test_extension_isolation.py` |
| Q11 | bytes/4 proxy; enclosing method ±50 lines; symmetric context trimming; `truncated_context`; diff over cap → pair `indeterminate (review_input_overflow)` | `review/input.py` | `test_review_input.py` |
| Q12 | Strict deny list; packages, imports and paths kept; allowed project tokens recorded per CVE | `review/input.py` | `test_review_isolation.py` |
| Q13 | Exclude the whole PoV test file; lightweight finder, method recorded | `review/packets.py` | `test_packets.py` |
| Q14 | Build once per attempt, then 10 clean test reruns; ordinary failure inside reruns → `indeterminate (inconsistent)` | `bank/classify.py`, `bank/vul4j.py` | `test_classify.py` |
| Q15 | ≤ 10 lines flagged, not enforced; comment definition; select then correct; infeasible F drops the cell, no redraw | `bank/sibling.py`, `bank/select.py` | `test_sibling.py`, `test_select.py` |
| Q16 | Sampling parameters may be omitted only via an explicit per-model flag with a deviation note; logged and reported | `study_config.py`, providers | `test_study_config.py` |
| Q17 | Pin rule per provider (config regexes); echo abort for API models; open weights verified at start-up, end of run and on every server (re)load | `study_config.py`, `providers/openweight.py`, `review/dispatch.py` | `test_openweight.py` |
| Q18 | Extra logs `reproduction.jsonl`, `selection.jsonl`, `siblings.jsonl`, `freeze.json` | `hp/logs.py` | `test_logs.py`, `test_study_e2e.py` |
| Q19 | Both suite scopes behind config (default full); `timing_pilot` command | `bank/vul4j.py`, `bank/classify.py`, `study.py timing-pilot` | `test_classify.py`, `test_timing_pilot.py` |
| Q21 | RQ2o, promotion rule, Δ₆, open-block D_diag, pipeline split, `paid_block_on_test`, explicit `extension.enabled`, Exp B without open models, seeded correction order | `analysis/extension.py`, `analysis/regret.py`, `review/schedule.py`, `bank/select.py`, `study_config.py` | `test_extension.py`, `test_schedule.py` |

## 10. v1.3 reconciliation list (filled provisionally, check against v1.3 when it arrives)

These are details that v1.3 itself fixes but neither SPEC_ANSWERS, v1.0 nor the brief states. Each is isolated in one function or config value, and each is listed again in the docs.

1. **§7 step 6, `suite_unstable`.** Provisional rule: a CVE is `suite_unstable` if any of its 20 Stage-1 runs did not complete, or if its ordinary-test set is empty. Flaky tests are excluded and listed; they do not disqualify a CVE on their own. (`bank/reproduce.py::status_for`)
2. **Which values are [default] / [extension default].** Provisional: v1.0 §6 markers (generation sampling, reasoning, caps, timeouts, margins), plus `paid_block_on_test`, `rq2o_mode` and the §15.7 promotion margins. The config comments say which source each marker comes from.
3. **`fixed_sequence` mode.** Provisional: Holm over {RQ1, RQ2}; RQ2o is tested after RQ2 and can only be rejected if RQ2 is, with adjusted p = max(adjusted p of RQ2, p of RQ2o).
4. **RQ2o margins on test.** Provisional: the RQ2 margins (+0.10 on U, −0.10 on A, cost ratio < 1).
5. **Projected half-width (§15.6, promotion condition iii).** Provisional: resample development clusters up to the number of test clusters in the split (33), `regret_draws` draws, half-width = half the two-sided 95% percentile interval.
6. **RQ6** is taken to be Δ₆ (§14.8), development-only when `paid_block_on_test` is false.
7. **"Fixed model-ID order"** for ties: ASCII order of model references (A < B < C < X < Y < Z < a < b < c).
8. **Policy pools.** r\* (Fixed), Generator-aware and Exclusion choose among the six core reviewers; strong\* among A, B, C; best cheap single among a, b, c.
9. **Exclusion regret.** Only the generator in fam(r\*) gets a replacement; its regret is against the best eligible reviewer outside that family, on overall U.
10. **Logit scale.** Empirical logit with ε = 1/(2N), N = trial-level calls in the cell.
11. **"Indeterminate-adjacent" CVEs (§15.5 item 7).** CVEs with at least one `indeterminate` attempt.
12. **RQ3 strata.** Similarity terciles and patch-size terciles on the V candidates of the analysed split; weakness class = advisory CWE.
13. **Experiment B subset.** 12 development CVEs drawn by seed from those with at least one core pair.
14. **Signature.** (exception type, whitespace-normalised message, first stack frame inside the PoV test class).
15. **Cost.** Summed over every logged attempt of a call, retries included.
16. **Closing a call.** A call closes on `ok`, on 4 logged attempts, or on a non-retryable status (schema_invalid, truncated, request_error); a resume continues only calls cut off while still retryable, so results never depend on how often a run was resumed.
17. **Leak scan hit.** A review input that trips the deny list excludes the pair (status `leak`, V and F together), like an overflow, and is reported.
18. **`inputs.jsonl`.** Logged in addition to the Q18 logs; it records overflow and leak exclusions.
19. **Panels in RQ3.** Cheap panel at t_p (primary), strong panel with each member at its own threshold (descriptive), open panel at t_o.
20. **Valid trial for C.** A call that ended `ok` (an abstention with a risk score counts).

Added after the independent code review (10 October; regression tests in `tests/study/test_review_fixes.py`):

21. **Completeness.** `analyse-dev` and `confirm` rebuild the schedule from the logs and refuse when a scheduled call has no row or is still open (`analysis/report.completeness`). Before this, a stopped run could be analysed with its missing calls coded fail-closed.
22. **Local faults.** A missing API key or SDK raises `engine.LocalFault` and stops the run; nothing is logged for the call, so it is never counted as a model failure.
23. **Attempts logged as they end.** Every attempt is appended when it ends (`on_attempt`), so a killed run keeps the attempts already made and the four-attempt budget holds across resumes. `logs.append` starts a new line after a partial one.
24. **Re-freezing.** Allowed, and recorded in `freeze_history.jsonl`, until the test split holds generation, twin, input or review rows; refused after. `confirm` also refuses test rows whose `config_sha256` differs from the frozen one.
25. **What the freeze hashes.** Config (without the freeze block), the running `hp/` package and `study.py`, the prompts, the frozen artefacts and `<paths.inputs>/advisories`.
26. **Leak-scan identity terms** are per model in the config (`identity_terms`), required as a non-empty list in live mode.
27. **Bound convention.** One-sided bounds and p-values agree by construction (bound beyond b ⇔ p ≤ α); a resample with an undefined value counts against the claim in both.
28. **Undefined rather than averaged around.** Pipeline risk: a generator row is undefined when an eligible CVE with near-misses has no U. Δ6: infeasible reviewers are left out and listed. D_diag: a block with an infeasible reviewer is undefined.
29. **Several PoV tests.** Stage 1 requires one stable signature per PoV test (the earlier code required one signature across all of them).
30. **Counts next to rates.** Every per-cell U, A, C in the development and test reports carries its unresolved trials per state and the pairs left out of C (with the share); totals per reviewer and overall. (The earlier docs said these were counted; they were counted in code but not reported.)
31. **Container workspaces.** `ContainerVul4J` removes each workspace on release (contents first from inside the container, since they may be root-owned), keeps one source-only checkout per (CVE, version) for file reads, and caches `vul4j info`.

