# SPEC_QUESTIONS: open points in the specification

**Status (2026-10-09): all 22 items answered in `docs/spec/SPEC_ANSWERS.md`.** The text below is the original Step 0 question list, kept unchanged for the record.

Written 2026-10-09 during Step 0. Each item gives where it comes from, the problem, why it matters, a **proposed default**, and what it blocks.

**None of the defaults is applied until you answer.** Section numbers are v1.0's unless marked otherwise, because v1.2 was not available (Q0).

## Index

| ID | Topic | Blocks |
|---|---|---|
| Q0 | Specification v1.2 is not available | yes |
| Q1 | Fail-closed coding: new path only, and three details | yes |
| Q2 | Status names | no |
| Q3 | Does a `reject` verdict with a low risk score count as approval? | no |
| Q4 | How strict the output schema is | no |
| Q5 | Which within-patch reference, and what can it detect? | yes |
| Q6 | Which reference do dq, dt and dt/dq use, and how should the concentrated-cause test work? | yes |
| Q7 | Aggregation for thresholds, gaps and panels | yes |
| Q8 | How Holm combines with the interval decision rules | yes |
| Q9 | Which clusters the bootstrap resamples | yes |
| Q10 | Extension thresholds and bit-identity | yes |
| Q11 | The 8,000-token review input cap | yes |
| Q12 | How far identifier stripping goes | yes |
| Q13 | Experiment B packets: PoV leakage and how good the builders must be | no |
| Q14 | Classification rerun protocol | no |
| Q15 | Sibling rubric and the order of selection and correction | no |
| Q16 | Reasoning setting against temperature and top-p | no |
| Q17 | Pin rules per provider | no |
| Q18 | Logs beyond §18.3 | no |
| Q19 | Runtime of 10/10 full test suites | no |
| Q20 | Two v1.0 statements that the brief contradicts (probably fixed in v1.2; please confirm) | no |
| Q21 | Extension items that exist only in v1.2 | yes |

---

## Blocking

### Q0. Specification v1.2 is not available
- **Where:** brief, "Sources of truth".
- **Issue:** `docs/spec/` does not exist. Neither the repo nor the project contains `Experiment_Specification_v1_2.md`. The project's `experiment_notes.tex` (5 Oct) and spec v1.0 (30 Sep) contain no extension, no open-weight models, no RQ2o, no §12.6 and no §15.7.
- **Why it matters:** the brief says the spec wins on details, and several work packages exist only in v1.2 (see Q21).
- **Proposed default:** none. Please add v1.2, your current `experiment_notes.tex` and `proposed_split.json` to `docs/spec/`. I then re-check PLAN.md and this file against it before WP1.
- **Blocks:** WP1 onwards.

### Q1. Fail-closed coding: new path only, and three details
- **Where:** brief ("keep every existing invariant: fail-closed coding"); v1.0 §11.5, §11.6.
- **Issue:** fail-closed is not an existing invariant. The current code treats non-`ok` calls as missing and drops incomplete panels (`dataset.build_cells`; internals §11.1), on the argument that coding a timeout as a rejection biases gate failure downward on the hardest items. The spec reverses that rule.
- **Why it matters:** on V, fail-closed makes a reviewer that times out look safer; on F it makes it look stricter. If loss rates differ by provider or by verbosity (the legacy docs say they do), this moves U and A per reviewer.
- **Proposed default:**
  - fail-closed on the new path only, with the per-(reviewer, state) unresolved counts reported next to every rate; legacy path unchanged;
  - "unresolved" means no `ok` record after `max_attempts` = 4 attempts **in total across resumes** (otherwise each resume would keep re-rolling failed calls);
  - for discrimination C (§14.5), a candidate–trial with no valid risk score counts as risk 100 on both V and F. Alternative: drop the pair and report how many were dropped.
- **Blocks:** WP4, WP5.

### Q5. Which within-patch reference, and what can it detect?
- **Where:** v1.0 §4.4 and §14.6; brief WP5 ("reuse the existing estimators … within-patch reference only within a candidate").
- **Issue 1:** the spec formula is a plug-in, G − mean_x h(p̂₁(x), p̂₂(x), p̂₃(x)). The existing estimator is distinct-trial recombination (`recomb_stat`), which the legacy docs prefer because the plug-in leaks 1/R of the dependence. Within one candidate with three trials, the plug-in averages all 27 trial combinations; recombination averages only the 6 combinations of three different trial indices.
- **Issue 2:** I checked numerically that **the mean of G over the 36 trial matchings equals the plug-in reference exactly.** So the plug-in within-patch gap is G(identity matching) − mean over all matchings: a permutation statistic. Each trial is a separate, stateless call, and the admission rule keeps calls on one candidate apart in time. Nothing in the design makes reviewer a's trial 1 related to reviewer b's trial 1. The gap therefore has expectation exactly 0 by construction, and it cannot detect same-patch coupling unless that coupling happens to line up with trial indices.
- **Why it matters:** the "large benchmark gap, near-zero within-patch gap" interpretation (§16, RQ3) would be reported as a finding when it is guaranteed by the design.
- **Proposed default:** use the plug-in form as written. In the paper, describe it as a design check with expectation 0, not as evidence that calls do not couple. Report the distinct-trial recombination version next to it. If you want to *test* coupling, trial j would need a real shared factor (for example, dispatching all reviewers' trial-j calls in one time window); that would be a design change.
- **Blocks:** WP5 (`commonmode.py`).

### Q6. Which reference do dq, dt and dt/dq use, and how should the concentrated-cause test work?
- **Where:** v1.0 §14.6 ("dt/dq relative to the within-patch reference"); §18.4 ("dt/dq > 3/2 is recovered from a planted concentrated common cause").
- **Issue:** relative to the within-patch reference, dq and dt both have expectation 0 (Q5), so their ratio is noise over noise. A planted concentrated common cause (some candidates fool every reviewer at once) is a *between-candidate* effect. It is invisible within a candidate: on such a candidate p̂(x) ≈ 1 and h(p̂(x)) ≈ 1. It only shows up against the benchmark-level reference h(p̄).
- **Also:** the legacy code calls the pooled reference a "trap" (`naive_pooled_reference`; `test_task_heterogeneity_alone_fabricates_dependence_against_a_pooled_null`) because there task heterogeneity was a nuisance. In v1.2, shared difficulty across patches *is* the phenomenon (§4.3, Eckhardt–Lee). The maths of the legacy test stays true; its framing is the opposite of the new paper's.
- **Proposed default:** report dq, dt and dt/dq against **both** references; the §18.4 test uses the benchmark-level reference; legacy docstrings stay unchanged, and new docs explain the change of framing.
- **Blocks:** WP5, WP7.

### Q7. Aggregation for thresholds, gaps and panels
- **Where:** §12.3, §12.5, §14.1, §14.6, §15.1.
- **Issue:**
  - (a) Is the development acceptance in "A ≥ 0.90" the hierarchical rate (candidate → CVE → row → equal-generator average) or the pooled share of F calls? §15.1 ("never pool calls") suggests hierarchical.
  - (b) With one threshold per reviewer, a Generator-aware route r(g) can have row-level A_{g,r} < 0.90 while its overall A_r ≥ 0.90. Is feasibility required per row, or only per reviewer?
  - (c) Do p̄ in h(p̄) and R₂ in the benchmark gap use the same hierarchical weights?
  - (d) The panel decision in trial j uses a_j, b_j, c_j. Is that identity matching the primary estimate, with the 36 matchings as sensitivity?
- **Proposed default:** (a) hierarchical; (b) reviewer-level only, with row-level A reported; (c) yes; (d) yes.
- **Blocks:** WP5.

### Q8. How Holm combines with the interval decision rules
- **Where:** §15.3, §15.4.
- **Issue:** Holm needs p-values or step-wise interval levels; §15.3 is written with 95% intervals.
  - Is "the upper 95% bound" the end of a two-sided 95% percentile interval (2.5% per tail) or a one-sided 95% bound?
  - RQ1 has two parts (U improves AND A drops less than 10 pp) and RQ2 three (cost, U, A). Should each hypothesis's p-value be the maximum of its parts (intersection–union)?
  - Is "cost ratio < 1" a point-estimate condition or a bootstrap bound?
  - Does RQ1 "practical equivalence" count as a rejection inside Holm?
- **Proposed default:** one-sided bootstrap p-values per component, using the existing convention (1 + #{draws on the wrong side}) / (B + 1); hypothesis p = max over its components; Holm on those; Holm-adjusted one-sided intervals at α/(m − i + 1); cost ratio as a bootstrap upper bound < 1; equivalence reported but outside the Holm family.
- **Blocks:** WP5 (`confirm.py`).

### Q9. Which clusters the bootstrap resamples
- **Where:** §15.2; brief ("bit-identical with and without extension rows").
- **Issue:** if the list of clusters to resample is derived from all rows, a CVE that has an extension pair but no core pair adds a cluster, changing every core resample. A related choice: resample all 33 test clusters, or only clusters with at least one evaluable core pair?
- **Proposed default:** resample only clusters with at least one evaluable core pair, derived from core rows only.
- **Blocks:** WP5.

### Q10. Extension thresholds and bit-identity
- **Where:** brief (§12.3 one threshold per reviewer; core bit-identical with or without extension rows).
- **Issue:** if a core reviewer's threshold were refit on all six generators' F, every core estimate would change when the extension is on. And which rows set the thresholds of X, Y, Z?
- **Proposed default:** core reviewers' thresholds are fit on core rows only and reused unchanged in the extension. X, Y and Z are fit on the extension's development rows from all six generators. Please confirm against v1.2.
- **Blocks:** extension parts of WP5.

### Q11. The 8,000-token review input cap
- **Where:** §11.1; brief WP4.
- **Issue:**
  - Tokens by whose tokenizer? Every reviewer must see an identical input, and provider tokenizers differ.
  - Does "each changed method with ±50 lines of context" mean the whole method plus 50 lines either side, or 50 lines around the changed lines?
  - What is "the fixed truncation rule" when the cap is exceeded, and what happens if the diff alone exceeds the cap?
- **Proposed default:** one deterministic, provider-independent token proxy (UTF-8 bytes / 4, rounded up), logged with each input. Context = the enclosing method plus 50 lines either side. When over the cap, trim context lines symmetrically from the outermost edge, never trim the diff, and record `truncated_context: true`. If the diff alone exceeds the cap, the candidate is `indeterminate (review_input_overflow)`, reported and not reviewed.
- **Blocks:** WP4.

### Q12. How far identifier stripping goes
- **Where:** §11.1, §5.6; brief (oracle isolation: "project name … can reach a reviewer prompt").
- **Issue:** project names occur inside the code reviewers must read: Java package declarations, imports and diff paths (for example `src/main/java/org/apache/struts2/…`). Stripping them changes the code; not stripping them breaks the literal "no project name in any prompt" rule.
- **Proposed default:**
  - strip CVE and Vul4J IDs, GitHub slugs, commit hashes, PoV test class and method names, PoV output, and model and generator names everywhere;
  - keep Java package names, imports and file paths, since they are part of the code;
  - the isolation test checks the strict list and records the allowed project tokens per CVE.
  - Alternative: rewrite package roots to a neutral prefix (`org.example.p1`). That makes the code less realistic and may not stop recognition.
- **Blocks:** WP4, WP7.

### Q21. Extension items that exist only in v1.2
- **Where:** brief §3, §12.6, §14.4, §15.7, WP1, WP5.
- **Issue:** I cannot plan the following without v1.2:
  - the RQ2o estimand (presumably the X/Y/Z 2-of-3 panel against strong\*?) and t_o;
  - the three §15.7 promotion conditions;
  - Δ₆ and which cells count as "cross-family";
  - D_diag for the open block (on both probability and logit scale, as in §14.4?);
  - what "pipeline risk split by generator group" groups;
  - what `extension.paid_block_on_test` blocks (commercial reviewers on open-generator test patches?);
  - the default for `extension.enabled`;
  - whether Experiment B includes open reviewers or open generators (the brief says cheap reviewers only);
  - what the "seeded correction order for extension twins" orders.
- **Proposed default:** none until v1.2 is available.
- **Blocks:** extension parts of WP1, WP3, WP4, WP5, WP7.

---

## Decision rule and schema

### Q2. Status names
- **Where:** v1.0 §11.6.
- **Issue:** it says "(from the harness)" but lists `schema_violation` and `reject`. The harness has `schema_invalid` and `request_error`, and `reject` is a verdict, not a status.
- **Proposed default:** keep the code's six names; fix the spec text.

### Q3. Does a `reject` verdict with a low risk score count as approval?
- **Where:** §11.5: a_rj = 1 if the call is valid, the verdict is not abstain, and s ≤ t_r.
- **Issue:** read literally, a call returning `verdict: "reject", risk: 10` is an approval whenever t_r ≥ 10. The native verdict is then used only in the sensitivity analysis.
- **Proposed default:** implement it literally, as written, and report how often verdict and threshold disagree. Please confirm, because the alternative (approval needs verdict = approve **and** s ≤ t_r) gives different thresholds and rates.

### Q4. How strict the output schema is
- **Where:** §11.3.
- **Issue:** should a justification over 150 words, or a risk score like `35.0`, make the call `schema_invalid` (and so a fail-closed non-approval)? Verbose models would then lose approvals systematically, which is the verbosity-correlated missingness the legacy design warned about.
- **Proposed default:** accept integral floats; enforce 0–100; do **not** invalidate long justifications, but record `justification_words` and report how many exceeded 150.

---

## Task bank

### Q13. Experiment B packets: PoV leakage and how good the builders must be
- **Where:** §13.
- **Issue:**
  - (a) In Vul4J the PoV is often a test method inside a test class that also holds ordinary tests. The "ordinary tests touching changed classes" packet can then expose the PoV's file. Exclude only the PoV method, or the whole file?
  - (b) Building a "structure" packet needs a Java call graph. Is a lightweight text-based caller/callee finder enough for an exploratory screen, or do you want a real parser (an extra dependency)?
- **Proposed default:** (a) exclude the whole file containing the PoV; (b) the lightweight finder, recording which method was used.

### Q14. Classification rerun protocol
- **Where:** §8.
- **Issue:**
  - Is an attempt run once and then rerun 10 times if it passes, or run 10 times from the start?
  - If an ordinary test fails in one of the 10 reruns, is the attempt `regression_fail` or `indeterminate` (inconsistent)?
  - Is each rerun a fresh build?
- **Proposed default:** one run through apply → build → ordinary tests; if those pass, 10 fresh reruns (PoV and ordinary tests); an ordinary-test failure inside the reruns → `indeterminate (inconsistent)`.

### Q15. Sibling rubric and the order of selection and correction
- **Where:** §9, §10.
- **Issue:**
  - Is "≤ 10 changed lines" a hard limit or a target that is flagged?
  - Which added lines count as comments?
  - Is F written only for the selected V (select first, then correct)?
  - If no valid F can be made for the selected V, is the cell dropped, or is another V drawn? Redrawing changes the inclusion probability.
- **Proposed default:** a target that is flagged, not enforced; added `//`, `/* */` and Javadoc lines count as comments; select first, then correct; if F is infeasible, drop the cell and report it, with no redraw.

### Q19. Runtime of 10/10 full test suites
- **Where:** §7, §17.
- **Issue:** 79 × 2 × 10 full-suite runs, plus 10 per near-miss or blocked attempt, plus 10 per sibling. Some Vul4J projects (Jenkins, CXF, Camel) have long suites.
- **Proposed default:** none (this is a design decision). One option is to run only the test modules of the affected project module and record that scope.

---

## Providers, pins and logs

### Q16. Reasoning setting against temperature and top-p
- **Where:** §6 ("reasoning: medium or equivalent", temperature 0.7, top-p 1.0).
- **Issue:** some provider APIs refuse sampling parameters when a reasoning mode is on. The harness already has `send_temperature: false` for this. The spec does not say whether that is allowed, or how it is recorded.
- **Proposed default:** allowed only through an explicit per-model flag in the config, logged with each call, and listed in the report as a deviation from §6. Validation refuses a silent omission.

### Q17. Pin rules per provider
- **Where:** §6 ("snapshot check").
- **Issue:**
  - The existing `_PINNED` regex requires a date, 8 digits, a `:tag` or a 4-digit suffix, so an ID ending in a 3-digit version suffix would be refused even if it is correctly pinned.
  - For open weights, is checking the checksum at start-up enough?
- **Proposed default:** a pin rule per provider in the config; for API models, rely on the served-model echo abort as well; for open weights, check at start-up, at the end of each run, and every N calls.

### Q18. Logs beyond §18.3
- **Where:** §18.3 ("every derived number is recomputed from these logs").
- **Issue:** the two listed logs are not enough to recompute everything. Selection and inclusion probabilities, sibling validation, reproduction status and the frozen artefacts are not in them.
- **Proposed default:** add `reproduction.jsonl`, `selection.jsonl`, `siblings.jsonl` and `freeze.json`, all append-only and hashed.

### Q20. Two v1.0 statements that the brief contradicts (probably fixed in v1.2; please confirm)
- **§4.7** says three reviewers at 30% give between 0% and 30% on 2-of-3. The brief's 0.45 ("all errors in pairs") is the true maximum, and I checked it: three pair-only patterns of 0.15 each give marginals of 0.30 and a 2-of-3 rate of 0.45. Fully shared errors (0.30) are not the worst case.
- **§12.2** gives the Generator-aware policy "r(A), r(B), r(C) and their thresholds", meaning generator-specific thresholds. The brief forbids those (one threshold per reviewer, §12.3). I follow the brief.
