# SPEC_ANSWERS: decisions on SPEC_QUESTIONS (Q0–Q21)

Answered 2026-10-09. Every decision below is now written into Experiment Specification v1.3, which supersedes v1.0–v1.2. Section numbers refer to v1.3. Where my decision differs from your proposed default, it says (differs from your proposal).

Thank you: Q5/Q6 caught a real error in the design (the within-patch gap is 0 by construction), and Q1 caught an error in my brief (fail-closed was not an existing invariant).

## Next step

1. Put these files in `docs/spec/`: `Experiment_Specification_v1_3.md`, `experiment_notes.tex` (rewritten 9 Oct), `proposed_split.json`, and this file.
2. Re-check `PLAN.md` against v1.3 and update it.
3. If nothing new conflicts, proceed with WP1 without waiting for me. Stop again only for a new blocking question.

## Blocking

**Q0. v1.2 not available.** Use v1.3 (above). It contains everything v1.2 had, plus these answers.

**Q1. Fail-closed.** Accepted: fail-closed on the new path only; the legacy path is unchanged; unresolved means no `ok` record after 4 attempts in total, counted across resumes; unresolved counts are reported per (reviewer, state) next to every rate (§11.6, §6).

* Discrimination C (differs from your proposal): use the valid trials only. A pair with no valid trial on V or on F is left out of C and counted (§14.5). Risk 100 on a missing V would reward a failed call with correct discrimination.
* Worst-case sensitivity: every abstain, invalid or unresolved call coded as approve on V and reject on F (§15.5 item 2).

**Q5. Within-patch reference.** You are right, and the spec now says so (§4.4). Implement the plug-in form, label it a design check with expectation 0, and report the distinct-trial recombination version next to it. No design change to test coupling. RQ3 instead describes what drives the benchmark gap, by generator, weakness class, similarity stratum and patch size (§14.6). The "large benchmark gap, near-zero within-patch gap" row is removed from §16.

**Q6. Reference for dq, dt and dt/dq.** Accepted in a stronger form: the benchmark-level reference is the primary one (§4.5, §14.6), and the §18.4 test uses it. Optionally also log the within-patch versions, labelled as having expectation 0. Leave legacy docstrings unchanged; new docs explain why shared difficulty, a nuisance in the legacy design, is the phenomenon here.

**Q7. Aggregation.** (a) hierarchical; (b) feasibility per reviewer only, with row-level A reported; (c) yes, the same hierarchical weights (§12.3, §4.4). (d) (differs from your proposal): the panel's primary estimate averages over all 36 trial matchings, which per candidate equals h(p̂₁(x), p̂₂(x), p̂₃(x)) from the members' thresholded per-trial approvals. The identity matching is the check (§11.5). Trials are exchangeable by design, so this is the same estimand with less noise. Add the §18.4 test that both equal h of the per-trial means.

**Q8. Holm with the interval rules (§15.3, §15.4).** Your proposal, with the level fixed:

* two-sided 95% percentile intervals are reported;
* decisions use one-sided bootstrap p-values, (1 + #wrong side) / (B + 1), per component, at a one-sided 0.025, which matches "the bound of a two-sided 95% interval";
* the hypothesis p-value is the maximum over its components;
* the cost ratio is a bootstrap component like the others;
* Holm at familywise one-sided 0.025 (two-sided 0.05), with Holm-adjusted one-sided bounds;
* RQ1 equivalence is reported outside the Holm family.

**Q9. Bootstrap clusters.** Accepted: for core analyses, only clusters with at least one evaluable core pair, derived from core rows only; extension analyses use their own list (§15.2).

**Q10. Extension thresholds** (differs from your proposal): all thresholds (all nine reviewers, t_p and t_o) are fit on the core development rows only (§12.3). This keeps the core bit-identical, puts RQ2o on the same footing as RQ2, and makes open-generated pairs a test of how thresholds transfer.

**Q11. The review input cap.** Accepted as proposed: the bytes / 4 proxy; the enclosing method plus 50 lines either side; symmetric trimming of context, never of the diff; `truncated_context`; a diff over the cap makes the pair `indeterminate (review_input_overflow)`, V and F together (§11.1).

**Q12. Identifier stripping.** Accepted as proposed. Keep packages, imports and paths; strip the strict list; record allowed project tokens per CVE; no package rewriting (§11.1).

**Q21. Extension items (now in v1.3):**

* RQ2o: the fixed X/Y/Z 2-of-3 panel against strong\* on the core bank, with common cut-off t_o chosen like t_p (§3, §12.6, §14.3b).
* Promotion (§15.7): on development data, (i) t_o attainable (A ≥ 0.90); (ii) Δ₂ᵁₒ < +0.05 and Δ₂ᴬₒ > −0.05; (iii) projected half-width for Δ₂ᵁₒ ≤ 0.10. Config mode `promotion_rule` (default) or `fixed_sequence`.
* Δ₆ (§14.8): for each of the nine reviewers, rows with fam(g) ≠ fam(r) only; open rows minus commercial rows; equal reviewer weight.
* D_diag for the open block: rows and columns X, Y, Z; probability and logit scale, as in §14.4.
* Pipeline risk split: commercial generators {A, B, C} versus open generators {X, Y, Z} (§14.7).
* `extension.paid_block_on_test`: commercial reviewers (A, B, C, a, b, c) on extension-bank test pairs. Default `true`; if `false`, that block runs on development only and RQ6 is labelled development-only (§12.7).
* `extension.enabled`: `true` for this study (author decision, 8 Oct). Validation must require it to be set explicitly.
* Experiment B: no open reviewers, no open generators (§13).
* Seeded correction order: the order in which the selected extension near-misses get their twins, fixed by seed before any review; core twins come first; the stopping point is logged (§9).

## Non-blocking

* **Q2. Status names:** keep the code's names; the spec now defers to them (§11.6).
* **Q3. Reject verdict with a low risk:** literal, as written. Report the verdict–threshold disagreement rate per reviewer (§11.5).
* **Q4. Schema strictness:** accepted. Any number in [0, 100] is accepted (not only integral floats); long justifications do not invalidate the call; record `justification_words` (§11.3).
* **Q13. Experiment B packets:** (a) exclude the whole PoV test file; (b) the lightweight finder, with the method recorded (§13).
* **Q14. Rerun protocol:** accepted, with one detail: build once per attempt, then 10 test reruns, each in a clean state (as in Stage 1), not 10 fresh builds. An ordinary-test failure inside the reruns makes the attempt `indeterminate (inconsistent)` (§8).
* **Q15. Sibling rubric:** accepted as proposed. A flagged target, not a hard limit; the comment definition as proposed; select first, then correct; an infeasible F drops the cell, with no redraw (§9).
* **Q16. Reasoning versus sampling settings:** accepted as proposed (§6).
* **Q17. Pins:** a rule per provider; the served-model echo abort for API models; open weights checked at start-up, at the end of each run, and on every server (re)load (§6).
* **Q18. Logs:** accepted. Add `reproduction.jsonl`, `selection.jsonl`, `siblings.jsonl` and `freeze.json`, plus the new `reviews.jsonl` fields (§18.3).
* **Q19. Runtime** (still a design decision): implement both scopes behind config. Default: full suites. Before Stage 2, I will run a timing pilot on Jenkins, CXF and Camel. The fallback is the full suite once per attempt, then 10 reruns of the PoV plus the affected module's tests, with the scope recorded per attempt (§8). Please add a `timing_pilot` command that reports wall-clock time per suite run.
* **Q20.** Both confirmed. The 0–45% range is in §4.7, and one threshold per reviewer is in §12.2–§12.3. Follow v1.3.
