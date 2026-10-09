# Changelog

## 0.3.0 (2026-10-09): Experiment Specification v1.3

Branch `study-v1.3`. Implements the v1.3 study next to the unchanged Experiment 1
harness. Plan: `PLAN.md`; decisions: `docs/spec/SPEC_ANSWERS.md`; implementation
map, invariants, provisional items and placeholders: `docs/study.html`.

### Added
- **Config and validation** (WP1): `study.jsonc` (live; every pin `TO_PIN_AT_FREEZE`),
  `study.synthetic.jsonc` (offline), `hp/study_config.py` (JSONC, config and code
  hashes, freeze, refusal conditions), prompts `review_v13.md` and `generate_v13.md`.
- **Providers** (WP2): `hp/providers/` package with output contracts (legacy, v1.3
  review, text), Google backend, open-weight backend with weights / precision /
  serving-stack pins and context-overflow detection, the nine-model synthetic world;
  attempt budget across resumes; `PinViolation`.
- **Task bank** (WP3): `hp/bank/` (Vul4J runner interface with a mock and a container
  runner, Stage 1 reproduction, generation, classification, selection, twins, split
  lock, bank assembly), `hp/engine.py`, `hp/leaks.py`, `hp/logs.py`, `study.py`,
  `timing-pilot`.
- **Review** (WP4): `hp/review/` (e0 builder with the bytes/4 cap, Experiment B
  packets, crossed schedule with the extension and `paid_block_on_test`, dispatch).
- **Analysis** (WP5): `hp/analysis/` (views, rates, thresholds, policies, regret,
  common mode, confirmatory inference with Holm, extension analyses, Experiment B,
  reports); `study.py analyse-dev | freeze | confirm | selftest`.
- **Logs** (WP6): row schemas for every log, `audit-logs`, recompute-from-logs check.
- **Tests** (WP7): new tests under `tests/study/`, including the
  section 18.4 tests, bit-identity of the core analysis with and without the
  extension, and an offline end-to-end run with nine synthetic models.
- **Docs** (WP8): `docs/study.html`, README section, this changelog.

### Changed
- `hp/providers.py` became `hp/providers/__init__.py`; backends take an output
  contract (default: the legacy verdict, so the legacy path behaves as before);
  `_classify` also reads an integer `code` attribute.
- `hp/schema.py`: v1.3 review and text contracts added next to the legacy verdict.
- `tests/conftest.py`: an autouse guard removes provider API keys and blocks sockets.
- Legacy modules carry a LEGACY / SHARED banner; `experiment*.json` carry
  `"mode": "legacy_exp1"` (ignored by the legacy loader; config hash unchanged).
- `HARNESS_VERSION` 0.2.0 -> 0.3.0.

### Fixed after the independent review (PLAN.md section 10, items 21-31)
- Analysis refuses runs with missing or open calls; `confirm` refuses test rows made
  under another config; re-freezing is refused once the test split holds work.
- Missing keys or SDKs stop the run (`LocalFault`) instead of being logged as failures.
- Attempts are logged as they end; appends after a partial line start a new line.
- The code hash covers the running package; the freeze also hashes the advisories;
  `identity_terms` per model are required in live mode.
- One-sided bounds agree with the p-values; undefined resamples count against a claim.
- Pipeline risk and Delta6 no longer average around missing cells.
- Stage 1 checks one stable signature per PoV test.
- Reports print unresolved trials and pairs left out of C next to every per-cell rate.
- `ContainerVul4J` removes its workspaces and reuses one checkout per CVE for reads.
- Test count: 355 (79 legacy + 276 new).

### Not changed
- Experiment 1 behaviour and its 79 tests.

### Still placeholder
See `docs/study.html` section 6: model and weight pins, prices, reasoning
parameters, Google SDK verification, the Vul4J container and its command lines,
advisories, twins, the timing pilot, and the v1.3 specification text.
