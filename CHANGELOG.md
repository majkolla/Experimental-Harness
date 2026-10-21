# Changelog

## 0.4.2 (2026-10-21): acceptance test

### Added
- **`study.py acceptance CONFIG`** (`hp/acceptance.py`): known-answer checks on the study
  host, every expected answer fixed in advance. *analysis*: the synthetic study recovers
  its planted structure and recomputes identically. *vul4j*: image provenance, Stage 1
  `eligible`, and five canary patches per CVE with known classes (human patch `blocked`,
  comment-only change `near_miss`, syntax error `build_fail`, wrong context and empty
  response `apply_fail`), plus the twin validator on the human patch (valid) and the
  comment-only change (invalid). *models*: pins, the context guard, one schema-valid review
  and (generators) one generation of a fixed toy diff per distinct model. *logs*: audit and
  analyse-dev recomputed from the logs equals `dev_report.json`. Writes only to
  `runs/acceptance/`; exits 1 unless accepted. Canaries are placed after the package
  line (never inside a comment) or at the end of the file, in the file's line endings.
- `tests/study/test_acceptance.py`: every section through the real adapters with fakes,
  and three defects it must catch (a runner that never reports a build failure, an Ollama
  upgrade after pinning, an edited development report). 396 tests.

## 0.4.1 (2026-10-16): smoke test on a small VM

### Added
- **`study.smoke.jsonc`**: the rehearsal with small open-weight models in all nine
  slots (generators qwen3.5:9b, granite4.2:8b, gemma4:e4b; cheap reviewers the
  Pilot 0 models), 32k generator context, `attempts_per_cell` 2, `reruns` 3,
  `workers` 2, 6-CPU/32 GB containers, logs in `runs/smoke-rehearsal`. Scope comes
  from `reproduce --cves`; later stages only touch eligible CVEs, so the
  registered split is unchanged. Guide: `docs/smoke-test.md`.
- **`tests/study/test_smoke_config.py`**: every command of the smoke guide through
  the real adapters (fake docker, fake Ollama), with and without near-misses
  (an empty bank must still reach `analyse-dev` and `audit-logs`). 385 tests.

### Changed
- **`scripts/azure/setup.sh`**: pulls the models of `MODEL_CONFIGS` (default
  `study.rehearsal.jsonc study.jsonc`) and does so *before* the Vul4J image build,
  so a wrong model tag fails in minutes, not after hours. `OLLAMA_MAX_LOADED` and
  `MIN_FREE_GB` are settable. `.venv-linux/` is git-ignored.

## 0.4.0 (2026-10-14): live contact, rehearsal mode, study host

Everything still runs offline (382 tests); the new paths are checked against the
Vul4J and Ollama sources and tested with fakes that reproduce their behaviour.

### Changed
- **`ContainerVul4J` rewritten against the Vul4J source** (commit 376411d). Metadata
  is read from the checkout's `VUL4J/vulnerability_info.json` and
  `{vulnerable,human_patch}/paths.json` (`vul4j info` logs to stderr, not stdout);
  `vul4j test -b all|povs` (there is no `--tests`); reports found anywhere under
  `target/surefire-reports`, `target/failsafe-reports` or `build/test-results`
  (multi-module Maven and Gradle); `--platform linux/amd64`; configurable network,
  timeouts and docker binary. Model diffs are applied with `difftools.apply`, the
  function the review stage uses, instead of `git apply`.
- **Ollama reasoning switch**: `reasoning_params.think` is sent as the top-level
  `think` field (inside `options` it was ignored); `keep_alive`; `thinking_chars`
  in the call metadata.
- **Leak scan scope** (PLAN section 10 item 32): model ids and identity terms apply
  only to the lines a patch adds, as case-sensitive whole words; oracle patterns
  still apply to the whole input. Generator inputs are scanned for oracle
  patterns only. Before, a CVE whose code imports `com.google...` had every pair
  excluded from review.
- **Parallel Stage 1 and classification**: `--jobs N`; rows are logged as each
  CVE or attempt finishes.
- Live mode refuses an advisory still marked `"status": "draft"`.

### Changed after an independent review (PLAN section 10 items 38-47)
- One container per checkout (`docker exec`), so `compile`'s Maven installs reach the tests;
  in-container timeouts, `--init`, CPU and memory limits.
- `InfraError`: Docker, OOM, checkout and build-timeout failures are never logged as
  outcomes; a resumed run retries them. Ctrl-C kills containers and logs nothing half-done.
- `test_all_cmd` gets the dataset's `cmd_options` and a missing Maven `test` goal.
- The Vul4J image is built from commit 376411d and pinned by image id; `vul4j-check`
  reports its provenance and warm-up failures.
- Twin drafts logged before validation; leak scan refined (case-insensitive words, only
  text the generator wrote); newline-only diff splitting, CRLF files, byte-faithful
  writes, deletions; PoV names mapped case-insensitively; rehearsal stand-ins share the
  X/Y/Z weights; live configs refuse rehearsal log paths.

### Added
- **Rehearsal mode** (`study.rehearsal.jsonc`): the real pipeline with open-weight
  stand-ins in all nine slots; refuses paid providers, the test split, `freeze`
  and `confirm`; logs under `runs/rehearsal`; reports carry a banner.
- **Twins by an open-weight model** (`sibling.method = openweight_model`, the
  spec's sensitivity method): one draft per pair from V's post-patch code,
  returned as a patch against the vulnerable version and validated like an
  author's twin. Prompt `prompts/sibling_v13.md`.
- `study.py pin` (open-weight pins from Ollama, Vul4J digest from Docker, written
  into the config in place) and `study.py vul4j-check` (one-CVE image smoke test).
- `scripts/azure/setup.sh`, `docs/azure-runbook.md`.
- 79 drafted advisories in `bank_inputs/advisories/`, `docs/advisories_review.md`.
- Proposed X/Y/Z: `qwen3.8:27b-q8_0`, `granite4.2:30b-q8_0`,
  `devstral-small-2:24b-instruct-2512-q8_0` (families outside Anthropic, OpenAI,
  Google).

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
