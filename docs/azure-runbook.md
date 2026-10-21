# Running the study on Azure

Written 14 October 2026. This runbook covers the study host: one Azure GPU VM that runs both
the Vul4J builds (Docker, x86-64) and the open-weight models (Ollama). It first runs a
**rehearsal**: the whole pipeline with open-weight stand-ins in all nine model slots, on the
development split only. The live study then needs only the six commercial models' keys and
pins.

## 1. The VM

| Item | Recommendation | Why |
|---|---|---|
| Size | `Standard_NC80adis_H100_v5`: 2× H100 NVL (94 GB each), 80 cores, 640 GiB RAM | X/Y/Z at Q8_0 are ~87 GB; the rehearsal adds three small models (~15 GB) and the context caches; 80 cores run 8 Vul4J builds at once (8 cores and 48 GB each) |
| Smaller option | `Standard_NC40ads_H100_v5`: 1× H100 NVL, 40 cores | Only with X/Y/Z at Q4_K_M (~51 GB): change the three `model` tags and `allowed_precisions`; use `--jobs 4` |
| Image | Ubuntu-HPC 22.04 (`microsoft-dsvm:ubuntu-hpc:2204:latest`; check with `az vm image list --publisher microsoft-dsvm --offer ubuntu-hpc --all`) | NVIDIA driver preinstalled |
| OS disk | 1 TB Premium SSD | Persistent: the repository, every log (`runs/`), the Vul4J image and the model weights survive a stop/deallocate |
| Local NVMe | mounted at `/data` by the setup script | Scratch only (Vul4J work directories). Wiped on deallocate; re-run the setup script after a restart |
| Network | SSH only (NSG); Ollama listens on 127.0.0.1 | Nothing is exposed |
| Quota | Request "Standard NCadsH100v5 Family vCPUs" in the region first | GPU quota is 0 by default |

The Vul4J image is amd64-only, so the study host must be x86-64 (an Apple Silicon Mac or a
DGX Spark would emulate it).

## 2. Setup

```bash
git clone <the repository> Experimental-Harness && cd Experimental-Harness
git checkout study-v1.3
bash scripts/azure/setup.sh          # driver, scratch disk, Docker + Vul4J image, Ollama + models, venv, tests
# log out and in again (docker group), then:
source .venv-linux/bin/activate
python study.py pin study.rehearsal.jsonc --write     # weight checksums, quantisation, Ollama version, Vul4J image id
python study.py validate study.rehearsal.jsonc
python study.py vul4j-check study.rehearsal.jsonc --cve VUL4J-12   # development, Maven
python study.py vul4j-check study.rehearsal.jsonc --cve VUL4J-70   # Gradle (all 9 Gradle CVEs are in the test split)
python study.py acceptance study.rehearsal.jsonc --cves VUL4J-12,VUL4J-5,VUL4J-70 --jobs 3   # must end ACCEPTED
```

**`acceptance`** checks known answers on the real host: the analysis on the synthetic
world, Vul4J canary patches with known classes, every open-weight model's pins and
output schema, and (after a run) that the development report recomputes from the logs.
See `docs/smoke-test.md` for the table of checks. Run it again on the study host before
the live study, and after any change to the image, Ollama or the models.

**The Vul4J image is built, not pulled.** The setup script builds it from Vul4J commit
`376411d`, the version the harness adapter was checked against. The build reproduces every
CVE once and fills the image's dependency caches, which is what lets the study run its
containers with `--network none`. It takes hours, once; the image stays on the OS disk. It
is pinned by image id (`pin_kind: image_id`). `VUL4J_SOURCE=hub` pulls `tuhhsoftsec/vul4j`
instead (then pinned by registry digest), but that image's build date and contents are not
known.

**`vul4j-check`** is the first contact with the image. It prints the image's Vul4J commit,
whether the build's warm-up reproduction ran and which CVEs it could not reproduce, then
checks out one CVE, builds the vulnerable and fixed versions in one container each and runs
the full suite once each. It must end with `OK` (PoV fails on vulnerable, passes on fixed).
If a build fails for lack of network, set `vul4j.network` to `"bridge"` and record it.

Pins are facts read from the server. If Ollama is upgraded or a model is re-pulled, the run
stops with a pin violation; re-run `pin --write` only if that change is intended.

**How the runner uses Vul4J.** One container per checkout: checkout, compile and every test
run of a version happen in the same container, because `compile` installs modules into the
container's Maven repository and multi-module tests read them from there. `-b all` runs the
dataset's `test_all_cmd`, which for most multi-module CVEs is already the failing module's
suite; the runner appends the dataset's `cmd_options` (Vul4J omits them for `-b all`) and adds
a missing Maven `test` goal (VUL4J-16). Docker, out-of-memory and build-timeout failures stop
the stage without logging the item, so running the command again retries it. Ctrl-C kills
the running containers and logs nothing half-done.

## 3. Rehearsal (development split only)

```bash
C=study.rehearsal.jsonc
DEV=VUL4J-5,VUL4J-6,VUL4J-7,VUL4J-8,VUL4J-12,VUL4J-13,VUL4J-18,VUL4J-22,VUL4J-26,VUL4J-27,VUL4J-28,VUL4J-29,VUL4J-30,VUL4J-31,VUL4J-32,VUL4J-33,VUL4J-34,VUL4J-35,VUL4J-36,VUL4J-41,VUL4J-43,VUL4J-67,VUL4J-78

python study.py timing-pilot $C --cves VUL4J-12,VUL4J-5,VUL4J-26 --runs 3   # minutes per full suite
python study.py reproduce   $C --cves $DEV --jobs 8      # Stage 1: 10+10 full suite runs per CVE (Stage 1 needs no model)
python study.py generate    $C --split development       # 6 generators x 10 attempts per CVE
python study.py classify    $C --split development --jobs 8
python study.py select      $C --split development
python study.py sibling     $C --split development       # Z drafts each twin, validated 10/10
python study.py bank        $C --split development
python study.py review      $C --split development --expb
python study.py analyse-dev $C                           # report starts with a REHEARSAL banner
python study.py audit-logs  $C
```

Every command resumes where it stopped; run it again after an interruption. Logs go to
`runs/rehearsal/`.

What to check before going live:

- **Stage 1:** how many development CVEs are `eligible`, and why the others are not
  (`build_fail`, `pov_unstable`, `suite_unstable`). Compare with the image's warm-up failures.
- **Timing:** the timing pilot gives minutes per full suite. Note that `module_fallback` saves
  little with Vul4J: it cannot run a module subset, so the runner runs the full command and
  filters (PLAN §10 item 34); the real lever is `--jobs`.
- **Generation:** `apply_fail` and `context_overflow` rates per generator. Many overflows mean
  `num_ctx` is too small for the files of some CVEs.
- **Near-miss yield per generator (gate G2):** at least 10 development CVEs with a near-miss
  per generator row.
- **Review:** parse failures, truncations and the leak-scan exclusions in `inputs.jsonl`.

The rehearsal refuses generation, twins and review on the test split, `freeze` and `confirm`
by design: rehearsal outcomes on test CVEs would be seen before the real study is frozen.
Stage 1 (no model involved) may run on all 79 CVEs, as in the study.

## 4. Going live

1. In `study.jsonc`: pin the six commercial models (`model`, `snapshot`, `reasoning_params`,
   `identity_terms`), their prices, `reasoning_params` for X/Y/Z, and `gpu_hour_usd`. Then
   `python study.py pin study.jsonc --write` for the X/Y/Z weights and the Vul4J digest.
2. Export `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`.
3. Review the 79 drafted advisories (`bank_inputs/advisories/`, see
   `docs/advisories_review.md`) and remove `"status": "draft"` from each one you accept.
   The freeze hashes them.
4. Twins: the study's method is `author` (you write `bank_inputs/siblings/<pair_id>.diff` in
   the logged correction order). The rehearsal's model-drafted twins are the spec's
   sensitivity method.
5. Run the same commands with `study.jsonc`, then `analyse-dev`, `freeze`, the test split, and
   `confirm`.

Stage 1 involves no model. If the Vul4J image digest and `hp/bank` are unchanged, the
rehearsal's `reproduction.jsonl` rows for the development CVEs are valid for the study too;
copying them is a decision to record, not a default.
