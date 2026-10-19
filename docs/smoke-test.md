# Smoke test on a small VM (weak models, 3 CVEs)

Written 16 October 2026. A first end-to-end run of the real pipeline on a cheap x86-64 VM
before renting the H100 study host (`docs/azure-runbook.md`). Config: `study.smoke.jsonc`
(rehearsal mode, small open-weight models in all nine slots, `attempts_per_cell` 2,
`reruns` 3). Its numbers test the plumbing, not the design.

## What it answers

1. Does the pinned Vul4J image build, and does the adapter work against it (`vul4j-check`)?
2. Does every stage run on real CVEs and real model output: reproduce, generate, classify,
   select, twins, bank, review, analyse-dev, audit-logs?
3. Rough rates to plan the rehearsal: build and test minutes per CVE, apply failures,
   context overflows, parse failures, near-miss yield.

## VM and cost

| Item | Choice | Price (Sweden Central, on demand, Oct 2026) |
|---|---|---|
| Size | `Standard_NC16as_T4_v3`: 16 vCPU, 110 GiB RAM, 1x T4 (16 GB) | ~$1.28/h (cheapest regions ~$1.20/h) |
| OS disk | 512 GB Premium SSD (P20) | ~$75/month, ~$2.5/day while the disk exists (approximate list price) |
| Image | `microsoft-dsvm:ubuntu-hpc:2204:latest` (NVIDIA driver included) | |
| Quota | "Standard NCASv3_T4 Family vCPUs" >= 16 in the region | default is often 0: request it first |

Spot (~$0.36/h) is not worth it: an eviction during the image build loses the whole
build (the warm-up is one Docker layer).

| Phase | Hours (estimate) | Compute cost |
|---|---|---|
| `setup.sh` without the image build (driver check, Ollama, ~25 GB of models, venv, tests) | 0.5-1 | ~$1 |
| Vul4J image build (reproduces all 79 CVEs once; the least certain number) | 3-8 | $4-10 |
| Checks and timing pilot | 0.5 | <$1 |
| Smoke run, 3 CVEs | 2-4 | $3-5 |
| **Total** | **~7-14** | **~$9-18**, plus ~$3-8 of disk for a few days |

Budget about **$30** to allow one re-run. Delete the VM and disk when done, or keep the
image: `docker save vul4j:376411d | zstd > vul4j.tar.zst`, copy it to a storage account
(cents per GB-month) and `docker load` it on the H100 host. The image id, and so the pin,
is unchanged by save/load.

## Steps

Before: the branch must be on GitHub (commit and push `study-v1.3`), and the VM needs
read access to the repository (deploy key, or HTTPS with a token).

```bash
# on your Mac
az group create -n hp-smoke -l swedencentral
az vm image terms accept --urn microsoft-dsvm:ubuntu-hpc:2204:latest
az vm create -g hp-smoke -n hp-smoke --image microsoft-dsvm:ubuntu-hpc:2204:latest \
  --size Standard_NC16as_T4_v3 --os-disk-size-gb 512 --storage-sku Premium_LRS \
  --admin-username michael --ssh-key-values ~/.ssh/id_ed25519.pub
ssh michael@<ip>

# on the VM
tmux new -s smoke
git clone <repo> Experimental-Harness && cd Experimental-Harness && git checkout study-v1.3
MODEL_CONFIGS=study.smoke.jsonc bash scripts/azure/setup.sh
#   models are pulled first (a bad tag fails within minutes); then the image build (hours)
#   follow it with: tail -f ~/vul4j-build.log
# log out and in again (docker group), then:
cd Experimental-Harness && source .venv-linux/bin/activate
C=study.smoke.jsonc
python study.py pin $C --write
python study.py validate $C
python study.py vul4j-check $C --cve VUL4J-12
python study.py timing-pilot $C --cves VUL4J-12 --runs 1
python study.py reproduce $C --cves VUL4J-12,VUL4J-5,VUL4J-41 --jobs 2
python study.py generate  $C --split development
python study.py classify  $C --split development --jobs 2
python study.py select    $C --split development
python study.py sibling   $C --split development
python study.py bank      $C --split development
python study.py review    $C --split development --expb
python study.py analyse-dev $C
python study.py audit-logs  $C
```

Every command resumes; after an interruption run it again. Logs: `runs/smoke-rehearsal/`.
The three CVEs are development CVEs from three repositories (commons-imaging,
commons-compress, plexus-archiver). Only CVEs that `reproduce` marks `eligible` go further.

## Go / no-go

| After | Expect | If not |
|---|---|---|
| `setup.sh` step 4 | six models pulled | a tag does not exist: change it in `study.smoke.jsonc` (only `qwen3.5:4b`, `granite4.2:3b`, `gemma4:e2b` are known to exist, from Pilot 0) |
| `vul4j-check` | commit True, warm-up ran True, ends `OK` | a build without network fails: set `vul4j.network` to `"bridge"` and note it |
| `reproduce` | 3 `eligible` | the status (`build_fail`, `pov_unstable`, `suite_unstable`) says where |
| `generate` | 36 calls (3 CVEs x 6 generators x 2) | many `context_overflow`: 32k is too small for that CVE's files |
| `classify` | some `near_miss` | see below |
| `bank` | > 0 pairs | see below |
| `review` | calls > 0, few parse failures | parse failures: the small model's output format |
| `audit-logs` | "every row has every required field" | a bug: keep the logs |

**An empty bank is possible with weak generators.** Then `review` makes no calls, which is
not a failure (the offline test checks this path) but leaves the review stage untested.
Raise `design.attempts_per_cell` to 5 in `study.smoke.jsonc` and run `generate` and the
later commands again (attempts 0-1 are kept, 2-4 are added), or add development CVEs to
`reproduce --cves`.

## Afterwards

```bash
az vm deallocate -g hp-smoke -n hp-smoke     # stop paying for compute, keep the disk
az group delete -n hp-smoke                  # remove everything
```

Bring back `runs/smoke-rehearsal/` (`scp -r`) and the timing-pilot numbers: they size
`--jobs` and the hours of the H100 rehearsal.
