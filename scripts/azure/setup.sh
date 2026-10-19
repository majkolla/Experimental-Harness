#!/usr/bin/env bash
# One-time setup of the study host on an Azure GPU VM (Ubuntu 22.04/24.04, x86-64).
# Idempotent: safe to re-run, also after the VM was deallocated. See docs/azure-runbook.md.
#
#   bash scripts/azure/setup.sh                 # everything
#   SKIP_MODELS=1 bash scripts/azure/setup.sh   # without pulling model weights
#   VUL4J_SOURCE=hub bash scripts/azure/setup.sh   # pull tuhhsoftsec/vul4j instead of building
#   MODEL_CONFIGS=study.smoke.jsonc bash scripts/azure/setup.sh   # smoke VM: only that config's models
#
# Settings (environment): MODEL_CONFIGS (configs whose open-weight models are pulled; default
# "study.rehearsal.jsonc study.jsonc"), OLLAMA_MAX_LOADED (default 6), MIN_FREE_GB (default 300).
#
# Where things live:
#   OS disk (persistent; make it 1 TB): the repository and all logs (runs/), Docker images
#     (the Vul4J image), Ollama model weights.
#   Local NVMe at $DATA (default /data; wiped when the VM is deallocated): only the Vul4J
#     work directories, which are scratch.
#
# Steps:
#   1. check the NVIDIA driver (nvidia-smi)
#   2. mount the local NVMe disk(s) at $DATA, never formatting a disk that has a filesystem
#   3. install Ollama (version $OLLAMA_VERSION if set) with the study's settings
#   4. pull every open-weight model named in $MODEL_CONFIGS (minutes; a wrong tag fails here,
#      before the hours-long image build)
#   5. install Docker; build the Vul4J image from the pinned Vul4J commit (default) or pull it
#   6. create a Python venv (.venv-linux) and run the tests
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA="${DATA:-/data}"
VUL4J_COMMIT="${VUL4J_COMMIT:-376411da11fa705019f731404de1d0679fe73537}"
VUL4J_TAG="${VUL4J_TAG:-vul4j:376411d}"
VUL4J_SOURCE="${VUL4J_SOURCE:-build}"
OLLAMA_VERSION="${OLLAMA_VERSION:-}"
MODEL_CONFIGS="${MODEL_CONFIGS:-study.rehearsal.jsonc study.jsonc}"
OLLAMA_MAX_LOADED="${OLLAMA_MAX_LOADED:-6}"
MIN_FREE_GB="${MIN_FREE_GB:-300}"
USER_NAME="${SUDO_USER:-$USER}"
say() { printf '\n== %s\n' "$*"; }

say "1. NVIDIA driver"
if ! command -v nvidia-smi >/dev/null || ! nvidia-smi -L; then
  echo "nvidia-smi not working. Use the Ubuntu-HPC image (drivers included) or install the"
  echo "driver: sudo apt-get install -y ubuntu-drivers-common && sudo ubuntu-drivers install --gpgpu"
  echo "then reboot and re-run this script."
  exit 1
fi

say "2. Scratch disk at $DATA"
if mountpoint -q "$DATA"; then
  echo "$DATA already mounted"
else
  sudo mkdir -p "$DATA"
  DEV=""
  if [ -e /dev/md0 ]; then
    DEV=/dev/md0                                  # an existing RAID (e.g. from the image)
  else
    # NVMe disks with no partitions, no filesystem and no mount: safe to format
    mapfile -t FREE < <(lsblk -dpno NAME,TYPE | awk '$1 ~ /nvme/ && $2=="disk" {print $1}' |
      while read -r d; do
        [ "$(lsblk -no NAME "$d" | wc -l)" -eq 1 ] || continue      # has partitions
        sudo blkid "$d" >/dev/null 2>&1 && continue                  # has a filesystem
        [ -z "$(lsblk -no MOUNTPOINT "$d" | tr -d '[:space:]')" ] && echo "$d"
      done)
    if [ "${#FREE[@]}" -gt 1 ]; then
      sudo apt-get install -y mdadm >/dev/null
      sudo mdadm --create /dev/md0 --level=0 --raid-devices="${#FREE[@]}" "${FREE[@]}" --run
      DEV=/dev/md0
    elif [ "${#FREE[@]}" -eq 1 ]; then
      DEV="${FREE[0]}"
    fi
    if [ -n "$DEV" ] && ! sudo blkid "$DEV" >/dev/null 2>&1; then
      sudo mkfs.ext4 -F -L studyscratch "$DEV"
    fi
  fi
  if [ -n "$DEV" ]; then
    sudo mount "$DEV" "$DATA"
    grep -q "LABEL=studyscratch" /etc/fstab || \
      echo "LABEL=studyscratch $DATA ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab >/dev/null
  else
    echo "no free local NVMe disk: $DATA is a directory on the OS disk"
  fi
fi
sudo mkdir -p "$DATA/vul4j-work"
sudo chown "$USER_NAME" "$DATA/vul4j-work"
AVAIL_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
if [ "$AVAIL_GB" -lt "$MIN_FREE_GB" ]; then
  echo "only ${AVAIL_GB} GB free on the OS disk; need ${MIN_FREE_GB} GB for the Vul4J image and the"
  echo "model weights (resize the OS disk: 1 TB for the study VM, 512 GB for the smoke VM)"; exit 1
fi

say "3. Ollama"
if ! command -v ollama >/dev/null; then
  if [ -n "$OLLAMA_VERSION" ]; then
    curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION="$OLLAMA_VERSION" sh
  else
    curl -fsSL https://ollama.com/install.sh | sh
  fi
fi
sudo mkdir -p /etc/systemd/system/ollama.service.d
# NUM_PARALLEL=1: Ollama reserves num_ctx x NUM_PARALLEL of context cache per model; at 64k
# tokens and four slots the six rehearsal models would not fit two H100s.
sudo tee /etc/systemd/system/ollama.service.d/study.conf >/dev/null <<EOF
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_KEEP_ALIVE=60m"
Environment="OLLAMA_MAX_LOADED_MODELS=$OLLAMA_MAX_LOADED"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_FLASH_ATTENTION=1"
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ollama
sudo systemctl restart ollama
for i in $(seq 1 30); do curl -sf http://127.0.0.1:11434/api/version && break; sleep 2; done
echo

say "4. Model weights ($MODEL_CONFIGS)"
if [ "${SKIP_MODELS:-0}" = "1" ]; then
  echo "skipped (SKIP_MODELS=1)"
else
  python3 - "$REPO" $MODEL_CONFIGS <<'PY' | sort -u | while read -r m; do echo "pull $m"; ollama pull "$m"; done
import pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from hp.study_config import parse_jsonc
for name in sys.argv[2:]:
    p = root / name
    if not p.is_file():
        sys.exit(f"MODEL_CONFIGS names {name}, which does not exist")
    else:
        for m in parse_jsonc(p.read_text())["models"].values():
            if m.get("provider") == "openweight" and "TO_PIN" not in str(m.get("model")):
                print(m["model"])
PY
fi
ollama list

say "5. Docker and the Vul4J image"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
fi
sudo usermod -aG docker "$USER_NAME" || true
if [ "$VUL4J_SOURCE" = "hub" ]; then
  VUL4J_TAG="tuhhsoftsec/vul4j"
  sudo docker pull --platform linux/amd64 "$VUL4J_TAG"
  echo "NOTE: set vul4j.image to $VUL4J_TAG and pin_kind to repo_digest in the config"
elif sudo docker image inspect "$VUL4J_TAG" >/dev/null 2>&1; then
  echo "$VUL4J_TAG already built"
else
  SRC="$HOME/vul4j-src"
  [ -d "$SRC/.git" ] || git clone https://github.com/tuhh-softsec/vul4j.git "$SRC"
  git -C "$SRC" fetch origin
  git -C "$SRC" checkout -q "$VUL4J_COMMIT"
  echo "building $VUL4J_TAG from $VUL4J_COMMIT; the build reproduces every CVE once (hours)"
  sudo docker build --platform linux/amd64 -t "$VUL4J_TAG" "$SRC" 2>&1 | tee "$HOME/vul4j-build.log" | tail -5
fi
sudo docker image inspect --format '{{json .RepoDigests}} {{.Id}}' "$VUL4J_TAG"

say "6. Python environment and tests"
sudo apt-get install -y python3-venv >/dev/null
python3 -m venv "$REPO/.venv-linux"
"$REPO/.venv-linux/bin/pip" install -q --upgrade pip
"$REPO/.venv-linux/bin/pip" install -q "pytest>=8.0" "ollama>=0.6" anthropic openai google-genai
cd "$REPO"
"$REPO/.venv-linux/bin/python" -m pytest tests -q

cat <<EOF

Setup done. Log out and in once (docker group), then from $REPO:

  source .venv-linux/bin/activate
  python study.py pin ${MODEL_CONFIGS%% *} --write        # weights pins + Vul4J image id
  python study.py validate ${MODEL_CONFIGS%% *}
  python study.py vul4j-check ${MODEL_CONFIGS%% *} --cve VUL4J-12

Then follow docs/smoke-test.md (smoke VM) or docs/azure-runbook.md, section "Rehearsal".
EOF
