"""Load and validate the experiment configuration and the task bank.

Everything in here runs before a single token is spent. A misconfiguration
that would invalidate the design raises; it does not warn. The relevant
failure mode is not "the run crashes", it is "the run completes and the
numbers mean something other than what the paper claims".
"""

import hashlib
import json
import pathlib
import re

#: Manifest fields that constitute ground truth. The oracle must never appear
#: on a reviewer's input path -- if it does, the experiment measures label
#: leakage rather than review. Enforced structurally: `Task.prompt_inputs()`
#: is the only accessor the request builder is given, and it cannot reach
#: these. `tests/test_oracle_isolation.py` asserts the strings are absent from
#: every built prompt.
ORACLE_KEYS = frozenset(
    {"label", "functional", "cwe", "oracle_notes", "exploit_path", "sibling_of"}
)

LABELS = ("vulnerable", "secure", "indeterminate")
FUNCTIONAL = ("pass", "fail", "unknown")

#: A model id with no version/date component is an alias, and an alias that
#: updates mid-run changes the subject of the experiment while it is being
#: measured, with nothing downstream able to detect it.
_PINNED = re.compile(r"(\d{4}-\d{2}-\d{2}|\d{8}|:\S+|-\d{4}$)")


class ConfigError(ValueError):
    pass


class Task:
    """A frozen task: patch text, a packet bank, and an oracle kept apart."""

    def __init__(self, task_id, root, manifest, patch_text, packets):
        self.task_id = task_id
        self.root = root
        self.patch_text = patch_text
        self.packets = packets  # list[(packet_id, text, sha12)]
        self._manifest = manifest

    # --- reviewer-visible surface (the only thing the prompt builder gets) ---
    def prompt_inputs(self, packet_index):
        pid, text, _ = self.packets[packet_index]
        return {"patch_text": self.patch_text, "packet_text": text, "packet_id": pid}

    # --- analysis-visible surface (never crosses into a request) ------------
    @property
    def oracle(self):
        return {k: self._manifest.get(k) for k in ORACLE_KEYS}

    @property
    def cluster(self):
        """Bootstrap cluster. Siblings of one CVE are *not* independent."""
        return self._manifest.get("cluster") or self.task_id

    @property
    def label(self):
        return self._manifest["label"]

    @property
    def functional(self):
        return self._manifest.get("functional", "unknown")

    @property
    def packet_bank_hash(self):
        return _sha12("".join(h for _, _, h in self.packets))

    def __repr__(self):
        return f"<Task {self.task_id} {self.label}>"


def _sha12(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _load_task(d, packets_per_task):
    manifest_path = d / "manifest.json"
    patch_path = d / "patch.diff"
    if not manifest_path.exists():
        raise ConfigError(f"{d.name}: manifest.json missing (no oracle => no Y)")
    if not patch_path.exists():
        raise ConfigError(f"{d.name}: patch.diff missing")

    manifest = json.loads(manifest_path.read_text())
    if manifest.get("label") not in LABELS:
        raise ConfigError(f"{d.name}: label={manifest.get('label')!r} not in {LABELS}")
    if manifest.get("functional", "unknown") not in FUNCTIONAL:
        raise ConfigError(f"{d.name}: functional={manifest.get('functional')!r}")

    pdir = d / "packets"
    files = sorted(pdir.glob("*.md")) if pdir.exists() else []
    if len(files) != packets_per_task:
        raise ConfigError(
            f"{d.name}: {len(files)} packets, config says {packets_per_task}. "
            "Packet counts must match exactly or B1 (equal packet use within "
            "and across regimes) cannot hold."
        )
    packets = []
    for f in files:
        text = f.read_text()
        packets.append((f.stem, text, _sha12(text)))

    # Equal-budget packets: shared-vs-diverse must vary coupling, not context
    # quality. Length is a crude proxy but catches the gross violation where
    # one arm effectively gets a richer bank.
    lens = [len(t) for _, t, _ in packets]
    if lens and max(lens) > 2 * min(lens):
        raise ConfigError(
            f"{d.name}: packet sizes {lens} differ by more than 2x. Unequal "
            "budgets confound coupling with information quality."
        )
    return Task(d.name, d, manifest, patch_path.read_text(), packets)


def load(cfg_path):
    cfg_path = pathlib.Path(cfg_path)
    cfg = json.loads(cfg_path.read_text())
    root = cfg_path.parent
    cfg["_root"] = root

    for key in ("name", "seed", "temperature", "replicates", "models", "panels", "log"):
        if key not in cfg:
            raise ConfigError(f"config missing required key: {key}")

    cfg.setdefault("regimes", ["shared", "diverse"])
    cfg.setdefault("packets_per_task", 6)
    cfg.setdefault("tasks_dir", "tasks")
    cfg.setdefault("prompt_file", "prompts/reviewer.md")
    cfg.setdefault("max_tokens", 2048)
    cfg.setdefault("timeout_s", 120)
    cfg.setdefault("max_attempts", 4)
    cfg.setdefault("workers", 4)
    cfg.setdefault("strict_model_pinning", True)
    cfg.setdefault("gate", {"k": 2, "n": 3})

    n = cfg["gate"]["n"]
    k = cfg["gate"]["k"]
    P = cfg["packets_per_task"]
    R = cfg["replicates"]

    # --- temperature -------------------------------------------------------
    # At temperature 0 the R replicates are one measurement copied R times:
    # the cross-replicate recombination baseline has nothing to recombine, and
    # every dependence estimate collapses to zero by construction.
    if not cfg["temperature"] > 0:
        raise ConfigError(
            "temperature must be > 0. At 0 the replicates are not replicates "
            "and q_recomb degenerates."
        )

    # --- panel shape -------------------------------------------------------
    if not 1 <= k <= n:
        raise ConfigError(f"gate k={k} outside 1..n={n}")
    for panel, seats in cfg["panels"].items():
        if len(seats) != n:
            raise ConfigError(f"panel {panel} has {len(seats)} seats, gate n={n}")
        for ref in seats:
            if ref not in cfg["models"]:
                raise ConfigError(f"panel {panel} references unknown model {ref!r}")

    # --- design divisibility ----------------------------------------------
    if R < 3:
        raise ConfigError(
            "replicates must be >= 3: the recombination baseline is built from "
            "triples of *distinct* replicate indices."
        )
    if P % n:
        raise ConfigError(
            f"packets_per_task={P} must be divisible by n={n}; the cyclic "
            f"design uses step P/n."
        )
    if R % P:
        raise ConfigError(
            f"replicates={R} must be a multiple of packets_per_task={P} for "
            "B1/B2 to hold exactly rather than approximately."
        )
    if R % n:
        raise ConfigError(
            f"replicates={R} must be a multiple of n={n} so that seat rotation "
            "puts every model in every seat equally often (B3)."
        )

    # --- model pinning -----------------------------------------------------
    unpinned = [
        f"{ref}={m['model']}"
        for ref, m in cfg["models"].items()
        if not _PINNED.search(m["model"])
    ]
    if unpinned and cfg["strict_model_pinning"]:
        raise ConfigError(
            "model ids look like floating aliases: "
            + ", ".join(unpinned)
            + ". Pin exact snapshots, or set strict_model_pinning=false and "
            "accept that a mid-run release is undetectable."
        )

    # --- prompt and tasks --------------------------------------------------
    prompt = (root / cfg["prompt_file"]).read_text()
    for token in ("{{PATCH}}", "{{CONTEXT}}"):
        if token not in prompt:
            raise ConfigError(f"prompt template is missing {token}")
    cfg["_prompt"] = prompt
    cfg["_prompt_hash"] = _sha12(prompt)

    tdir = root / cfg["tasks_dir"]
    dirs = sorted(p for p in tdir.iterdir() if p.is_dir()) if tdir.exists() else []
    if not dirs:
        raise ConfigError(f"no task directories under {tdir}")
    cfg["_tasks"] = [_load_task(d, P) for d in dirs]

    if not any(t.label == "vulnerable" for t in cfg["_tasks"]):
        raise ConfigError("no vulnerable tasks: there is no false approval to measure")
    if not any(t.label == "secure" for t in cfg["_tasks"]):
        raise ConfigError(
            "no secure sibling tasks. With defective patches only, a reviewer "
            "that rejects everything scores perfectly."
        )

    cfg["_config_hash"] = _sha12(
        json.dumps(
            {
                key: cfg[key]
                for key in (
                    "name",
                    "seed",
                    "temperature",
                    "replicates",
                    "models",
                    "panels",
                    "regimes",
                    "packets_per_task",
                    "gate",
                    "max_tokens",
                )
            },
            sort_keys=True,
        )
    )
    return cfg


def build_prompt(template, patch_text, packet_text):
    """The *only* function that assembles reviewer input.

    Its signature is the enforcement mechanism for oracle isolation: there is
    no parameter through which a label, CWE id or exploit note could arrive.
    """
    return template.replace("{{PATCH}}", patch_text).replace(
        "{{CONTEXT}}", packet_text
    )
