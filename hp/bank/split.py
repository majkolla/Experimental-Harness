"""The registered development/test split, and the test-set lock (section 5.4).

The split file is read, never written: its SHA-256 is pinned in the config and
checked at load. Test-split CVEs are unreachable for generation, correction
and review until the study is frozen: `freeze.frozen` is true AND the config
hash, the code hash and every frozen artefact still match (`study_config.
freeze_status`). Stage 1 (reproduction) and the timing pilot may touch test
CVEs; they never call a model.

In synthetic mode the active CVEs are the synthetic world's subset of the
registered split (`synthetic_world.cve_limit`).
"""

import json

from .. import study_config as S
from .. import synthworld


class SplitLockError(PermissionError):
    """A test-split CVE was requested before the study was frozen."""


SPLITS = ("development", "test")
LOCKED_PURPOSES = ("generation", "correction", "review", "selection")


class Split:
    def __init__(self, data):
        self.data = data
        self.cluster_of = {}
        self.split_of = {}
        for name in SPLITS:
            for cluster, cves in data[name].items():
                for cve in cves:
                    self.cluster_of[cve] = cluster
                    self.split_of[cve] = name

    def cves(self, name):
        return sorted(
            (c for c, s in self.split_of.items() if s == name),
            key=lambda c: (len(c), c),
        )

    def clusters(self, name):
        return sorted(self.data[name])


def load_split(cfg):
    if "_split" in cfg:
        return cfg["_split"]
    raw = json.loads((cfg["_root"] / cfg["split"]["file"]).read_text())
    if cfg["mode"] == "synthetic":
        raw = {**raw, **synthworld.world_for(cfg).split}
    cfg["_split"] = Split(raw)
    return cfg["_split"]


def frozen(cfg):
    """(ok, reason), computed once per loaded config."""
    if "_freeze_ok" not in cfg:
        cfg["_freeze_ok"] = S.freeze_status(cfg)
    return cfg["_freeze_ok"]


def assert_accessible(cfg, cve, purpose):
    split = load_split(cfg)
    name = split.split_of.get(cve)
    if name is None:
        raise SplitLockError(f"{cve} is not in the registered split")
    if name == "test" and purpose in LOCKED_PURPOSES:
        ok, reason = frozen(cfg)
        if not ok:
            raise SplitLockError(
                f"{cve} is a test-split CVE: {purpose} is locked until the study is "
                f"frozen ({reason})"
            )
    return name


def accessible_cves(cfg, name, purpose):
    """Every CVE of a split, after the lock check (raises for a locked test split)."""
    cves = load_split(cfg).cves(name)
    for cve in cves:
        assert_accessible(cfg, cve, purpose)
    return cves
