"""Rehearsal mode: the real pipeline with open-weight stand-ins in every slot.
It must never make a paid call, never open the test split, never be frozen,
and never share logs with the study."""

import json
import pathlib
import shutil

import pytest

from hp import pins, study_config as S
from hp.bank import split

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHA = "ab" * 32


class Probe:
    def __init__(self, host):
        pass

    def version(self):
        return "0.13.0"

    def facts(self, model):
        return {"weights_sha": SHA, "precision": "Q8_0"}


class Inspect:
    def __init__(self, digests, image_id="sha256:" + "99" * 32):
        self.digests, self.image_id = digests, image_id

    def __call__(self, argv):
        class P:
            returncode, stderr = 0, ""
            stdout = json.dumps(self.digests) + "|" + self.image_id
        assert argv[:3] == ["docker", "image", "inspect"]
        return P()


def _rehearsal(tmp_path):
    shutil.copy(ROOT / "study.rehearsal.jsonc", tmp_path / "study.rehearsal.jsonc")
    shutil.copytree(ROOT / "prompts", tmp_path / "prompts")
    (tmp_path / "docs" / "spec").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "spec" / "proposed_split.json", tmp_path / "docs" / "spec")
    return tmp_path / "study.rehearsal.jsonc"


def _pinned(tmp_path):
    path = _rehearsal(tmp_path)
    pins.run(path, write=True, probe_factory=Probe,
             docker_run=Inspect(["tuhhsoftsec/vul4j@sha256:" + "cd" * 32]))
    return path


def test_the_shipped_rehearsal_config_needs_only_server_facts(tmp_path):
    path = _rehearsal(tmp_path)
    with pytest.raises(S.ConfigError) as exc:
        S.load(path)
    msg = str(exc.value)
    assert "rehearsal mode refuses placeholder values" in msg
    left = msg.split(" at: ")[1].split(", ")
    assert all(p.split(".")[-1] in ("weights_sha", "precision", "serving_stack", "image_digest")
               for p in left)


def test_pin_writes_server_facts_and_keeps_comments(tmp_path):
    path = _pinned(tmp_path)
    text = path.read_text()
    assert "TO_PIN_AT_FREEZE" not in text
    assert "// Nine slots, every one an open-weight stand-in" in text
    cfg = S.load(path)
    assert cfg["mode"] == "rehearsal"
    assert all(m["weights_sha"] == SHA and m["serving_stack"] == "ollama 0.13.0"
               for m in cfg["models"].values())
    assert cfg["vul4j"]["image_digest"] == "sha256:" + "99" * 32     # a local build: image id
    assert cfg["vul4j"]["pin_kind"] == "image_id"
    assert cfg["models"]["X"]["reasoning_params"] == {"think": False}   # nested object kept
    # strong stand-ins share the X/Y/Z weights and context, so Ollama loads each once
    for big, ext in (("A", "X"), ("B", "Y"), ("C", "Z")):
        assert (cfg["models"][big]["model"], cfg["models"][big]["num_ctx"]) == \
            (cfg["models"][ext]["model"], cfg["models"][ext]["num_ctx"])


def test_a_paid_provider_is_refused(tmp_path):
    path = _pinned(tmp_path)
    text = path.read_text().replace('"model": "qwen3.5:9b"', '"model": "qwen3.5:9b"', 1)
    text = text.replace('"tier": "strong", "provider": "openweight"',
                        '"tier": "strong", "provider": "anthropic"', 1)
    path.write_text(text)
    with pytest.raises(S.ConfigError, match="never make a paid call"):
        S.load(path)


def test_rehearsal_logs_are_kept_apart(tmp_path):
    path = _pinned(tmp_path)
    path.write_text(path.read_text().replace('"runs": "runs/rehearsal"', '"runs": "runs/study"'))
    with pytest.raises(S.ConfigError, match="paths.runs must contain 'rehearsal'"):
        S.load(path)
    live = (tmp_path / "study.rehearsal.jsonc").read_text().replace('"mode": "rehearsal"', '"mode": "live"')
    live = live.replace('"runs": "runs/study"', '"runs": "runs/rehearsal"')
    (tmp_path / "live.jsonc").write_text(live)
    with pytest.raises(S.ConfigError, match="live mode must not write into rehearsal logs"):
        S.load(tmp_path / "live.jsonc")


def test_a_rehearsal_never_opens_the_test_split_and_cannot_be_frozen(tmp_path):
    path = _pinned(tmp_path)
    cfg = S.load(path)
    sp = split.load_split(cfg)
    dev, test = sp.cves("development")[0], sp.cves("test")[0]
    assert split.assert_accessible(cfg, dev, "generation") == "development"
    for purpose in split.LOCKED_PURPOSES:
        with pytest.raises(split.SplitLockError, match="rehearsal never touches the test split"):
            split.assert_accessible(cfg, test, purpose)
    with pytest.raises(S.ConfigError, match="rehearsal cannot be frozen"):
        S.freeze(path, [])
    text = path.read_text().replace('"frozen": false', '"frozen": true')
    path.write_text(text)
    with pytest.raises(S.ConfigError, match="cannot be frozen"):
        S.load(path)


def test_vul4j_pin_is_a_registry_digest_or_a_local_image_id():
    run = Inspect(["other/img@sha256:" + "00" * 32, "tuhhsoftsec/vul4j@sha256:" + "11" * 32])
    assert pins.vul4j_digest("tuhhsoftsec/vul4j", run) == ("sha256:" + "11" * 32, "repo_digest")
    assert pins.vul4j_digest("vul4j:376411d", Inspect([])) == ("sha256:" + "99" * 32, "image_id")
    with pytest.raises(RuntimeError, match="no digest or image id"):
        pins.vul4j_digest("vul4j:376411d", Inspect([], image_id=""))


def test_a_local_image_pin_is_written_with_its_kind(tmp_path):
    path = _rehearsal(tmp_path)
    pins.run(path, write=True, probe_factory=Probe, docker_run=Inspect([]))
    cfg = S.load(path)
    assert cfg["vul4j"]["image_digest"] == "sha256:" + "99" * 32
    assert cfg["vul4j"]["pin_kind"] == "image_id"
