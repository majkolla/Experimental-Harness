"""Section 18.4: no generator identity, CVE id, project slug, commit hash or PoV
token appears in any review input. Checked on every input the synthetic
development run actually built (e0 and all Experiment B packets), against the
world's own ground truth rather than through hp.leaks."""

import re

from hp import logs, study_config as S, synthworld
from hp.bank import split as SP


def _inputs(dev_run):
    rd = dev_run["rd"]
    rows = list(logs.read(rd / "inputs.jsonl"))
    texts = {r["input_sha"]: (rd / "inputs" / f"{r['input_sha']}.txt").read_text()
             for r in rows if r["status"] == "ok"}
    return rows, texts


def test_every_built_input_is_free_of_oracle_and_identity_material(dev_run):
    cfg = dev_run["cfg"]
    world = synthworld.world_for(cfg)
    rows, texts = _inputs(dev_run)
    assert rows and len(texts) >= 2
    assert {r["packet"] for r in rows} == {None, "structure", "ordinary_tests", "contracts"}
    models = [m["model"] for m in cfg["models"].values()]
    for r in rows:
        if r["status"] != "ok":
            continue
        text = texts[r["input_sha"]]
        c = world.cves[r["cve"]]
        # the slug as a reference; as a Java path or package segment it is code (Q12)
        assert not re.search(r"(?<![\w./-])" + re.escape(c["cluster"]) + r"(?![\w/-])", text)
        assert "github.com/" + c["cluster"] not in text
        forbidden = [r["cve"], *c["commit_hashes"], *[h[:7] for h in c["commit_hashes"]],
                     synthworld.POV_METHOD, synthworld.POV_MESSAGE, *c["pov_tests"], *models,
                     r["pair_id"], r["candidate_id"]]
        for f in forbidden:
            assert f not in text, (f, r["candidate_id"], r["packet"])
        assert not re.search(r"VUL4J-\d+|CVE-\d{4}-\d+", text)
        assert not re.search(r"\bgenerator\b", text, re.I)


def test_the_pov_test_file_never_reaches_a_packet(dev_run):
    world = synthworld.world_for(dev_run["cfg"])
    rows, texts = _inputs(dev_run)
    tests_packets = [r for r in rows if r["packet"] == "ordinary_tests" and r["status"] == "ok"]
    assert tests_packets
    for r in tests_packets:
        text = texts[r["input_sha"]]
        pov_file = world.cves[r["cve"]]["pov_test_files"][0]
        assert pov_file not in text
        assert "DispatcherTest" in text  # an ordinary test file touching the class is included


def test_allowed_project_tokens_are_recorded(dev_run):
    rows, _ = _inputs(dev_run)
    assert all(r["allowed_project_tokens"] for r in rows)


def test_review_rows_carry_oracle_fields_only_on_the_analysis_side(dev_run):
    rows = [r for r in logs.read(dev_run["rd"] / "reviews.jsonl")]
    assert rows and all(r["generator"] and r["cve"] for r in rows)
    split = SP.load_split(dev_run["cfg"])
    assert {split.split_of[r["cve"]] for r in rows} == {"development"}


def test_real_backends_never_receive_the_synthetic_context(monkeypatch, tmp_path):
    from hp import engine, providers, schema

    seen = []

    def fake(spec, prompt, cfg, contract):
        seen.append(set(spec))
        return {"verdict": "approve", "risk": 1, "justification": ""}, {"served_model": spec["model"]}

    monkeypatch.setitem(providers.PROVIDERS, "anthropic", fake)
    cfg = {"models": {"A": {"provider": "anthropic", "model": "m", "tier": "strong"}},
           "max_attempts": 4, "workers": 1, "seed": 1,
           "sampling": {"review_temperature": 0.7, "review_top_p": 1.0},
           "caps": {"review_output_tokens": 10}, "timeouts_s": {"review_timeout_s": 1},
           "prices_usd_per_mtok": {"A": {"input": 0, "output": 0}}, "openweight_cost": {}}
    calls = [{"call_id": "c1", "panel_key": "k", "model_ref": "A", "_context": {"generator": "B"}}]
    engine.run_calls(cfg, calls, tmp_path / "log.jsonl", "probe", schema.REVIEW_V13,
                     lambda c: ("p", "sha"), lambda c, rec, ex: {"kind": "reproduction", **{
                         k: None for k in logs.REQUIRED["reproduction"] if k != "kind"}},
                     "review")
    assert seen and all("_context" not in keys and "_world" not in keys for keys in seen)
