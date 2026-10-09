"""The oracle must never reach the prompt.

If a label, CWE id or exploit note leaks into reviewer input, the experiment
measures label leakage rather than review -- and the leak is invisible in the
results, because a reviewer that reads "this patch is still vulnerable" produces
perfectly plausible verdicts.
"""

import inspect

from hp import config, design


def test_no_oracle_string_appears_in_any_prompt(write_cfg):
    cfg = config.load(write_cfg())
    tasks = {t.task_id: t for t in cfg["_tasks"]}
    # `label` and `functional` are single common words that legitimately occur
    # in prose; the distinctive oracle content is what a leak would carry.
    telltale = ("cwe", "oracle_notes", "exploit_path")
    secrets = [
        v
        for t in cfg["_tasks"]
        for key, v in t.oracle.items()
        if key in telltale and isinstance(v, str) and len(v) > 3
    ]
    assert len(secrets) >= 8, "fixture must plant oracle strings"

    for call in design.build_schedule(cfg):
        task = tasks[call["task"]]
        pi = task.prompt_inputs(call["packet_index"])
        prompt = config.build_prompt(cfg["_prompt"], pi["patch_text"], pi["packet_text"])
        for s in secrets:
            assert s not in prompt, f"oracle leak in {call['call_id']}: {s!r}"


def test_build_prompt_has_no_channel_for_the_oracle(write_cfg):
    """Structural enforcement, not a convention: there is no parameter to leak through."""
    params = list(inspect.signature(config.build_prompt).parameters)
    assert params == ["template", "patch_text", "packet_text"]


def test_prompt_inputs_exposes_only_reviewer_visible_material(write_cfg):
    cfg = config.load(write_cfg())
    task = cfg["_tasks"][0]
    assert set(task.prompt_inputs(0)) == {"patch_text", "packet_text", "packet_id"}
    assert set(task.oracle) >= {"label", "cwe", "oracle_notes", "exploit_path"}


def test_gate_rule_is_absent_from_the_prompt(write_cfg):
    """A reviewer told "two of three merges this" answers a different question."""
    cfg = config.load(write_cfg())
    lowered = cfg["_prompt"].lower()
    for phrase in ("two of three", "2 of 3", "majority", "other reviewer", "panel"):
        assert phrase not in lowered
