"""Verdict parsing, and the status taxonomy that keeps missingness honest."""

import json
import re

from hp import schema

GOOD = {"merge_verdict": "approve", "confidence": 0.8, "findings": []}


def _old_greedy_parse(text):
    """The previous implementation, kept as the thing being regressed against."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))["merge_verdict"]
    except (json.JSONDecodeError, KeyError):
        return None


def test_structured_payload_passes_straight_through():
    v, reason = schema.parse_verdict(GOOD)
    assert reason is None and v["merge_verdict"] == "approve"


def test_prose_containing_braces_defeats_the_greedy_regex_but_not_the_parser():
    text = (
        "Looking at the diff, the guard `if x in {a, b}` covers the listing path "
        "but not the export path.\n\n"
        "```json\n" + json.dumps(GOOD) + "\n```\n"
    )
    assert _old_greedy_parse(text) is None, "fixture must actually break the old parser"
    v, reason = schema.parse_verdict(text)
    assert reason is None and v["merge_verdict"] == "approve"


def test_two_json_objects_the_second_of_which_is_the_verdict():
    text = '{"scratch": {"considered": ["a", "b"]}}\n' + json.dumps(GOOD)
    v, reason = schema.parse_verdict(text)
    assert reason is None and v["confidence"] == 0.8


def test_trailing_prose_after_the_object():
    text = json.dumps(GOOD) + "\n\nHappy to elaborate if useful."
    v, _ = schema.parse_verdict(text)
    assert v is not None


def test_unknown_verdict_value_is_a_schema_violation_not_a_rejection():
    v, reason = schema.parse_verdict({"merge_verdict": "APPROVE_WITH_NITS",
                                      "confidence": 0.5, "findings": []})
    assert v is None and "merge_verdict" in reason


def test_confidence_out_of_range_is_rejected():
    bad = dict(GOOD, confidence=1.7)
    v, reason = schema.parse_verdict(bad)
    assert v is None and "confidence" in reason


def test_extra_keys_are_rejected():
    v, reason = schema.parse_verdict(dict(GOOD, risk_score=3))
    assert v is None and "unexpected" in reason


def test_findings_shape_is_enforced():
    v, reason = schema.parse_verdict(
        dict(GOOD, findings=[{"severity": "catastrophic", "summary": "x"}])
    )
    assert v is None and "severity" in reason


def test_empty_and_missing_json():
    assert schema.parse_verdict("")[1] == "empty response"
    assert schema.parse_verdict("I cannot help with that.")[1] == "no JSON object found"


def test_braces_inside_strings_do_not_confuse_the_scanner():
    payload = dict(GOOD, findings=[{"severity": "low", "summary": 'uses f"{sort}"'}])
    v, _ = schema.parse_verdict(json.dumps(payload))
    assert v["findings"][0]["summary"] == 'uses f"{sort}"'


def test_statuses_are_distinct_and_retry_policy_is_narrow():
    """Truncation, schema violation, timeout and a 400 are four different facts."""
    assert len(set(schema.STATUSES)) == len(schema.STATUSES)
    assert schema.TRUNCATED != schema.SCHEMA_INVALID
    assert set(schema.RETRYABLE) == {schema.TIMEOUT, schema.TRANSPORT_ERROR}
    # a schema violation is not retried: same prompt, same temperature, same
    # failure -- it is a datum about the model, recorded as one
    assert schema.SCHEMA_INVALID not in schema.RETRYABLE
    assert schema.REQUEST_ERROR not in schema.RETRYABLE
    assert schema.COMPLETE == (schema.OK,)
