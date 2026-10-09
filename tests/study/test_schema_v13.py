"""The v1.3 review contract (section 11.3, SPEC_ANSWERS Q4) and the text contract."""

import pytest

from hp import schema
from hp.schema import REVIEW_V13, TEXT, SchemaError, parse_with, validate_v13


def test_any_number_in_range_is_a_valid_risk():
    for risk in (0, 35, 35.0, 12.5, 100):
        assert validate_v13({"verdict": "approve", "risk": risk, "justification": "x"})["risk"] == float(risk)


@pytest.mark.parametrize("risk", [-1, 100.5, True, "40", None])
def test_out_of_range_or_non_numeric_risk_is_a_schema_violation(risk):
    with pytest.raises(SchemaError):
        validate_v13({"verdict": "approve", "risk": risk, "justification": "x"})


def test_a_long_justification_is_recorded_not_rejected():
    v = validate_v13({"verdict": "reject", "risk": 80, "justification": "word " * 400})
    assert v["justification_words"] == 400


def test_unknown_verdict_and_extra_keys_are_violations():
    with pytest.raises(SchemaError, match="verdict"):
        validate_v13({"verdict": "lgtm", "risk": 1, "justification": ""})
    with pytest.raises(SchemaError, match="unexpected keys"):
        validate_v13({"verdict": "approve", "risk": 1, "justification": "", "notes": ""})


def test_text_fallback_finds_the_verdict_after_prose():
    text = 'I looked at {the diff}. {"verdict": "abstain", "risk": 50, "justification": "unclear"}'
    v, reason = parse_with(text, REVIEW_V13)
    assert reason is None and v["verdict"] == "abstain"


def test_text_contract_requires_non_empty_text():
    assert parse_with("```diff\n```", TEXT)[0] == {"text": "```diff\n```"}
    assert parse_with("  ", TEXT) == (None, "empty text response")


def test_legacy_contract_is_still_the_default():
    assert schema.parse_verdict({"merge_verdict": "approve", "confidence": 0.5, "findings": []})[0]
    assert schema.LEGACY.validate is schema.validate
