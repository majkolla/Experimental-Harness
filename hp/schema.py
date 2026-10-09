"""The reviewer's output contract, and the status taxonomy around it.

Two invariants live here.

1. `run_status` is strictly separate from `decision`. A timeout is not an
   abstention; a truncated response is not a rejection; a schema violation is
   not a verdict. Collapsing these into one "missing" bucket biases the gate
   estimates, because the collapse rate is not uniform across model families --
   verbose models truncate more often, so missingness would be correlated with
   the composition factor under study.

2. Parsing never guesses. A response either yields a verdict that validates
   against VERDICT_SCHEMA, or it yields a status explaining why it did not.
"""

import json

DECISIONS = ("approve", "reject", "abstain")
SEVERITIES = ("none", "low", "medium", "high", "critical")

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "merge_verdict": {"type": "string", "enum": list(DECISIONS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "summary": {"type": "string"},
                },
                "required": ["severity", "summary"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["merge_verdict", "confidence", "findings"],
    "additionalProperties": False,
}

# --- status taxonomy -------------------------------------------------------
# Exactly one of these ends up on every log record.

OK = "ok"  # a schema-valid verdict was obtained
SCHEMA_INVALID = "schema_invalid"  # response arrived, did not validate
TRUNCATED = "truncated"  # provider stopped on the token limit
TIMEOUT = "timeout"  # no response within timeout_s
TRANSPORT_ERROR = "transport_error"  # network / 5xx / rate limit exhausted
REQUEST_ERROR = "request_error"  # 4xx: our request was wrong, do not retry

STATUSES = (OK, SCHEMA_INVALID, TRUNCATED, TIMEOUT, TRANSPORT_ERROR, REQUEST_ERROR)

#: Statuses worth another attempt. REQUEST_ERROR is not here on purpose: an
#: invalid request will fail identically forever and retrying only burns budget.
RETRYABLE = (TIMEOUT, TRANSPORT_ERROR)

#: A call is "complete" for resume purposes only if it reached OK. The previous
#: implementation treated any logged record as done, so one transient 429
#: permanently removed that call from the schedule -- and its panel with it.
COMPLETE = (OK,)


class SchemaError(ValueError):
    """The response did not carry a verdict conforming to VERDICT_SCHEMA."""


def validate(obj):
    """Minimal dependency-free validation of VERDICT_SCHEMA.

    Deliberately hand-written rather than jsonschema: the contract is four
    fields, and an experiment should not silently change shape because a
    validation library was upgraded mid-run.
    """
    if not isinstance(obj, dict):
        raise SchemaError(f"top level is {type(obj).__name__}, not object")
    extra = set(obj) - {"merge_verdict", "confidence", "findings"}
    if extra:
        raise SchemaError(f"unexpected keys: {sorted(extra)}")
    missing = {"merge_verdict", "confidence", "findings"} - set(obj)
    if missing:
        raise SchemaError(f"missing keys: {sorted(missing)}")

    if obj["merge_verdict"] not in DECISIONS:
        raise SchemaError(f"merge_verdict={obj['merge_verdict']!r} not in {DECISIONS}")

    conf = obj["confidence"]
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise SchemaError(f"confidence is {type(conf).__name__}, not number")
    if not 0.0 <= float(conf) <= 1.0:
        raise SchemaError(f"confidence={conf} outside [0,1]")

    findings = obj["findings"]
    if not isinstance(findings, list):
        raise SchemaError("findings is not an array")
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            raise SchemaError(f"findings[{i}] is not an object")
        if set(f) != {"severity", "summary"}:
            raise SchemaError(f"findings[{i}] keys = {sorted(f)}")
        if f["severity"] not in SEVERITIES:
            raise SchemaError(f"findings[{i}].severity={f['severity']!r}")
        if not isinstance(f["summary"], str):
            raise SchemaError(f"findings[{i}].summary is not a string")

    return {
        "merge_verdict": obj["merge_verdict"],
        "confidence": float(conf),
        "findings": findings,
    }


def _json_candidates(text):
    """Yield every balanced-brace substring of `text`, outermost first.

    Replaces `re.search(r"\\{.*\\}", text, re.S)`, which is greedy and spans
    from the first '{' to the last '}' anywhere in the response. Any reviewer
    that writes prose containing a brace, emits two JSON blocks, or wraps its
    answer in a fenced code block after some reasoning defeats that regex --
    and the failure is silent, showing up as a dropped panel rather than a
    parse error.
    """
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0:
                    yield text[start : i + 1]


def parse_verdict(payload):
    """Return (verdict_dict, None) or (None, reason_string).

    `payload` is either a dict (provider-native structured output, the normal
    path) or raw text (fallback for providers without schema enforcement).
    """
    if isinstance(payload, dict):
        try:
            return validate(payload), None
        except SchemaError as exc:
            return None, str(exc)

    if not payload or not payload.strip():
        return None, "empty response"

    reasons = []
    for cand in _json_candidates(payload):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError as exc:
            reasons.append(f"json: {exc.msg}")
            continue
        try:
            return validate(obj), None
        except SchemaError as exc:
            reasons.append(str(exc))
    if not reasons:
        return None, "no JSON object found"
    return None, "; ".join(reasons[:3])


# ---------------------------------------------------------------------------
# Output contracts. The legacy verdict above is one contract; the v1.3 study
# adds its review verdict and a plain-text contract for generation. Every
# provider backend receives a contract and asks for that shape natively.
# ---------------------------------------------------------------------------

#: OpenAI strict json_schema rejects validation keywords like minimum/maximum,
#: so the wire schema is the structural subset; the local validator still
#: enforces the numeric range on the way back in.
LEGACY_STRICT_SCHEMA = {
    "type": "object",
    "properties": {
        "merge_verdict": {"type": "string", "enum": list(DECISIONS)},
        "confidence": {"type": "number"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "summary": {"type": "string"},
                },
                "required": ["severity", "summary"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["merge_verdict", "confidence", "findings"],
    "additionalProperties": False,
}

#: Spec v1.3 section 11.3. `risk` is the reviewer's estimate (0-100) that the
#: patched code is still exploitable for the reported issue or has a new
#: vulnerability. Any number in [0, 100] is valid (SPEC_ANSWERS Q4); a long
#: justification is recorded, never invalidating.
REVIEW_V13_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(DECISIONS)},
        "risk": {"type": "number", "minimum": 0, "maximum": 100},
        "justification": {"type": "string"},
    },
    "required": ["verdict", "risk", "justification"],
    "additionalProperties": False,
}

REVIEW_V13_STRICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(DECISIONS)},
        "risk": {"type": "number"},
        "justification": {"type": "string"},
    },
    "required": ["verdict", "risk", "justification"],
    "additionalProperties": False,
}


def validate_v13(obj):
    """Validate a v1.3 review verdict. Returns the normalised dict."""
    if not isinstance(obj, dict):
        raise SchemaError(f"top level is {type(obj).__name__}, not object")
    keys = {"verdict", "risk", "justification"}
    extra = set(obj) - keys
    if extra:
        raise SchemaError(f"unexpected keys: {sorted(extra)}")
    missing = keys - set(obj)
    if missing:
        raise SchemaError(f"missing keys: {sorted(missing)}")
    if obj["verdict"] not in DECISIONS:
        raise SchemaError(f"verdict={obj['verdict']!r} not in {DECISIONS}")
    risk = obj["risk"]
    if isinstance(risk, bool) or not isinstance(risk, (int, float)):
        raise SchemaError(f"risk is {type(risk).__name__}, not number")
    if not 0.0 <= float(risk) <= 100.0:
        raise SchemaError(f"risk={risk} outside [0, 100]")
    if not isinstance(obj["justification"], str):
        raise SchemaError("justification is not a string")
    return {
        "verdict": obj["verdict"],
        "risk": float(risk),
        "justification": obj["justification"],
        "justification_words": len(obj["justification"].split()),
    }


def validate_text(obj):
    if not isinstance(obj, str) or not obj.strip():
        raise SchemaError("empty text response")
    return {"text": obj}


class Contract:
    """What a call must return, and how a provider should ask for it."""

    def __init__(self, name, kind, schema, strict_schema, tool_name, tool_desc,
                 validator, summarise):
        self.name = name
        self.kind = kind  # "json" or "text"
        self.schema = schema
        self.strict_schema = strict_schema
        self.tool_name = tool_name
        self.tool_desc = tool_desc
        self.validate = validator
        self.summarise = summarise

    def __repr__(self):
        return f"<Contract {self.name}>"


LEGACY = Contract(
    "legacy_exp1", "json", VERDICT_SCHEMA, LEGACY_STRICT_SCHEMA, "submit_review",
    "Submit your merge verdict for the patch under review. "
    "merge_verdict must be one of approve, reject, abstain.",
    validate,
    lambda v: {"decision": v["merge_verdict"], "confidence": v["confidence"]},
)

REVIEW_V13 = Contract(
    "review_v13", "json", REVIEW_V13_SCHEMA, REVIEW_V13_STRICT_SCHEMA, "submit_review",
    "Submit your review: verdict (approve, reject or abstain), risk (0-100) "
    "and a justification of at most 150 words.",
    validate_v13,
    lambda v: {"decision": v["verdict"], "risk": v["risk"],
               "justification_words": v["justification_words"]},
)

TEXT = Contract(
    "text", "text", None, None, None, None, validate_text,
    lambda v: {"decision": None, "text": v["text"]},
)


def parse_with(payload, contract):
    """Like parse_verdict, for any contract. Returns (value, None) or (None, reason)."""
    if contract.kind == "text":
        try:
            return contract.validate(payload), None
        except SchemaError as exc:
            return None, str(exc)
    if isinstance(payload, dict):
        try:
            return contract.validate(payload), None
        except SchemaError as exc:
            return None, str(exc)
    if not payload or not str(payload).strip():
        return None, "empty response"
    reasons = []
    for cand in _json_candidates(payload):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError as exc:
            reasons.append(f"json: {exc.msg}")
            continue
        try:
            return contract.validate(obj), None
        except SchemaError as exc:
            reasons.append(str(exc))
    if not reasons:
        return None, "no JSON object found"
    return None, "; ".join(reasons[:3])
