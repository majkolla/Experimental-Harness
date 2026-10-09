"""Configuration and validation for the v1.3 study (Experiment Specification v1.3).

This is the study's counterpart of the legacy `hp/config.py` (Experiment 1),
which stays unchanged. Two rules shape everything here.

**Defaults are config, not code.** Every value the specification fixes or marks
[default ...] is read from the config file, never filled in with `setdefault`.
A missing value is a refusal, not a silent default. The registry
`DEFAULT_KEYS` lists the keys the specification marks as defaults; the shipped
config files carry a `// [default ...]` comment on each of them, and a test
checks that.

**A misconfiguration that would invalidate the design raises.** `load` collects
every problem it can find and raises one `ConfigError` that lists them all.
In particular a ``live`` config refuses to load while any value is still the
placeholder ``TO_PIN_AT_FREEZE`` (model ids, snapshots, weight checksums,
prices, the Vul4J image ...), and a ``synthetic`` config refuses to load if any
model uses a real provider, so a synthetic run can never spend money.

The config file is JSON with ``//`` and ``/* */`` comments (JSONC). Hashes are
taken over the parsed, canonicalised JSON, so comments never change them. The
``freeze`` block is excluded from the config hash (it records that hash).
"""

import hashlib
import json
import pathlib
import re

from .config import ConfigError

PLACEHOLDER = "TO_PIN_AT_FREEZE"
MODES = ("synthetic", "live")

# Design structure (spec section 2, 3): fixed by the design, not tunable.
CORE_GENERATORS = ("A", "B", "C")
CHEAP_REVIEWERS = ("a", "b", "c")
CORE_REVIEWERS = CORE_GENERATORS + CHEAP_REVIEWERS
OPEN_MODELS = ("X", "Y", "Z")
ALL_MODELS = CORE_REVIEWERS + OPEN_MODELS
FAMILY = {"A": 1, "a": 1, "B": 2, "b": 2, "C": 3, "c": 3, "X": 4, "Y": 5, "Z": 6}
TIER = {"A": "strong", "B": "strong", "C": "strong",
        "a": "cheap", "b": "cheap", "c": "cheap",
        "X": "open", "Y": "open", "Z": "open"}

LIVE_PROVIDERS = ("anthropic", "openai", "google", "openweight")
SYNTHETIC_PROVIDERS = ("synthetic_world",)
PACKET_KINDS = ("structure", "ordinary_tests", "contracts")
SUITE_SCOPES = ("full", "module_fallback")
RQ2O_MODES = ("promotion_rule", "fixed_sequence")
SIBLING_METHODS = ("author", "openweight_model")

#: Keys the specification marks [default ...] or [extension default ...].
#: Each must carry such a comment on its line in the shipped config files.
#: Leaf names are unique within a config file, which is what lets the check
#: find the line without a path-tracking parser.
DEFAULT_KEYS = (
    "gen_temperature",
    "gen_top_p",
    "reasoning",
    "gen_output_tokens",
    "review_input_tokens",
    "review_output_tokens",
    "packet_tokens",
    "review_timeout_s",
    "gen_timeout_s",
    "sesoi_unsafe",
    "ni_accept",
    "ni_unsafe",
    "suite_scope",
    "method",
    "paid_block_on_test",
    "rq2o_mode",
)

REQUIRED_TOP = (
    "study", "spec_version", "mode", "seed", "split", "paths", "prompts",
    "models", "pin_rules", "allowed_precisions", "sampling", "caps", "timeouts_s", "max_attempts",
    "workers", "design", "prices_usd_per_mtok", "openweight_cost",
    "acceptance_target", "margins", "alpha_one_sided", "bootstrap", "regret",
    "experiment_b", "extension", "stage1", "sibling", "vul4j", "freeze",
)

PROMPT_SLOTS = {
    "review": ("{{PR_DESCRIPTION}}", "{{DIFF}}", "{{CONTEXT}}", "{{EVIDENCE_SECTION}}"),
    "generate": ("{{ADVISORY}}", "{{FILES}}"),
}


# ---------------------------------------------------------------------------
# JSONC
# ---------------------------------------------------------------------------


def strip_jsonc(text):
    """Return (json_text, comments_by_line). Newlines are preserved.

    Comments are recognised only outside strings, so a URL such as
    "http://host" inside a value survives.
    """
    out = []
    comments = {}
    i, n = 0, len(text)
    line = 1
    in_str = esc = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            elif ch == "\n":
                line += 1
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            comments.setdefault(line, []).append(text[i + 2 : j].strip())
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1:
                raise ConfigError("unterminated /* comment in config")
            body = text[i + 2 : j]
            comments.setdefault(line, []).append(body.strip())
            nl = body.count("\n")
            out.append("\n" * nl)
            line += nl
            i = j + 2
            continue
        if ch == "\n":
            line += 1
        out.append(ch)
        i += 1
    return "".join(out), {k: " ".join(v) for k, v in comments.items()}


def parse_jsonc(text):
    body, _ = strip_jsonc(text)
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config is not valid JSON after removing comments: {exc}")


def default_annotations(text):
    """{leaf_key: comment} for every registered default key found in `text`."""
    _, comments = strip_jsonc(text)
    found = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        for key in DEFAULT_KEYS:
            if re.search(r'"%s"\s*:' % re.escape(key), raw):
                found.setdefault(key, comments.get(lineno, ""))
    return found


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    return sha256_bytes(pathlib.Path(path).read_bytes())


def config_hash(cfg):
    """SHA-256 of the canonical config without its freeze block and derived keys."""
    body = {k: v for k, v in cfg.items() if k != "freeze" and not k.startswith("_")}
    return sha256_bytes(canonical(body))


def code_files(root):
    root = pathlib.Path(root)
    files = [p for p in (root / "hp").rglob("*.py") if "__pycache__" not in p.parts]
    files += [p for p in (root / "prompts").rglob("*") if p.is_file()]
    if (root / "study.py").exists():
        files.append(root / "study.py")
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def code_hash(root):
    """SHA-256 over every analysis-relevant source file (hp/, prompts/, study.py)."""
    root = pathlib.Path(root)
    lines = [
        f"{p.relative_to(root).as_posix()}\t{sha256_file(p)}\n" for p in code_files(root)
    ]
    return sha256_bytes("".join(lines).encode())


# ---------------------------------------------------------------------------
# placeholders
# ---------------------------------------------------------------------------


def find_placeholders(obj, path=""):
    """Dotted paths of every value equal to PLACEHOLDER."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).startswith("_"):
                continue
            hits += find_placeholders(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += find_placeholders(v, f"{path}[{i}]")
    elif obj == PLACEHOLDER:
        hits.append(path)
    return hits


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _get(cfg, dotted):
    cur = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise KeyError(dotted)
        cur = cur[part]
    return cur


# ---------------------------------------------------------------------------
# the gauntlet
# ---------------------------------------------------------------------------


def active_models(cfg):
    """Model refs in use: the six core models, plus X/Y/Z if the extension is on."""
    ext = cfg.get("extension", {}).get("enabled") is True
    return ALL_MODELS if ext else CORE_REVIEWERS


def _check_models(cfg, problems):
    models = cfg["models"]
    mode = cfg["mode"]
    ext = cfg["extension"].get("enabled")
    want = set(active_models(cfg))
    missing = want - set(models)
    if missing:
        problems.append(f"models missing: {sorted(missing)} (extension.enabled={ext})")
    extra = set(models) - set(ALL_MODELS)
    if extra:
        problems.append(f"unknown model references: {sorted(extra)}")

    for ref in sorted(want & set(models)):
        m = models[ref]
        if not isinstance(m, dict):
            problems.append(f"models.{ref} is not an object")
            continue
        for key in ("roles", "family", "tier", "provider", "model"):
            if key not in m:
                problems.append(f"models.{ref}.{key} missing")
        roles = set(m.get("roles") or [])
        if m.get("family") != FAMILY[ref]:
            problems.append(f"models.{ref}.family={m.get('family')!r}, the design fixes {FAMILY[ref]}")
        if m.get("tier") != TIER[ref]:
            problems.append(f"models.{ref}.tier={m.get('tier')!r}, the design fixes {TIER[ref]!r}")
        if TIER[ref] == "cheap" and roles != {"reviewer"}:
            problems.append(f"models.{ref}: a cheap model is a reviewer only, roles={sorted(roles)}")
        if TIER[ref] in ("strong", "open") and roles != {"generator", "reviewer"}:
            problems.append(f"models.{ref}: roles must be generator and reviewer, got {sorted(roles)}")

        prov = m.get("provider")
        if mode == "live" and prov not in LIVE_PROVIDERS:
            problems.append(f"models.{ref}.provider={prov!r} is not allowed in live mode")
        if mode == "synthetic" and prov not in SYNTHETIC_PROVIDERS:
            problems.append(
                f"models.{ref}.provider={prov!r}: synthetic mode allows only "
                f"{SYNTHETIC_PROVIDERS}, so a synthetic run can never make a paid call"
            )
        if mode == "live" and TIER[ref] == "open" and prov != "openweight":
            problems.append(f"models.{ref}: open-tier models are served by 'openweight'")
        if mode == "live" and TIER[ref] != "open" and prov == "openweight":
            problems.append(f"models.{ref}: API-tier models cannot use 'openweight'")

        # Q16: omitting a sampling parameter is a recorded deviation, never silent
        for flag in ("send_temperature", "send_top_p"):
            if m.get(flag, True) is False and not str(m.get("deviation_note", "")).strip():
                problems.append(
                    f"models.{ref}.{flag}=false needs a non-empty deviation_note "
                    "(spec section 6: sampling settings are fixed; an omission is a "
                    "reported deviation)"
                )

    # strong and cheap model of one family share a provider
    for big, small in zip(CORE_GENERATORS, CHEAP_REVIEWERS):
        if big in models and small in models:
            if models[big].get("provider") != models[small].get("provider"):
                problems.append(
                    f"models.{big} and models.{small} are family {FAMILY[big]} "
                    "but use different providers"
                )


def _check_pins(cfg, problems):
    """Q17: a pin rule per provider; open weights need checksum, precision, stack."""
    if cfg["mode"] != "live":
        return
    rules = cfg["pin_rules"]
    for ref in active_models(cfg):
        m = cfg["models"].get(ref)
        if not isinstance(m, dict):
            continue
        prov = m.get("provider")
        if prov == "openweight":
            if any(m.get(k) == PLACEHOLDER for k in ("weights_sha", "precision",
                                                      "serving_stack", "num_ctx")):
                continue  # reported once by the placeholder check
            if cfg.get("allowed_precisions") == PLACEHOLDER:
                continue
            sha = str(m.get("weights_sha", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                problems.append(f"models.{ref}.weights_sha must be a 64-hex SHA-256")
            if m.get("precision") not in cfg.get("allowed_precisions", []):
                problems.append(
                    f"models.{ref}.precision={m.get('precision')!r} not in allowed_precisions"
                )
            if not str(m.get("serving_stack", "")).strip():
                problems.append(f"models.{ref}.serving_stack is empty")
            ctx = m.get("num_ctx")
            need = cfg["caps"].get("review_input_tokens", 0) + cfg["caps"].get(
                "review_output_tokens", 0
            )
            if not _int(ctx) or ctx <= need:
                problems.append(
                    f"models.{ref}.num_ctx={ctx!r} must exceed review input + output caps ({need})"
                )
            continue
        rule = rules.get(prov)
        if not rule:
            problems.append(f"pin_rules has no rule for provider {prov!r}")
            continue
        for key in ("model", "snapshot"):
            val = str(m.get(key, ""))
            if val == PLACEHOLDER:
                continue  # reported once by the placeholder check
            if not re.search(rule, val):
                problems.append(
                    f"models.{ref}.{key}={val!r} does not match the pin rule for {prov} "
                    f"({rule}); a floating alias changes the subject mid-run"
                )


def _check_numbers(cfg, problems):
    s = cfg["sampling"]
    for key in ("gen_temperature", "review_temperature"):
        if not _num(s.get(key)) or not s[key] > 0:
            problems.append(
                f"sampling.{key} must be > 0: at 0 the repeated trials are copies "
                "and every dependence estimate collapses"
            )
    for key in ("gen_top_p", "review_top_p"):
        if not _num(s.get(key)) or not 0 < s[key] <= 1:
            problems.append(f"sampling.{key} must be in (0, 1]")
    if not str(s.get("reasoning", "")).strip():
        problems.append("sampling.reasoning must be set")

    for key in ("gen_output_tokens", "review_input_tokens", "review_output_tokens",
                "packet_tokens", "context_lines", "justification_words",
                "sibling_target_lines"):
        v = cfg["caps"].get(key)
        if not _int(v) or v <= 0:
            problems.append(f"caps.{key} must be a positive integer")
    for key in ("review_timeout_s", "gen_timeout_s"):
        v = cfg["timeouts_s"].get(key)
        if not _num(v) or v <= 0:
            problems.append(f"timeouts_s.{key} must be positive")

    ma = cfg["max_attempts"]
    if not _int(ma) or not 1 <= ma <= 4:
        problems.append("max_attempts must be 1..4 (one call plus at most three retries, section 6)")
    if not _int(cfg["workers"]) or cfg["workers"] < 1:
        problems.append("workers must be a positive integer")

    d = cfg["design"]
    if d.get("trials") != 3:
        problems.append(
            "design.trials must be 3: the panel estimate averages the 36 = 3! x 3! "
            "trial matchings and the 2-of-3 identities assume three trials"
        )
    if (d.get("gate_k"), d.get("gate_n")) != (2, 3):
        problems.append("design gate must be 2-of-3")
    for key in ("attempts_per_cell", "reruns"):
        if not _int(d.get(key)) or d[key] < 1:
            problems.append(f"design.{key} must be a positive integer")

    unit = [("acceptance_target", cfg["acceptance_target"]),
            ("alpha_one_sided", cfg["alpha_one_sided"]),
            ("regret.delta", cfg["regret"].get("delta")),
            ("regret.stability_share", cfg["regret"].get("stability_share"))]
    for name, v in unit:
        if not _num(v) or not 0 < v < 1:
            problems.append(f"{name} must be in (0, 1)")
    for key in ("sesoi_unsafe", "ni_accept", "ni_unsafe"):
        v = cfg["margins"].get(key)
        if not _num(v) or not 0 < v < 1:
            problems.append(f"margins.{key} must be in (0, 1)")

    b = cfg["bootstrap"]
    floor = {"regret_draws": 2000, "confirm_draws": 10000} if cfg["mode"] == "live" else {
        "regret_draws": 20, "confirm_draws": 20}
    for key, lo in floor.items():
        v = b.get(key)
        if not _int(v) or v < lo:
            problems.append(f"bootstrap.{key}={v!r} below the {cfg['mode']} minimum {lo}")


def _check_extension(cfg, problems):
    e = cfg["extension"]
    if not isinstance(e.get("enabled"), bool):
        problems.append(
            "extension.enabled must be set explicitly to true or false (SPEC_ANSWERS Q21)"
        )
    if not isinstance(e.get("paid_block_on_test"), bool):
        problems.append("extension.paid_block_on_test must be true or false")
    if e.get("rq2o_mode") not in RQ2O_MODES:
        problems.append(f"extension.rq2o_mode must be one of {RQ2O_MODES}")
    pr = e.get("promotion", {})
    for key in ("ni_unsafe", "ni_accept", "max_half_width"):
        v = pr.get(key)
        if not _num(v) or not 0 < v < 1:
            problems.append(f"extension.promotion.{key} must be in (0, 1)")


def _check_misc(cfg, problems):
    root = cfg["_root"]
    # split (registered file, read-only, SHA pinned)
    sp = cfg["split"]
    path = root / sp.get("file", "")
    if not path.is_file():
        problems.append(f"split file not found: {sp.get('file')!r}")
    elif cfg["mode"] == "live" or sp.get("sha256") != PLACEHOLDER:
        got = sha256_file(path)
        if got != sp.get("sha256"):
            problems.append(
                f"split file SHA-256 {got} != pinned {sp.get('sha256')}; the "
                "registered split must not change"
            )

    # prompts
    cfg["_prompts"] = {}
    for kind, slots in PROMPT_SLOTS.items():
        rel = cfg["prompts"].get(kind)
        p = root / rel if rel else None
        if not p or not p.is_file():
            problems.append(f"prompts.{kind} not found: {rel!r}")
            continue
        text = p.read_text()
        for slot in slots:
            if slot not in text:
                problems.append(f"prompts.{kind} is missing the slot {slot}")
        cfg["_prompts"][kind] = {"text": text, "sha256": sha256_bytes(text.encode())}

    if cfg["stage1"].get("suite_scope") not in SUITE_SCOPES:
        problems.append(f"stage1.suite_scope must be one of {SUITE_SCOPES}")
    if cfg["sibling"].get("method") not in SIBLING_METHODS:
        problems.append(f"sibling.method must be one of {SIBLING_METHODS}")

    if cfg["mode"] == "synthetic" and not isinstance(cfg.get("synthetic_world"), dict):
        problems.append("synthetic mode needs a synthetic_world block")
    if cfg["mode"] == "live" and "synthetic_world" in cfg:
        problems.append("live mode must not carry a synthetic_world block")

    v = cfg["vul4j"]
    want = "container" if cfg["mode"] == "live" else "mock"
    if v.get("runner") != want:
        problems.append(f"vul4j.runner must be {want!r} in {cfg['mode']} mode")

    xb = cfg["experiment_b"]
    if not _int(xb.get("n_cves")) or xb["n_cves"] < 1:
        problems.append("experiment_b.n_cves must be a positive integer")
    if set(xb.get("reviewers", [])) - set(CHEAP_REVIEWERS) or not xb.get("reviewers"):
        problems.append(
            "experiment_b.reviewers must be cheap reviewers only (no open models, Q21)"
        )
    if tuple(xb.get("packets", [])) != PACKET_KINDS:
        problems.append(f"experiment_b.packets must be {list(PACKET_KINDS)}")

    prices = cfg["prices_usd_per_mtok"]
    for ref in active_models(cfg):
        pr = prices.get(ref)
        if not isinstance(pr, dict) or "input" not in pr or "output" not in pr:
            problems.append(f"prices_usd_per_mtok.{ref} needs input and output")
            continue
        for k in ("input", "output"):
            if pr[k] != PLACEHOLDER and (not _num(pr[k]) or pr[k] < 0):
                problems.append(f"prices_usd_per_mtok.{ref}.{k} must be a number >= 0")
    oc = cfg["openweight_cost"]
    if oc.get("primary") != "hosted_price" or oc.get("sensitivity") != "gpu_seconds":
        problems.append(
            "openweight_cost: primary must be 'hosted_price' and sensitivity 'gpu_seconds'"
        )


def freeze_status(cfg):
    """(ok, reason). ok only if frozen and every recorded hash still matches."""
    fz = cfg.get("freeze") or {}
    if fz.get("frozen") is not True:
        return False, "freeze.frozen is not true"
    if fz.get("config_sha256") != cfg["_config_sha256"]:
        return False, (
            f"config changed since freeze: {cfg['_config_sha256']} != "
            f"{fz.get('config_sha256')}"
        )
    got = code_hash(cfg["_root"])
    if fz.get("code_sha256") != got:
        return False, f"code changed since freeze: {got} != {fz.get('code_sha256')}"
    rec_path = runs_dir(cfg) / "freeze.json"
    if not rec_path.is_file():
        return False, f"{rec_path} missing"
    rec = json.loads(rec_path.read_text())
    if rec.get("config_sha256") != fz.get("config_sha256") or rec.get(
        "code_sha256"
    ) != fz.get("code_sha256"):
        return False, "freeze.json does not match the config's freeze block"
    for rel, sha in (rec.get("artefacts") or {}).items():
        p = runs_dir(cfg) / rel
        if not p.is_file() or sha256_file(p) != sha:
            return False, f"frozen artefact {rel} missing or changed"
    return True, "frozen"


def runs_dir(cfg):
    return cfg["_root"] / cfg["paths"]["runs"]


def load(cfg_path, require_valid_freeze=True):
    """Load and validate a study config. Raises ConfigError listing every problem."""
    cfg_path = pathlib.Path(cfg_path)
    text = cfg_path.read_text()
    cfg = parse_jsonc(text)
    if not isinstance(cfg, dict):
        raise ConfigError("config top level must be an object")
    cfg["_root"] = cfg_path.resolve().parent
    cfg["_path"] = cfg_path.resolve()
    cfg["_text"] = text

    missing = [k for k in REQUIRED_TOP if k not in cfg]
    if missing:
        raise ConfigError(
            "config missing required keys (no silent defaults): " + ", ".join(missing)
        )
    problems = []
    if cfg["mode"] not in MODES:
        raise ConfigError(f"mode={cfg['mode']!r} not in {MODES}")

    try:
        _check_extension(cfg, problems)
        _check_models(cfg, problems)
        _check_numbers(cfg, problems)
        _check_misc(cfg, problems)
        _check_pins(cfg, problems)
    except (KeyError, TypeError, AttributeError) as exc:
        problems.append(f"malformed config section: {exc!r}")

    if cfg["mode"] == "live":
        ph = find_placeholders(cfg)
        if ph:
            problems.append(
                "live mode refuses placeholder values (" + PLACEHOLDER + ") at: "
                + ", ".join(ph)
            )

    cfg["_config_sha256"] = config_hash(cfg)
    fz = cfg.get("freeze") or {}
    for key in ("frozen", "config_sha256", "code_sha256"):
        if key not in fz:
            problems.append(f"freeze.{key} missing")
    if require_valid_freeze and fz.get("frozen") is True and not problems:
        ok, reason = freeze_status(cfg)
        if not ok:
            problems.append(f"freeze block invalid: {reason}")

    if problems:
        raise ConfigError("study config refused:\n  - " + "\n  - ".join(problems))
    return cfg


_FREEZE_BLOCK = re.compile(r'"freeze"\s*:\s*\{[^{}]*\}', re.S)


def write_freeze_block(cfg_path, config_sha, code_sha):
    """Rewrite the freeze block of a config file in place (comments elsewhere kept)."""
    p = pathlib.Path(cfg_path)
    text = p.read_text()
    m = list(_FREEZE_BLOCK.finditer(text))
    if len(m) != 1:
        raise ConfigError("the config must contain exactly one freeze block")
    block = json.dumps(
        {"frozen": True, "config_sha256": config_sha, "code_sha256": code_sha}
    )
    p.write_text(text[: m[0].start()] + f'"freeze": {block}' + text[m[0].end() :])


def freeze(cfg_path, artefacts):
    """Freeze the study: record hashes, write runs/freeze.json, rewrite the freeze line.

    `artefacts` are paths relative to the runs directory (thresholds, primary
    choice, ...). After this, test-split access requires that the config (minus
    its freeze block), the code under hp/, prompts/ and study.py, and every
    artefact are byte-identical to what was frozen.
    """
    import datetime

    cfg = load(cfg_path, require_valid_freeze=False)
    rd = runs_dir(cfg)
    rec = {
        "kind": "freeze",
        "config_path": cfg["_path"].name,
        "config_sha256": cfg["_config_sha256"],
        "code_sha256": code_hash(cfg["_root"]),
        "artefacts": {},
        "frozen_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": cfg["mode"],
    }
    for rel in artefacts:
        p = rd / rel
        if not p.is_file():
            raise ConfigError(f"cannot freeze: artefact {rel} does not exist in {rd}")
        rec["artefacts"][rel] = sha256_file(p)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "freeze.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    write_freeze_block(cfg_path, rec["config_sha256"], rec["code_sha256"])
    return rec

