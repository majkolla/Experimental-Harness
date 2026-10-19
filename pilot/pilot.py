#!/usr/bin/env python3
"""Pilot: do three LLM reviewers miss the same vulnerabilities?

Each item is a piece of Java code with a known label: "vulnerable" (the code
before a CVE fix) or "safe" (the same code after the fix). Each reviewer looks
at each item `trials` times, as independent async API calls. The report
compares how often all three (and two of three) approve vulnerable code with
what you would expect if their mistakes were independent.

    python pilot.py run    --config config.json --items items.jsonl
    python pilot.py report --config config.json --items items.jsonl
    python pilot.py run    --config config.json --items items.jsonl --mock   # offline, no keys
    python pilot.py run    --only R1 --limit 2                               # one reviewer, 2 CVEs

Local models: "provider": "ollama" talks to an Ollama server (default
http://localhost:11434) and needs no API key and no extra Python package.

Answers are appended to results.jsonl (results.mock.jsonl with --mock).
Rerunning `run` skips calls that already have an answer, so an interrupted
run can simply be restarted. Calls that failed after 4 attempts are retried.
"""

import argparse
import asyncio
import hashlib
import urllib.request
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

PROMPT = """You are reviewing Java code before it is merged into a production codebase.
Decide whether this code contains a security vulnerability that should block the merge.

```java
{code}
```

Answer with JSON only, no other text:
{{"verdict": "approve" or "reject", "risk": <0-100: how likely a security vulnerability is present>, "reason": "<one sentence>"}}
"approve" means you see no security problem that should block the merge."""

DEFAULT_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "google": "GOOGLE_API_KEY"}


# ---------------------------------------------------------------------------
# one API call per provider; each returns the model's text
# ---------------------------------------------------------------------------

_clients = {}


def _client(r, make):
    if r["name"] not in _clients:
        _clients[r["name"]] = make()
    return _clients[r["name"]]


def _key(r):
    if r["provider"] == "ollama":
        return "unused"
    env = r.get("api_key_env", DEFAULT_KEY_ENV.get(r["provider"]))
    return os.environ.get(env) or ("unused" if r.get("base_url") else None)


def _temperature(r):
    return {} if r.get("temperature") is None else {"temperature": r["temperature"]}


async def call_anthropic(r, prompt, item):
    import anthropic
    client = _client(r, lambda: anthropic.AsyncAnthropic(api_key=_key(r)))
    msg = await client.messages.create(model=r["model"], max_tokens=r.get("max_tokens", 1000),
                                       messages=[{"role": "user", "content": prompt}], **_temperature(r))
    return "".join(b.text for b in msg.content if b.type == "text")


async def call_openai(r, prompt, item):
    # also covers any OpenAI-compatible server (OpenRouter, Ollama, vLLM) via "base_url"
    import openai
    client = _client(r, lambda: openai.AsyncOpenAI(api_key=_key(r), base_url=r.get("base_url")))
    resp = await client.chat.completions.create(model=r["model"], **_temperature(r),
                                                messages=[{"role": "user", "content": prompt}])
    return resp.choices[0].message.content or ""


async def call_google(r, prompt, item):
    from google import genai
    from google.genai import types
    client = _client(r, lambda: genai.Client(api_key=_key(r)))
    config = types.GenerateContentConfig(**_temperature(r)) if _temperature(r) else None
    resp = await client.aio.models.generate_content(model=r["model"], contents=prompt, config=config)
    return resp.text or ""


REVIEW_SCHEMA = {"type": "object", "required": ["verdict", "risk", "reason"],
                 "properties": {"verdict": {"type": "string", "enum": ["approve", "reject"]},
                                "risk": {"type": "number"}, "reason": {"type": "string"}}}


def _http_json(url, body=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def ollama_host(r):
    return r.get("host", "http://localhost:11434").rstrip("/")


async def call_ollama(r, prompt, item):
    """A local model served by Ollama. The native API is used so the context
    length can be set per call (Ollama otherwise cuts long prompts silently)."""
    body = {"model": r["model"], "stream": False, "keep_alive": r.get("keep_alive", "30m"),
            "messages": [{"role": "user", "content": prompt}],
            "options": {"num_ctx": r.get("num_ctx", 16384), **_temperature(r)}}
    if r.get("structured"):
        body["format"] = REVIEW_SCHEMA  # constrained JSON; see README before using with thinking models
    if "think" in r:
        body["think"] = r["think"]      # true / false, or a level such as "low" for gpt-oss
    data = await asyncio.to_thread(_http_json, ollama_host(r) + "/api/chat", body, r.get("timeout_s", 900))
    return data["message"].get("content") or "", {
        "prompt_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count"),
        "done_reason": data.get("done_reason"), "model_digest": r.get("_digest")}


async def call_mock(r, prompt, item):
    """Offline stand-in. Some items are hard for everyone (a planted shared blind
    spot), so the report should show joint approval above independence."""
    h = lambda s: int(hashlib.sha256(s.encode()).hexdigest(), 16) % 1000 / 1000
    hard = h(item.get("pair", item["id"])) < 0.3                  # 30% of CVEs are hard for all
    skill = 0.15 + 0.1 * h(r["name"])                             # reviewer-specific base rate
    if item["label"] == "vulnerable":
        p_approve = 0.75 if hard else skill
    else:
        p_approve = 0.85
    await asyncio.sleep(0)
    verdict = "approve" if random.random() < p_approve else "reject"
    return json.dumps({"verdict": verdict, "risk": 20 if verdict == "approve" else 80, "reason": "mock"})


CALLS = {"anthropic": call_anthropic, "openai": call_openai, "google": call_google,
         "ollama": call_ollama, "mock": call_mock}


def parse(text):
    """The first JSON object in the text that carries a valid verdict."""
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text, i)
        except ValueError:
            continue
        if isinstance(obj, dict) and str(obj.get("verdict", "")).lower() in ("approve", "reject"):
            return str(obj["verdict"]).lower(), obj.get("risk"), obj.get("reason")
    return None, None, None


async def review(r, item, trial, sem):
    prompt = PROMPT.format(code=item["code"])
    row = {"item": item["id"], "reviewer": r["name"], "model": r["model"], "trial": trial}
    err = None
    for attempt in range(1, 5):
        async with sem:
            t0 = time.time()
            try:
                out = await asyncio.wait_for(CALLS[r["provider"]](r, prompt, item),
                                             timeout=r.get("timeout_s", 900 if r["provider"] == "ollama" else 180))
            except Exception as e:  # rate limit, timeout, server error: back off and try again
                err = f"{type(e).__name__}: {str(e)[:300]}"
            else:
                text, meta = out if isinstance(out, tuple) else (out, {})
                verdict, risk, reason = parse(text)
                return {**row, "status": "ok" if verdict else "unparsed", "verdict": verdict,
                        "risk": risk, "reason": reason, "raw": text[:2000], **meta,
                        "attempts": attempt, "seconds": round(time.time() - t0, 2)}
        await asyncio.sleep(min(60, 2 ** attempt + random.random()))
    return {**row, "status": "error", "error": err, "attempts": 4}


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def load_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass  # a line cut off by an interrupted run
    return rows


def results_path(args):
    return Path(args.results or ("results.mock.jsonl" if args.mock else "results.jsonl"))


def prompt_tokens_estimate(item):
    """Rough upper estimate: Java code is about 3 to 4 bytes per token."""
    return len(PROMPT.format(code=item["code"]).encode()) // 3


def check_ollama(r, items):
    """The server answers, the model is pulled, and every prompt fits the context."""
    try:
        tags = _http_json(ollama_host(r) + "/api/tags")["models"]
    except Exception as e:
        return [f"{r['name']}: no Ollama server at {ollama_host(r)} ({type(e).__name__}); start the Ollama app"]
    found = {m["name"]: m.get("digest") for m in tags}
    name = r["model"] if ":" in r["model"] else r["model"] + ":latest"
    if name not in found:
        return [f"{r['name']}: model {r['model']} is not pulled; run: ollama pull {r['model']}"]
    r["_digest"] = found[name]
    need = max((prompt_tokens_estimate(it) for it in items), default=0) + 1500  # room for the answer
    if need > r.get("num_ctx", 16384):
        return [f"{r['name']}: the longest prompt needs about {need} tokens; set \"num_ctx\" to at least that"]
    return []


def reviewers(cfg, mock, items=()):
    revs = cfg["reviewers"]
    if len(revs) != 3 or len({r["name"] for r in revs}) != 3:
        sys.exit("config: exactly three reviewers with distinct names are needed")
    if mock:
        return [{**r, "provider": "mock"} for r in revs]
    problems = []
    for r in revs:
        if r["provider"] not in CALLS or r["provider"] == "mock":
            problems.append(f"{r['name']}: unknown provider {r['provider']!r}")
        if not r.get("model") or r["model"] == "SET_ME":
            problems.append(f"{r['name']}: set the model id")
        elif r["provider"] == "ollama":
            problems += check_ollama(r, items)
            continue
        if not _key(r):
            problems.append(f"{r['name']}: environment variable "
                            f"{r.get('api_key_env', DEFAULT_KEY_ENV.get(r['provider']))} is not set")
    if problems:
        sys.exit("config problems:\n  " + "\n  ".join(problems))
    return revs


def limit_items(items, n):
    """The items of the first n CVE pairs."""
    if not n:
        return items
    keep = list(dict.fromkeys(it.get("pair", it["id"]) for it in items))[:n]
    return [it for it in items if it.get("pair", it["id"]) in keep]


async def run(args, cfg):
    items = limit_items(load_jsonl(args.items), args.limit)
    revs = reviewers(cfg, args.mock, items)
    if args.only:
        revs = [r for r in revs if r["name"] in args.only.split(",")]
        if not revs:
            sys.exit(f"--only {args.only}: no reviewer with that name in the config")
    out = results_path(args)
    done = {(r["item"], r["reviewer"], r["trial"]) for r in load_jsonl(out)
            if r["status"] in ("ok", "unparsed")}
    todo = [(r, it, t) for it in items for r in revs for t in range(1, cfg.get("trials", 3) + 1)
            if (it["id"], r["name"], t) not in done]
    random.Random(cfg.get("seed", 1)).shuffle(todo)  # no ordering by item or provider
    print(f"{len(items)} items x {len(revs)} reviewer(s) x {cfg.get('trials', 3)} trials: "
          f"{len(todo)} calls to make ({len(done)} already answered) -> {out}")
    if not todo:
        return
    if not (args.mock or args.yes) and input("Make these calls? [y/N] ").strip().lower() != "y":
        return
    sem = asyncio.Semaphore(cfg.get("concurrency", 8))
    status = Counter()
    with open(out, "a", encoding="utf-8") as fh:
        for n, fut in enumerate(asyncio.as_completed([review(r, it, t, sem) for r, it, t in todo]), 1):
            row = await fut
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            status[row["status"]] += 1
            if n % 25 == 0 or n == len(todo):
                print(f"  {n}/{len(todo)}  {dict(status)}")
    if status["error"]:
        print(f"{status['error']} calls failed after 4 attempts; run again to retry them.")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def h3(a, b, c):
    """P(at least 2 of 3 approve) when the three decisions are independent."""
    return a * b + a * c + b * c - 2 * a * b * c


def mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else float("nan")


def summarise(P):
    """P: one row per item, the three reviewers' approval rates on that item.

    Per item, the product of the three rates is the mean over all 27 matchings
    of their trials, i.e. the chance that one random answer from each approves.
    The independence reference multiplies the reviewers' overall rates instead.
    """
    p = [mean(col) for col in zip(*P)]
    pairs = {(i, j): (mean(row[i] * row[j] for row in P), p[i] * p[j])
             for i in range(3) for j in range(i + 1, 3)}
    return {"p": p,
            "all_obs": mean(math.prod(row) for row in P), "all_ind": math.prod(p),
            "maj_obs": mean(h3(*row) for row in P), "maj_ind": h3(*p), "pairs": pairs}


def bootstrap(P_by_group, draws, seed):
    """Resample groups (repositories) with replacement; differences observed - independent."""
    rng = random.Random(seed)
    groups = sorted(P_by_group)
    d_all, d_maj, ratio = [], [], []
    for _ in range(draws):
        rows = [row for g in (rng.choice(groups) for _ in groups) for row in P_by_group[g]]
        s = summarise(rows)
        d_all.append(s["all_obs"] - s["all_ind"])
        d_maj.append(s["maj_obs"] - s["maj_ind"])
        if s["all_ind"] > 0:
            ratio.append(s["all_obs"] / s["all_ind"])
    ci = lambda v: (sorted(v)[int(0.025 * len(v))], sorted(v)[int(0.975 * len(v)) - 1]) if v else (None, None)
    return ci(d_all), ci(d_maj), ci(ratio)


def report(args, cfg):
    names = [r["name"] for r in cfg["reviewers"]]
    models = {r["name"]: "mock" if args.mock else r.get("model") for r in cfg["reviewers"]}
    items = {it["id"]: it for it in limit_items(load_jsonl(args.items), args.limit)}
    rows = [r for r in load_jsonl(results_path(args)) if r["item"] in items]
    if not rows:
        sys.exit(f"no results in {results_path(args)} for these items")
    status = Counter(r["status"] for r in rows)
    votes = defaultdict(list)
    for r in rows:
        if r["status"] == "ok":
            votes[(r["item"], r["reviewer"])].append(1.0 if r["verdict"] == "approve" else 0.0)

    rates, left_out = {}, []
    for iid in sorted(items):
        v = [votes.get((iid, n)) for n in names]
        if all(v):
            rates[iid] = [mean(x) for x in v]
        else:
            left_out.append(iid)

    def by_label(label):
        return [iid for iid in rates if items[iid]["label"] == label]

    vul, safe = by_label("vulnerable"), by_label("safe")
    if not vul:
        missing = [n for n in names if not any(k[1] == n for k in votes)]
        sys.exit("no vulnerable item has an answer from every reviewer yet"
                 + (f" (no answers yet from {', '.join(missing)}; run them with --only)" if missing else ""))
    sv, ss = summarise([rates[i] for i in vul]), summarise([rates[i] for i in safe]) if safe else None
    groups = defaultdict(list)
    for i in vul:
        groups[items[i].get("group", i)].append(rates[i])
    ci_all, ci_maj, ci_ratio = bootstrap(groups, cfg.get("bootstrap_draws", 2000), cfg.get("seed", 1))

    f = lambda x: "n/a" if x is None or x != x else f"{x:.3f}"
    sd = lambda x: "n/a" if x is None else f"{x:+.3f}"
    row = lambda label, *cols: f"  {label:<34}" + "".join(f"{c:>19}" for c in cols)
    ratio = sv["all_obs"] / sv["all_ind"] if sv["all_ind"] else None
    L = [f"Pilot report: {len(vul)} vulnerable and {len(safe)} safe items, "
         f"{len(groups)} repositories, {cfg.get('trials', 3)} trials per reviewer",
         f"Calls: {dict(status)}; items left out (a reviewer has no valid answer): {len(left_out)}",
         "", row("Approval rate", "vulnerable code", "safe code"),
         row("", "(lower = better)", "(higher = better)")]
    for k, n in enumerate(names):
        L.append(row(f"{n} ({models[n]})", f(sv["p"][k]), f(ss["p"][k]) if ss else "n/a"))
    L += ["", row("Vulnerable code approved by", "observed", "if independent", "difference", "95% CI"),
          row("all three reviewers", f(sv["all_obs"]), f(sv["all_ind"]),
              sd(sv["all_obs"] - sv["all_ind"]), f"[{sd(ci_all[0])}, {sd(ci_all[1])}]"),
          row("two or more (majority gate)", f(sv["maj_obs"]), f(sv["maj_ind"]),
              sd(sv["maj_obs"] - sv["maj_ind"]), f"[{sd(ci_maj[0])}, {sd(ci_maj[1])}]"),
          row("the best single reviewer", f(min(sv["p"]))),
          "", f"  All three approve {'n/a' if ratio is None else f'{ratio:.1f}x'} as often as independence "
              f"predicts (95% CI {'n/a' if ci_ratio[0] is None else f'{ci_ratio[0]:.1f}x to {ci_ratio[1]:.1f}x'}).",
          "", row("Both approve vulnerable code", "observed", "if independent")]
    for (i, j), (obs, ind) in sv["pairs"].items():
        L.append(row(f"{names[i]} + {names[j]}", f(obs), f(ind)))
    if ss:
        L += ["", row("Safe code approved by", "observed"),
              row("all three reviewers", f(ss["all_obs"])),
              row("two or more (majority gate)", f(ss["maj_obs"]))]
    missed = [i for i in vul if min(rates[i]) >= 2 / 3]
    L += ["", f"Vulnerable items every reviewer approved in at least 2 of 3 trials: {len(missed)}"]
    for i in missed:
        L.append(f"  {i:<28} {items[i].get('cwe', ''):<12} approval {[round(x, 2) for x in rates[i]]}")
    L += ["", "How to read this: every call is separate, so the reviewers cannot copy each other.",
          "Observed above 'if independent' means they tend to miss the same vulnerabilities, so a",
          "panel buys less safety than multiplying their error rates suggests. With about ten",
          "repositories the intervals are wide and run somewhat narrow (about 88% coverage instead",
          "of 95% in a simulation): treat the result as a go / no-go signal, not a finding."]
    text = "\n".join(L)
    print(text)
    out, csv = results_path(args).with_suffix(".report.txt"), results_path(args).with_suffix(".per_item.csv")
    out.write_text(text + "\n", encoding="utf-8")
    with open(csv, "w", encoding="utf-8") as fh:
        fh.write("item,group,label,cwe," + ",".join(names) + "\n")
        for iid, rr in sorted(rates.items()):
            it = items[iid]
            fh.write(f"{iid},{it.get('group', '')},{it['label']},{it.get('cwe', '')},"
                     + ",".join(f"{x:.3f}" for x in rr) + "\n")
    print(f"\n(written to {out} and {csv})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "report"])
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--items", default="items.jsonl")
    ap.add_argument("--results", help="default: results.jsonl (results.mock.jsonl with --mock)")
    ap.add_argument("--mock", action="store_true", help="offline fake reviewers, no API keys, no cost")
    ap.add_argument("--yes", action="store_true", help="do not ask before making calls")
    ap.add_argument("--only", help="run only these reviewers (comma-separated names), e.g. one local model at a time")
    ap.add_argument("--limit", type=int, help="use only the first N CVEs (a quick trial run)")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.command == "run":
        asyncio.run(run(args, cfg))
        args.command = "report"
    report(args, cfg)


if __name__ == "__main__":
    main()
