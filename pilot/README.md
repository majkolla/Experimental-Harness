# Reviewer pilot

A small, separate check to run before the full study: do three LLM reviewers tend to approve
the same vulnerable code? It does not use the `hp/` harness.

## What it does

1. `build_items.py` takes the CVEs of the **development** split. For each CVE it cuts the
   changed region (±25 lines) out of the human fix commit, once before the fix and once after.
   - Before the fix is a **vulnerable** item; after the fix is a **safe** item.
   - The test split is never used.
2. `pilot.py run` sends every item to each of three reviewers, 3 times each, as separate async
   API calls. Each reviewer answers approve or reject, with a risk score.
3. `pilot.py report` compares how often all three, and two of three, approve vulnerable code
   against what independent reviewers would give (the product of their individual rates).
   Confidence intervals come from resampling repositories.

## Steps

```bash
cd pilot
python build_items.py                         # needs GitHub access; writes items.jsonl
cp config.example.json config.json            # set the three model ids
python pilot.py run --mock                    # dry run: fake reviewers, no keys, no cost
pip install anthropic openai google-genai
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=... GOOGLE_API_KEY=...
python pilot.py run                           # asks before making calls; rerun to resume
python pilot.py report                        # numbers again, from results.jsonl
```

## Local models with Ollama

Local models cost nothing per call, need no API keys, and keep fixed weights (each answer logs
the model's digest). The `ollama` provider uses only the Python standard library, so nothing
needs installing besides Ollama.

Run the pilot on the Mac itself: the Ollama server listens on `localhost`.

1. Install the Ollama app from ollama.com and open it.
2. Pull three models from **different makers**. Different makers are what make the
   correlation question interesting. Choose by the Mac's memory:

   | Mac memory | models                                                                 | download |
   |------------|------------------------------------------------------------------------|----------|
   | 16 GB      | `qwen3.5:9b` (Alibaba), `gemma4:12b` (Google), `granite4.2:8b` (IBM)   | ~20 GB   |
   | 32 GB      | `qwen3.5:9b`, `gemma4:12b`, `gpt-oss:20b` (OpenAI)                     | ~29 GB   |
   | 64 GB+     | `qwen3.5:27b`, `gemma4:31b`, `gpt-oss:20b`                             | ~51 GB   |

   ```bash
   ollama pull qwen3.5:9b && ollama pull gemma4:12b && ollama pull granite4.2:8b
   ```
3. `cp config.local.example.json config.json`, and change the models if you chose a different row.
4. Try one model on 2 CVEs, and look at `seconds` in `results.jsonl`:
   `python pilot.py run --only qwen --limit 2`
5. Run one model at a time, so Ollama does not swap models in and out of memory:
   ```bash
   python pilot.py run --only qwen
   python pilot.py run --only gemma
   python pilot.py run --only granite
   python pilot.py report
   ```
   Each model makes 126 calls. If all three fit in memory at once, run without `--only` and set
   `"concurrency": 3`.

Settings worth knowing:

- **`num_ctx` (default 16384).**
  - Ollama's own default context is small: 4k tokens on machines with under 24 GB of GPU memory.
  - It cuts longer prompts silently.
  - The pilot sets the context on every call. It refuses to start if the longest prompt would
    not fit, or if a model is not pulled.
- **Thinking.**
  - These models reason before answering by default, which is slower.
  - `"think": false` turns it off for qwen3.5 and gemma4; gpt-oss takes a level such as
    `"think": "low"`.
  - Use the same choice for all three reviewers where you can, and write it down.
- **`"structured": true`.**
  - Forces the answer into the JSON schema.
  - Leave it off unless a model keeps producing unparsed answers.
  - Try it on `--limit 2` first: its interaction with thinking models is not documented.

These are open models of 8 to 31B parameters. A result says how open-weight reviewers fail
together, which matches the study's X/Y/Z extension. It does not say how commercial frontier
reviewers do.

## Size and cost

21 of the 23 development CVEs build:

- VUL4J-27 is skipped because its code is over 400 lines.
- VUL4J-28 is skipped because it shares VUL4J-27's fix.

That gives 21 CVEs × 2 items × 3 reviewers × 3 trials = 378 calls. Each call sends at most
about 5k tokens and gets back a short JSON answer.

GitHub limits unauthenticated use to 60 API calls an hour; one build uses about 23. Answers are
cached in `.cache/`, so a rebuild (for example with a different `--context`) costs none. If the
limit is hit, `items.jsonl` is left untouched.

## Outputs

- `results.jsonl`: one line per call, including the raw answer.
- `results.report.txt`: the report.
- `results.per_item.csv`: approval rate per item and reviewer, to see which vulnerabilities
  every reviewer misses.

## Config

`config.json` has three reviewers. Each one has:

- `provider`: one of `anthropic`, `openai`, `google` or `ollama` (local; see above).
- `model`
- `temperature`: optional; set it to `null` for models that refuse it.
- `api_key_env`: optional; overrides the default key variable.

`"provider": "openai"` with `"base_url"` reaches any OpenAI-compatible server, such as
OpenRouter or vLLM. For Ollama, use `"provider": "ollama"`, which can set the context length.

## Limits

- Reviewers judge a code region, not a generated patch.
- The CVEs are public, so models may recognise them.
- The fixed code can contain clues, such as an added check or comment.
- About ten repositories give wide intervals. A simulation gave about 88% coverage for the
  nominal 95% intervals.

Read the result as a go / no-go signal for the full study.
