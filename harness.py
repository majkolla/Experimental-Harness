import os
import time
 
 
def _ollama(model, prompt, temperature):
    from ollama import chat
 
    r = chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": temperature},
    )
    return r.message.content, {"served_model": model}
 
 
def _anthropic(model, prompt, temperature):
    from anthropic import Anthropic
 
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    r = client.messages.create(
        model=model,
        max_tokens=1024,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    return r.content[0].text, {
        "served_model": r.model,
        "stop_reason": r.stop_reason,
        "in_tokens": r.usage.input_tokens,
        "out_tokens": r.usage.output_tokens,
    }
 
 
def _openai(model, prompt, temperature):
    from openai import OpenAI
 
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    r = client.responses.create(
        model=model,
        input=prompt,
        temperature=temperature,
    )
    return r.output_text, {
        "served_model": r.model,
        "in_tokens": r.usage.input_tokens,
        "out_tokens": r.usage.output_tokens,
    }
 
 
PROVIDERS = {"ollama": _ollama, "anthropic": _anthropic, "openai": _openai}
 
 
def dispatch(provider, model, prompt, temperature):
    """Returns a dict. status is 'ok' or 'error' -- separate from any verdict."""
    started = time.time()
    try:
        text, meta = PROVIDERS[provider](model, prompt, temperature)
        status = "ok"
    except Exception as exc:  # noqa: BLE001 - a failed call is data, not a crash
        text, meta, status = None, {"error": repr(exc)}, "error"
    return {
        "status": status,
        "response": text,
        "started": started,
        "finished": time.time(),
        **meta,
    }