import os
from concurrent.futures import ThreadPoolExecutor


QUERY = "What is the capital of France?"

MODELS = [
    ("ollama", "llama3.2"),
    ("ollama", "gemma3"),
    ("ollama", "qwen3"),
    ("anthropic", "claude-sonnet-4-6"),
    ("openai", "gpt-5.6"),
]


def ask_local(model: str, prompt: str) -> str:
    from ollama import chat

    response = chat(
        model=model,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    return response.message.content


def ask_anthropic(model: str, prompt: str) -> str:
    from anthropic import Anthropic

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"]
    )

    response = client.messages.create(
        model=model,
        max_tokens=1000,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    return response.content[0].text


def ask_openai(model: str, prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"]
    )

    response = client.responses.create(
        model=model,
        input=prompt,
    )

    return response.output_text


ASK = {
    "ollama": ask_local,
    "anthropic": ask_anthropic,
    "openai": ask_openai,
}


def ask_agent(agent):
    provider, model = agent
    return ASK[provider](model, QUERY)


def run_panel():
    with ThreadPoolExecutor(max_workers=len(MODELS)) as pool:
        return list(pool.map(ask_agent, MODELS))


responses = run_panel()

for (provider, model), response in zip(MODELS, responses):
    print(f"\n--- {provider}: {model} ---")
    print(response)