from concurrent.futures import ThreadPoolExecutor
from ollama import chat

QUERY = "What is the capital of France?"

MODELS = [
    "llama3.2",
    "gemma3",
    "qwen3",
]


def ask_local(model: str, prompt: str) -> str:
    response = chat(
        model=model,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return response.message.content


def run_panel(prompt: str):
    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(
            lambda model: ask_local(model, prompt),
            MODELS,
        ))


responses = run_panel(QUERY)

for model, response in zip(MODELS, responses):
    print(f"\n--- {model} ---")
    print(response)