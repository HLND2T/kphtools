from __future__ import annotations

from typing import Any

from openai import AsyncOpenAI


def create_openai_client(base_url: str | None, api_key: str) -> AsyncOpenAI:
    kwargs: dict[str, Any] = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs)


async def call_llm_text(
    model: str,
    prompt: str,
    api_key: str,
    base_url: str | None = None,
    temperature: float | None = None,
) -> str:
    client = create_openai_client(base_url, api_key)
    response = await client.responses.create(
        model=model,
        input=prompt,
        temperature=temperature,
    )
    return response.output_text
