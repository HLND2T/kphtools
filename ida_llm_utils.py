from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx
from openai import AsyncOpenAI


def create_openai_client(base_url: str | None, api_key: str) -> AsyncOpenAI:
    kwargs: dict[str, Any] = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs)


def _require_non_empty(value: str | None, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} cannot be empty")
    return text


async def _call_llm_text_via_codex_http(
    *,
    model: str,
    prompt: str,
    api_key: str,
    base_url: str | None,
    temperature: float | None = None,
    effort: str | None = None,
) -> str:
    normalized_base_url = _require_non_empty(base_url, "base_url")
    parsed_base = urlparse(normalized_base_url)
    if not parsed_base.netloc:
        raise ValueError("base_url must include host")

    body: dict[str, Any] = {
        "input": [{"role": "user", "content": prompt}],
        "model": _require_non_empty(model, "model"),
        "stream": True,
    }
    if effort:
        body["reasoning"] = {"effort": str(effort).strip().lower()}
    if temperature is not None:
        body["temperature"] = temperature

    headers = {
        "Authorization": f"Bearer {_require_non_empty(api_key, 'api_key')}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Accept-Encoding": "identity",
        "Host": parsed_base.netloc,
    }
    text_parts: list[str] = []
    endpoint = normalized_base_url.rstrip("/") + "/responses"
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, read=300.0),
        trust_env=False,
    ) as client:
        async with client.stream("POST", endpoint, headers=headers, json=body) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                stripped = line.strip()
                if not stripped.startswith("data:"):
                    continue
                payload_text = stripped[5:].strip()
                if not payload_text or payload_text == "[DONE]":
                    continue
                payload = json.loads(payload_text)
                event_type = payload.get("type") if isinstance(payload, dict) else None
                if event_type == "response.output_text.delta":
                    text_parts.append(str(payload.get("delta") or ""))
                elif event_type == "response.completed":
                    response_payload = payload.get("response")
                    if not isinstance(response_payload, dict):
                        continue
                    for item in response_payload.get("output") or []:
                        if not isinstance(item, dict):
                            continue
                        for content_item in item.get("content") or []:
                            if (
                                isinstance(content_item, dict)
                                and content_item.get("type") == "output_text"
                            ):
                                text_parts.append(str(content_item.get("text") or ""))
                elif event_type in {"error", "response.error", "response.failed"}:
                    raise RuntimeError(f"codex transport received {event_type}")

    return "".join(text_parts).strip()


async def call_llm_text(
    model: str,
    prompt: str,
    api_key: str,
    base_url: str | None = None,
    temperature: float | None = None,
    effort: str | None = None,
    fake_as: str | None = None,
) -> str:
    if str(fake_as or "").strip().lower() == "codex":
        return await _call_llm_text_via_codex_http(
            model=model,
            prompt=prompt,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            effort=effort,
        )

    client = create_openai_client(base_url, api_key)
    request: dict[str, Any] = {"model": model, "input": prompt}
    if temperature is not None:
        request["temperature"] = temperature
    if effort:
        request["reasoning"] = {"effort": str(effort).strip().lower()}
    response = await client.responses.create(**request)
    return response.output_text
