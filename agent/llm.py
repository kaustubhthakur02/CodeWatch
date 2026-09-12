"""Thin OpenRouter chat client."""

from __future__ import annotations

import json
import os

import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("CODEWATCH_MODEL", "openai/gpt-4o-mini")


class LLMError(RuntimeError):
    pass


def chat(
    messages: list[dict],
    model: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 4096,
    expect_json: bool = False,
) -> str:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise LLMError("OPENROUTER_API_KEY is not set")

    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if expect_json:
        payload["response_format"] = {"type": "json_object"}

    resp = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/codewatch",
            "X-Title": "CodeWatch",
        },
        json=payload,
        timeout=180,
    )
    if resp.status_code != 200:
        raise LLMError(f"OpenRouter {resp.status_code}: {resp.text[:500]}")

    data = resp.json()
    if "choices" not in data:
        raise LLMError(f"Unexpected OpenRouter response: {json.dumps(data)[:500]}")
    return data["choices"][0]["message"]["content"]


def chat_json(messages: list[dict], **kwargs) -> dict:
    raw = chat(messages, expect_json=True, **kwargs)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Models occasionally wrap JSON in a markdown fence despite response_format.
        stripped = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
        return json.loads(stripped.strip())
