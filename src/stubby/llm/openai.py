"""OpenAI provider (Chat Completions with structured output)."""

from __future__ import annotations

import json
import os

import httpx

from .base import LLMError

DEFAULT_MODEL = "gpt-4o-mini"
API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider:
    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY is not set")
        self.model = model or os.environ.get("STUBBY_LLM_MODEL") or DEFAULT_MODEL
        self._client = client or httpx.Client(timeout=60.0)

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "result", "strict": True, "schema": schema},
            },
        }
        try:
            resp = self._client.post(
                API_URL, json=body, headers={"Authorization": f"Bearer {self.api_key}"}
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return json.loads(content)
        except httpx.HTTPStatusError as exc:
            # Never echo headers: they carry the API key.
            raise LLMError(f"OpenAI request failed with HTTP {exc.response.status_code}") from None
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError(f"OpenAI request failed: {type(exc).__name__}") from None
