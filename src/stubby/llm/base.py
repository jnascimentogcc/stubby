"""LLM provider interface.

The LLM extracts the vulnerable symbol(s) from advisory text and fix-commit
diffs (see ``symbols.py``). Providers (OpenAI first, then local models)
implement this protocol. Only public advisory data is ever sent to a provider,
never project source code.
"""

from __future__ import annotations

from typing import Protocol


class LLMError(RuntimeError):
    """The provider failed or returned something unusable."""


class LLMProvider(Protocol):
    name: str

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        """Return a JSON object that conforms to ``schema``."""
        ...
