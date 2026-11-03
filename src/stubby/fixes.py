"""Fetch the diff of a vulnerability's fix commit (public GitHub data only)."""

from __future__ import annotations

import re

import httpx

MAX_DIFF_CHARS = 12_000
_MAX_URLS = 2
_GITHUB_FIX = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/(?:commit/[0-9a-f]{7,40}|pull/\d+)/?$")


def fetch_fix_diff(urls: list[str], client: httpx.Client) -> str:
    """Return the (truncated) diff of the first fix URLs that resolve, else ``""``.

    Failures are swallowed: the diff only improves extraction, it is not required.
    """
    parts: list[str] = []
    for url in [u for u in urls if _GITHUB_FIX.match(u)][:_MAX_URLS]:
        try:
            resp = client.get(url.rstrip("/") + ".diff", follow_redirects=True)
            resp.raise_for_status()
        except httpx.HTTPError:
            continue
        parts.append(resp.text)
    return "\n".join(parts)[:MAX_DIFF_CHARS]
