"""Minimal client for the OSV.dev API."""

from __future__ import annotations

import time
from typing import Iterable

import httpx

from .models import Dependency, Vulnerability

OSV_BASE = "https://api.osv.dev/v1"
_BATCH_SIZE = 500
_RETRY_STATUS = {429, 500, 502, 503, 504}


class OSVClient:
    def __init__(
        self, client: httpx.Client | None = None, timeout: float = 30.0, retries: int = 3, backoff: float = 1.0
    ) -> None:
        self._retries = retries
        self._backoff = backoff
        self._client = client or httpx.Client(timeout=timeout)
        self._detail_cache: dict[str, Vulnerability] = {}

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Send a request, retrying transient failures (5xx, 429, network errors) with backoff."""
        for attempt in range(self._retries + 1):
            try:
                resp = self._client.request(method, url, **kwargs)
                if resp.status_code not in _RETRY_STATUS:
                    resp.raise_for_status()
                    return resp
                error: Exception = httpx.HTTPStatusError(
                    f"{resp.status_code} from {url}", request=resp.request, response=resp
                )
            except httpx.TransportError as exc:
                error = exc
            if attempt == self._retries:
                raise error
            time.sleep(self._backoff * 2**attempt)
        raise AssertionError("unreachable")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OSVClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def vulnerabilities_for(
        self, deps: Iterable[Dependency]
    ) -> dict[Dependency, list[Vulnerability]]:
        """Map each dependency to the vulnerabilities OSV reports for it."""
        dep_list = list(deps)
        ids_by_dep: dict[Dependency, list[str]] = {}
        for start in range(0, len(dep_list), _BATCH_SIZE):
            chunk = dep_list[start : start + _BATCH_SIZE]
            # OSV caps each result page; keep following page tokens for the
            # queries that report more vulnerabilities.
            pending = {i: None for i in range(len(chunk))}  # query index -> page token
            while pending:
                indexes = list(pending)
                queries = [_query(chunk[i], pending[i]) for i in indexes]
                resp = self._request("POST", f"{OSV_BASE}/querybatch", json={"queries": queries})
                results = resp.json().get("results", [])
                pending = {}
                for i, entry in zip(indexes, results):
                    ids = ids_by_dep.setdefault(chunk[i], [])
                    ids.extend(v["id"] for v in entry.get("vulns", []))
                    if entry.get("next_page_token"):
                        pending[i] = entry["next_page_token"]
        return {
            dep: [self.get_vulnerability(i) for i in dict.fromkeys(ids)]
            for dep, ids in ids_by_dep.items()
            if ids
        }

    def get_vulnerability(self, vuln_id: str) -> Vulnerability:
        cached = self._detail_cache.get(vuln_id)
        if cached is not None:
            return cached
        resp = self._request("GET", f"{OSV_BASE}/vulns/{vuln_id}")
        vuln = parse_vulnerability(resp.json())
        self._detail_cache[vuln_id] = vuln
        return vuln


def _query(dep: Dependency, page_token: str | None) -> dict:
    query: dict = {
        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
        "version": dep.version,
    }
    if page_token:
        query["page_token"] = page_token
    return query


def parse_vulnerability(data: dict) -> Vulnerability:
    return Vulnerability(
        id=data["id"],
        aliases=list(data.get("aliases", [])),
        summary=data.get("summary", ""),
        details=data.get("details", ""),
        references=[r["url"] for r in data.get("references", []) if "url" in r],
        fix_urls=[r["url"] for r in data.get("references", []) if r.get("type") == "FIX" and "url" in r],
    )
