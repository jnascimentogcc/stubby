import json

import httpx
import pytest

from stubby.fixes import fetch_fix_diff
from stubby.llm.base import LLMError
from stubby.llm.openai import OpenAIProvider
from stubby.models import Vulnerability
from stubby.osv import parse_vulnerability
from stubby.symbols import SymbolExtractor, validate

ADVISORY = "Prototype pollution in the `template` function allows code injection via options."


class StubProvider:
    name = "stub"

    def __init__(self, response):
        self.response = response
        self.calls = 0

    def complete_json(self, system, user, schema):
        self.calls += 1
        return self.response


def vuln(**kw) -> Vulnerability:
    return Vulnerability(id="GHSA-1", summary="Prototype pollution", details=ADVISORY, **kw)


def test_validate_keeps_only_quoted_symbols():
    raw = {
        "confidence": "high",
        "symbols": [
            {"name": "_.template", "module": "", "quote": "in the `template` function"},
            {"name": "merge", "module": "", "quote": "merge is vulnerable"},  # not in text
            {"name": "evil", "module": "", "quote": "in the `template` function"},  # not in quote
            {"name": "not an id", "module": "", "quote": "in the `template` function"},
        ],
    }
    result = validate(raw, ADVISORY)
    assert [s.name for s in result.symbols] == ["template"]
    assert result.rejected == 3
    assert result.confidence == "medium"  # dropped proposals cap the confidence


def test_validate_requires_the_symbol_as_a_whole_word():
    text = "Calling reset with crafted input is unsafe."
    raw = {"confidence": "high", "symbols": [{"name": "set", "module": "", "quote": "Calling reset with"}]}
    assert validate(raw, text).symbols == []


def test_validate_high_confidence_needs_clean_list():
    raw = {
        "confidence": "high",
        "symbols": [{"name": "template", "module": "lodash/template", "quote": "the `template` function"}],
    }
    result = validate(raw, ADVISORY)
    assert result.confidence == "high"
    assert result.symbols[0].module == "lodash/template"


def test_validate_empty_or_garbage_is_low():
    assert validate({"confidence": "high", "symbols": []}, ADVISORY).confidence == "low"
    assert validate({}, ADVISORY).usable is False


def test_extractor_caches_on_disk_and_in_memory(tmp_path):
    raw = {"confidence": "high", "symbols": [{"name": "template", "module": "", "quote": "`template` function"}]}
    provider = StubProvider(raw)
    first = SymbolExtractor(provider, use_fix_diff=False, cache_dir=tmp_path)
    assert first.extract(vuln()).symbols[0].name == "template"
    first.extract(vuln())
    assert provider.calls == 1

    second = SymbolExtractor(StubProvider({}), use_fix_diff=False, cache_dir=tmp_path)
    cached = second.extract(vuln())
    assert cached.symbols[0].name == "template" and cached.confidence == "high"
    assert second.provider.calls == 0


def test_extractor_sends_only_advisory_data():
    seen = {}

    class Spy(StubProvider):
        def complete_json(self, system, user, schema):
            seen["user"] = user
            return super().complete_json(system, user, schema)

    SymbolExtractor(Spy({"symbols": [], "confidence": "low"}), use_fix_diff=False).extract(vuln())
    assert ADVISORY in seen["user"] and "GHSA-1" in seen["user"]


def test_parse_vulnerability_collects_fix_urls():
    v = parse_vulnerability(
        {
            "id": "GHSA-1",
            "references": [
                {"type": "WEB", "url": "https://x"},
                {"type": "FIX", "url": "https://github.com/o/r/commit/abcdef1"},
            ],
        }
    )
    assert v.fix_urls == ["https://github.com/o/r/commit/abcdef1"]


def test_fetch_fix_diff_only_github_commits_and_swallows_errors():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        if "bad" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, text="diff --git a/x b/x\n+fix")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    urls = [
        "https://example.com/commit/abcdef1",  # not GitHub: never fetched
        "https://github.com/o/bad/commit/abcdef1",
        "https://github.com/o/r/commit/abcdef2",
    ]
    assert fetch_fix_diff(urls, client) == "diff --git a/x b/x\n+fix"
    assert requested == [
        "https://github.com/o/bad/commit/abcdef1.diff",
        "https://github.com/o/r/commit/abcdef2.diff",
    ]


def test_openai_provider_requires_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LLMError, match="OPENAI_API_KEY"):
        OpenAIProvider()


def test_openai_provider_parses_structured_output_and_hides_key():
    def handler(request):
        body = json.loads(request.content)
        assert body["response_format"]["json_schema"]["strict"] is True
        assert request.headers["authorization"] == "Bearer sk-test"
        if body["model"] == "boom":
            return httpx.Response(500)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"symbols": []}'}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ok = OpenAIProvider(api_key="sk-test", model="m", client=client)
    assert ok.complete_json("s", "u", {}) == {"symbols": []}

    bad = OpenAIProvider(api_key="sk-test", model="boom", client=client)
    with pytest.raises(LLMError) as info:
        bad.complete_json("s", "u", {})
    assert "sk-test" not in str(info.value) and "500" in str(info.value)
