import json

import httpx

from stubby.models import Dependency
from stubby.osv import OSVClient

LODASH = Dependency("npm", "lodash", "4.17.15", direct=True)
EXPRESS = Dependency("npm", "express", "4.0.0", direct=True)


def make_client(handler) -> OSVClient:
    return OSVClient(client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_querybatch_follows_page_tokens_and_dedupes():
    batches = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            batches.append(queries)
            if len(batches) == 1:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"vulns": [{"id": "GHSA-1"}], "next_page_token": "tok"},
                            {},
                        ]
                    },
                )
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]})
        vuln_id = request.url.path.rsplit("/", 1)[1]
        return httpx.Response(200, json={"id": vuln_id})

    with make_client(handler) as osv:
        result = osv.vulnerabilities_for([LODASH, EXPRESS])

    assert len(batches) == 2
    assert batches[1] == [
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15", "page_token": "tok"}
    ]
    assert list(result) == [LODASH]
    assert [v.id for v in result[LODASH]] == ["GHSA-1", "GHSA-2"]


def test_vulnerability_details_are_cached():
    detail_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}]}] * 2})
        detail_calls.append(request.url.path)
        return httpx.Response(200, json={"id": "GHSA-1", "aliases": ["CVE-1"]})

    with make_client(handler) as osv:
        result = osv.vulnerabilities_for([LODASH, EXPRESS])

    assert len(detail_calls) == 1
    assert result[LODASH][0].display_id == "CVE-1"
