from datetime import datetime, timezone

import pytest

from stubby.models import Dependency, Finding, Verdict, Vulnerability
from stubby.scan import ScanResult
from stubby.vex import build_vex

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
DEP = Dependency("npm", "lodash", "4.17.15", direct=True)
VULN = Vulnerability(id="GHSA-1", aliases=["CVE-2020-8203"])


def statement_for(verdict: Verdict, notes: str = "some notes") -> dict:
    result = ScanResult("app", "1.0.0", "npm", [Finding(DEP, VULN, verdict, notes)])
    return build_vex(result, now=NOW)["statements"][0]


def test_affected_statement_has_action():
    stmt = statement_for(Verdict.AFFECTED)
    assert stmt["status"] == "affected"
    assert "action_statement" in stmt
    assert stmt["status_notes"] == "some notes"


def test_not_affected_statement_has_justification_and_impact():
    stmt = statement_for(Verdict.NOT_AFFECTED, "never called")
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == "vulnerable_code_not_in_execute_path"
    assert stmt["impact_statement"] == "never called"
    assert "status_notes" not in stmt


def test_inconclusive_maps_to_under_investigation():
    stmt = statement_for(Verdict.INCONCLUSIVE)
    assert stmt["status"] == "under_investigation"
    assert "justification" not in stmt


def test_aliases_exclude_display_id_and_are_omitted_when_empty():
    stmt = statement_for(Verdict.INCONCLUSIVE)
    assert stmt["vulnerability"] == {
        "name": "CVE-2020-8203",
        "aliases": ["GHSA-1"],
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
    }

    bare = Finding(DEP, Vulnerability(id="GHSA-2"))
    doc = build_vex(ScanResult("app", "1.0.0", "npm", [bare]), now=NOW)
    assert doc["statements"][0]["vulnerability"] == {
        "name": "GHSA-2",
        "@id": "https://github.com/advisories/GHSA-2",
    }


def test_vulnerability_carries_the_advisory_title_and_a_bounded_description():
    titled = Finding(DEP, Vulnerability(id="GHSA-3", summary="Prototype pollution in lodash"))
    long = Finding(DEP, Vulnerability(id="PYSEC-1", details="word " * 200))
    doc = build_vex(ScanResult("app", "1.0.0", "npm", [titled, long]), now=NOW)
    assert doc["statements"][0]["vulnerability"]["description"] == "Prototype pollution in lodash"
    second = doc["statements"][1]["vulnerability"]
    assert second["@id"] == "https://osv.dev/vulnerability/PYSEC-1"
    assert len(second["description"]) <= 400 and second["description"].endswith("...")


def test_product_purl_encodes_scoped_project_name():
    doc = build_vex(ScanResult("@acme/app", "2.0.0", "npm", [Finding(DEP, VULN)]), now=NOW)
    assert doc["statements"][0]["products"][0]["@id"] == "pkg:npm/%40acme/app@2.0.0"


@pytest.mark.parametrize("author", ["stubby", "ACME Security"])
def test_author_is_configurable(author):
    doc = build_vex(ScanResult("app", "1.0.0", "npm", []), author=author, now=NOW)
    assert doc["author"] == author
    assert doc["statements"] == []
