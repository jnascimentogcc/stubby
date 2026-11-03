from pathlib import Path

from stubby.analyzers.javascript import JavaScriptAdapter, package_name_from_specifier
from stubby.lockfiles.npm import parse_package_lock
from stubby.models import Dependency, Verdict, Vulnerability
from stubby.osv import parse_vulnerability
from stubby.scan import scan_project
from stubby.vex import build_vex

FIXTURE = Path(__file__).parent / "fixtures" / "sample-js"


class FakeOSV:
    """Stands in for OSVClient so tests need no network."""

    def vulnerabilities_for(self, deps):
        vuln = Vulnerability(
            id="GHSA-xxxx-xxxx-xxxx",
            aliases=["CVE-2020-8203"],
            summary="Prototype pollution",
        )
        return {d: [vuln] for d in deps if d.name in {"lodash", "unused-lib", "nested"}}


def test_package_name_from_specifier():
    assert package_name_from_specifier("lodash/merge") == "lodash"
    assert package_name_from_specifier("@scope/pkg/sub") == "@scope/pkg"
    assert package_name_from_specifier("./local") is None
    assert package_name_from_specifier("node:fs") is None


def test_parse_package_lock_marks_direct_and_skips_links():
    name, version, deps = parse_package_lock(FIXTURE / "package-lock.json")
    assert (name, version) == ("sample-js", "1.0.0")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].direct
    assert by_name["@scope/pkg"].direct
    assert not by_name["nested"].direct
    assert "linked" not in by_name


def test_find_imports_ignores_node_modules_and_relative():
    imports = JavaScriptAdapter().find_imports(FIXTURE)
    assert set(imports) == {"lodash", "@scope/pkg"}
    assert len(imports["lodash"]) == 2
    assert imports["lodash"][0].file.endswith("index.ts")


def test_scan_never_concludes_not_affected_in_v01():
    result = scan_project(FIXTURE, osv=FakeOSV())
    assert {f.dependency.name for f in result.findings} == {"lodash", "unused-lib", "nested"}
    assert all(f.verdict is Verdict.INCONCLUSIVE for f in result.findings)
    notes = {f.dependency.name: f.notes for f in result.findings}
    assert "imported in 1 file" in notes["lodash"]
    assert "never imported" in notes["unused-lib"]
    assert "transitive" in notes["nested"]


def test_vex_document_shape():
    result = scan_project(FIXTURE, osv=FakeOSV())
    doc = build_vex(result)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    stmt = doc["statements"][0]
    assert stmt["vulnerability"]["name"] == "CVE-2020-8203"
    assert stmt["status"] == "under_investigation"
    assert stmt["products"][0]["subcomponents"][0]["@id"].startswith("pkg:npm/")


def test_purl_encodes_scoped_names():
    assert Dependency("npm", "@scope/pkg", "1.2.3").purl == "pkg:npm/%40scope/pkg@1.2.3"


def test_parse_vulnerability():
    v = parse_vulnerability(
        {"id": "GHSA-1", "aliases": ["CVE-1"], "references": [{"url": "https://x"}]}
    )
    assert v.display_id == "CVE-1"
    assert v.references == ["https://x"]
