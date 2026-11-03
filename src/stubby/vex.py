"""OpenVEX document writer (spec v0.2.0)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .models import Dependency, Finding, Verdict
from .scan import ScanResult

CONTEXT = "https://openvex.dev/ns/v0.2.0"

_STATUS = {
    Verdict.AFFECTED: "affected",
    Verdict.NOT_AFFECTED: "not_affected",
    Verdict.INCONCLUSIVE: "under_investigation",
}


def build_vex(result: ScanResult, author: str = "stubby", now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    product_purl = Dependency(
        result.ecosystem, result.project_name, result.project_version
    ).purl
    statements = [_statement(f, product_purl, now) for f in result.findings]

    digest = hashlib.sha256(
        json.dumps(statements, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "@context": CONTEXT,
        "@id": f"https://openvex.dev/docs/stubby/vex-{digest}",
        "author": author,
        "role": "Automated reachability analysis (draft, requires human review)",
        "timestamp": now.isoformat(timespec="seconds"),
        "version": 1,
        "tooling": "stubby",
        "statements": statements,
    }


def _statement(finding: Finding, product_purl: str, now: datetime) -> dict:
    vuln = finding.vulnerability
    stmt: dict = {
        "vulnerability": {
            "name": vuln.display_id,
            "aliases": sorted({vuln.id, *vuln.aliases} - {vuln.display_id}),
        },
        "products": [
            {
                "@id": product_purl,
                "subcomponents": [{"@id": finding.dependency.purl}],
            }
        ],
        "status": _STATUS[finding.verdict],
        "timestamp": now.isoformat(timespec="seconds"),
    }
    if not stmt["vulnerability"]["aliases"]:
        del stmt["vulnerability"]["aliases"]
    stmt["vulnerability"]["@id"] = vuln.url
    if vuln.description:
        stmt["vulnerability"]["description"] = vuln.description

    if finding.verdict is Verdict.AFFECTED:
        stmt["action_statement"] = "Upgrade the affected dependency to a fixed version."
    elif finding.verdict is Verdict.NOT_AFFECTED:
        stmt["justification"] = "vulnerable_code_not_in_execute_path"
        stmt["impact_statement"] = finding.notes
    if finding.notes and finding.verdict is not Verdict.NOT_AFFECTED:
        stmt["status_notes"] = finding.notes
    if finding.reasons:
        stmt["x-stubby-reasons"] = list(finding.reasons)  # extension field: why it stayed inconclusive
    return stmt
