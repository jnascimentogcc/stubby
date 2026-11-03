import json

import httpx

from stubby import cli
from stubby.models import Dependency, Finding, Vulnerability
from stubby.scan import ScanResult


def fake_result() -> ScanResult:
    finding = Finding(
        Dependency("npm", "lodash", "4.17.15", direct=True),
        Vulnerability(id="GHSA-1", aliases=["CVE-2020-8203"]),
        notes="imported in 1 file(s)",
    )
    return ScanResult("app", "1.0.0", "npm", [finding])


def test_scan_prints_findings_and_writes_vex(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "scan_project", lambda path, extractor=None, site_packages=None: fake_result())
    out = tmp_path / "vex.json"

    assert cli.main(["scan", str(tmp_path), "-o", str(out), "--author", "me"]) == 0

    stdout = capsys.readouterr().out
    assert "lodash@4.17.15  CVE-2020-8203  inconclusive" in stdout
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["author"] == "me"
    assert doc["statements"][0]["status"] == "under_investigation"


def test_scan_without_output_does_not_write_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "scan_project", lambda path, extractor=None, site_packages=None: fake_result())
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan"]) == 0
    assert list(tmp_path.iterdir()) == []


def test_unsupported_project_exits_with_2(monkeypatch, capsys):
    def boom(path, extractor=None, site_packages=None):
        raise ValueError("No supported project found")

    monkeypatch.setattr(cli, "scan_project", boom)
    assert cli.main(["scan", "."]) == 2
    assert "No supported project found" in capsys.readouterr().err


def test_osv_network_failure_exits_with_3(monkeypatch, capsys):
    def boom(path, extractor=None, site_packages=None):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(cli, "scan_project", boom)
    assert cli.main(["scan", "."]) == 3
    assert "could not reach OSV.dev" in capsys.readouterr().err
