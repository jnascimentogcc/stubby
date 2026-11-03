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
    monkeypatch.setattr(cli, "scan_project", lambda path, extractor=None, site_packages=None, repository=None, progress=None: fake_result())
    out = tmp_path / "vex.json"

    assert cli.main(["scan", str(tmp_path), "-o", str(out), "--author", "me"]) == 0

    stdout = capsys.readouterr().out
    assert "lodash@4.17.15  CVE-2020-8203  inconclusive" in stdout
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["author"] == "me"
    assert doc["statements"][0]["status"] == "under_investigation"


def test_scan_without_output_does_not_write_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "scan_project", lambda path, extractor=None, site_packages=None, repository=None, progress=None: fake_result())
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan"]) == 0
    assert list(tmp_path.iterdir()) == []


def test_unsupported_project_exits_with_2(monkeypatch, capsys):
    def boom(path, extractor=None, site_packages=None, repository=None, progress=None):
        raise ValueError("No supported project found")

    monkeypatch.setattr(cli, "scan_project", boom)
    assert cli.main(["scan", "."]) == 2
    assert "No supported project found" in capsys.readouterr().err


def test_osv_network_failure_exits_with_3(monkeypatch, capsys):
    def boom(path, extractor=None, site_packages=None, repository=None, progress=None):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(cli, "scan_project", boom)
    assert cli.main(["scan", "."]) == 3
    assert "could not reach OSV.dev" in capsys.readouterr().err


def test_progress_reports_stages_and_can_be_silenced(capsys):
    from stubby.cli import _progress

    assert _progress(True) is None
    report = _progress(False)
    report("Querying OSV.dev", False)
    report("[1/2] pkg@1 CVE-1", True)  # per-item updates are only shown on a terminal
    err = capsys.readouterr().err
    assert "... Querying OSV.dev" in err


def test_report_command_writes_standalone_html(tmp_path, capsys):
    import json

    vex = {
        "timestamp": "t",
        "role": "r",
        "statements": [
            {
                "vulnerability": {"name": "CVE-1", "@id": "https://nvd.nist.gov/vuln/detail/CVE-1", "description": "</script><b>x"},
                "products": [{"@id": "pkg:npm/app@1", "subcomponents": [{"@id": "pkg:npm/lodash@4"}]}],
                "status": "under_investigation",
            }
        ],
    }
    src = tmp_path / "vex.json"
    src.write_text(json.dumps(vex))
    assert cli.main(["report", str(src)]) == 0
    html = (tmp_path / "vex.html").read_text(encoding="utf-8")
    assert "nvd.nist.gov/vuln/detail/CVE-1" in html
    assert "</script><b>" not in html  # advisory text cannot close the data script

    (tmp_path / "bad.json").write_text("[]")
    assert cli.main(["report", str(tmp_path / "bad.json")]) == 2


def test_help_documents_every_option(capsys):
    import pytest

    parser = cli.build_parser()
    for command in ("scan", "report", "bench"):
        with pytest.raises(SystemExit) as exit_:
            parser.parse_args([command, "--help"])
        assert exit_.value.code == 0
        text = capsys.readouterr().out
        for action in parser._subparsers._group_actions[0].choices[command]._actions:
            for flag in action.option_strings:
                assert flag in text
        assert "exit status" in text
    for flag in ("--llm", "--repository", "--site-packages", "--cache-dir", "--no-fix-diff", "--quiet"):
        assert flag in parser._subparsers._group_actions[0].choices["scan"].format_help()
