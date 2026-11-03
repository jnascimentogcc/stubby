import json
import shutil
from pathlib import Path

import pytest

from stubby import cli
from stubby.bench import compute_metrics, format_report, load_cases, run_case, run_cases
from stubby.models import Verdict

CASES_DIR = Path(__file__).parent.parent / "benchmarks" / "cases"
CASES = load_cases(CASES_DIR)


def test_benchmark_has_cases_for_every_verdict():
    assert len(CASES) >= 15
    assert {c.expected for c in CASES} == set(Verdict)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_case_is_never_a_false_not_affected(case):
    assert not run_case(case).unsafe


@pytest.mark.parametrize("case", [c for c in CASES if not c.known_gap], ids=lambda c: c.id)
def test_case_matches_expected_verdict(case):
    result = run_case(case)
    assert result.actual is case.expected, result.notes


@pytest.mark.parametrize("case", [c for c in CASES if c.known_gap], ids=lambda c: c.id)
def test_known_gaps_are_still_gaps(case):
    # When a gap gets fixed this fails, which is the cue to drop its `known_gap`.
    assert run_case(case).actual is not case.expected


def test_metrics_for_the_suite():
    metrics = compute_metrics(run_cases(CASES))
    assert metrics.unsafe == 0
    assert metrics.precision[Verdict.NOT_AFFECTED] == 1.0
    assert metrics.precision[Verdict.AFFECTED] == 1.0


def test_report_lists_cases_and_headline_numbers():
    report = format_report(run_cases(CASES))
    assert "lodash-template-named-import" in report
    assert "False not_affected (release blocker): 0" in report
    assert "known gap:" in report


def copy_cases(tmp_path: Path, case_id: str, expected: str) -> Path:
    dest = tmp_path / case_id
    shutil.copytree(CASES_DIR / case_id, dest)
    meta_path = dest / "case.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["expected"] = expected
    meta.pop("known_gap", None)
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    return tmp_path


def test_unsafe_outcome_is_detected_and_fails_the_command(tmp_path, capsys):
    # The project does not use `template`, so the tool says not_affected;
    # a case that claims it is affected makes that a false not_affected.
    root = copy_cases(tmp_path, "lodash-template-other-member", "affected")
    [result] = run_cases(load_cases(root))
    assert result.unsafe

    assert cli.main(["bench", str(root)]) == 1
    assert "UNSAFE" in capsys.readouterr().out


def test_bench_command_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["bench"]) == 2  # default path has no cases here
    assert cli.main(["bench", str(CASES_DIR)]) == 0  # known gaps do not fail by default
    assert cli.main(["bench", str(CASES_DIR), "--strict"]) == 1
    assert cli.main(["bench", str(tmp_path)]) == 2  # no cases
    capsys.readouterr()
