"""Benchmark runner: known advisories, small projects, expected verdicts.

A case is a directory holding ``case.json`` and a ``project/`` folder (see
``benchmarks/README.md``). Cases run offline by default: the advisory is read
from ``case.json`` and the LLM answer is replayed from ``llm_response``.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .llm.base import LLMProvider
from .models import Dependency, Verdict, Vulnerability
from .osv import parse_vulnerability
from .scan import scan_project
from .symbols import SymbolExtractor

VERDICTS = [Verdict.AFFECTED, Verdict.NOT_AFFECTED, Verdict.INCONCLUSIVE]


@dataclass
class Case:
    id: str
    description: str
    directory: Path
    package: str
    vulnerability: Vulnerability
    expected: Verdict
    llm_response: dict | None
    known_gap: str | None = None

    @property
    def project(self) -> Path:
        return self.directory / "project"


@dataclass
class CaseResult:
    case: Case
    actual: Verdict
    notes: str

    @property
    def passed(self) -> bool:
        return self.actual is self.case.expected

    @property
    def unsafe(self) -> bool:
        """A false ``not_affected``: the one outcome that must never happen."""
        return self.actual is Verdict.NOT_AFFECTED and self.case.expected is not Verdict.NOT_AFFECTED


class RecordedProvider:
    """Replays the model answer stored in a case, so runs are offline and stable."""

    name = "recorded"

    def __init__(self, response: dict) -> None:
        self.response = response

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        return self.response


class _StaticOSV:
    def __init__(self, package: str, vuln: Vulnerability) -> None:
        self.package, self.vuln = package, vuln

    def vulnerabilities_for(self, deps):
        return {d: [self.vuln] for d in deps if d.name == self.package}


def load_cases(root: Path) -> list[Case]:
    cases = []
    for meta_path in sorted(root.glob("*/case.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        cases.append(
            Case(
                id=meta_path.parent.name,
                description=meta["description"],
                directory=meta_path.parent,
                package=meta["package"],
                vulnerability=parse_vulnerability(meta["vulnerability"]),
                expected=Verdict(meta["expected"]),
                llm_response=meta.get("llm_response"),
                known_gap=meta.get("known_gap"),
            )
        )
    return cases


def run_case(case: Case, provider: LLMProvider | None = None) -> CaseResult:
    """Run one case. ``provider`` overrides the recorded answer (live mode)."""
    if provider is None and case.llm_response is not None:
        provider = RecordedProvider(case.llm_response)
    extractor = SymbolExtractor(provider, use_fix_diff=False) if provider else None
    result = scan_project(case.project, osv=_StaticOSV(case.package, case.vulnerability), extractor=extractor)
    findings = [f for f in result.findings if f.vulnerability.id == case.vulnerability.id]
    if not findings:
        raise ValueError(f"{case.id}: package {case.package!r} not found in the lockfile")
    finding = findings[0]
    return CaseResult(case, finding.verdict, finding.notes)


def run_cases(cases: list[Case], provider: LLMProvider | None = None) -> list[CaseResult]:
    return [run_case(c, provider) for c in cases]


@dataclass
class Metrics:
    total: int
    correct: int
    unsafe: int
    precision: dict[Verdict, float | None]
    recall: dict[Verdict, float | None]
    matrix: Counter  # (expected, actual) -> count


def compute_metrics(results: list[CaseResult]) -> Metrics:
    matrix: Counter = Counter((r.case.expected, r.actual) for r in results)

    def ratio(num: int, den: int) -> float | None:
        return num / den if den else None

    precision, recall = {}, {}
    for v in VERDICTS:
        tp = matrix[(v, v)]
        predicted = sum(matrix[(e, v)] for e in VERDICTS)
        expected = sum(matrix[(v, a)] for a in VERDICTS)
        precision[v], recall[v] = ratio(tp, predicted), ratio(tp, expected)
    return Metrics(
        total=len(results),
        correct=sum(r.passed for r in results),
        unsafe=sum(r.unsafe for r in results),
        precision=precision,
        recall=recall,
        matrix=matrix,
    )


def _pct(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.0%}"


def format_report(results: list[CaseResult]) -> str:
    m = compute_metrics(results)
    width = max((len(r.case.id) for r in results), default=10)
    lines = []
    for r in results:
        mark = "UNSAFE" if r.unsafe else ("ok" if r.passed else ("gap" if r.case.known_gap else "MISS"))
        lines.append(
            f"{mark:<6}  {r.case.id:<{width}}  expected {r.case.expected.value:<12} got {r.actual.value}"
        )
        if not r.passed and r.case.known_gap:
            lines.append(f"{'':<8}known gap: {r.case.known_gap}")
    lines += ["", f"{m.correct}/{m.total} cases match the expected verdict."]
    lines.append(f"False not_affected (release blocker): {m.unsafe}")
    lines += ["", f"{'verdict':<14}precision  recall"]
    for v in VERDICTS:
        lines.append(f"{v.value:<14}{_pct(m.precision[v]):<11}{_pct(m.recall[v])}")
    return "\n".join(lines)
