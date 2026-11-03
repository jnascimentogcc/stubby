"""Scan orchestration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .analyzers.base import LanguageAdapter
from .analyzers.javascript import JavaScriptAdapter
from .analyzers.python import PythonAdapter
from .graph import DependencyGraph, GraphNode
from .llm.base import LLMError
from .models import Dependency, Evidence, Finding, Verdict, Vulnerability
from .osv import OSVClient
from .symbols import SymbolExtractor, VulnerableSymbols

ADAPTERS: list[LanguageAdapter] = [JavaScriptAdapter(), PythonAdapter()]

# Uses of a package binding whose member cannot be told apart from the vulnerable one.
_OPAQUE_SYMBOLS = {None, "*", "default"}


@dataclass
class ScanResult:
    project_name: str
    project_version: str
    ecosystem: str
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)


@dataclass
class DependentUsage:
    """How one installed package that requires the vulnerable package uses it."""

    node: GraphNode
    installed: bool
    evidence: list[Evidence] = field(default_factory=list)
    dynamic: list[Evidence] = field(default_factory=list)
    incomplete: bool = False


def scan_project(
    project_dir: Path,
    osv: OSVClient | None = None,
    extractor: SymbolExtractor | None = None,
    site_packages: Path | None = None,
) -> ScanResult:
    project_dir = project_dir.resolve()
    adapter = next((a for a in ADAPTERS if a.detect(project_dir)), None)
    if adapter is None:
        raise ValueError(
            f"No supported project found in {project_dir} (supports npm projects with a "
            "package-lock.json and Python projects with a poetry.lock or pinned requirements.txt)."
        )
    if site_packages is not None and hasattr(adapter, "with_environment"):
        adapter = adapter.with_environment(site_packages)

    name, version, deps = adapter.load_dependencies(project_dir)
    usage = adapter.analyze(project_dir)
    graph = adapter.dependency_graph(project_dir)
    package_reports: dict[str, object] = {}  # install location -> UsageReport, analysed once

    owns_client = osv is None
    osv = osv or OSVClient()
    try:
        vulns_by_dep = osv.vulnerabilities_for(deps)
    finally:
        if owns_client:
            osv.close()

    findings: list[Finding] = []
    for dep, vulns in vulns_by_dep.items():
        evidence = usage.by_package.get(dep.name, [])
        instances = graph.instances(dep.name, dep.version) if graph else []
        chain = _chain(graph, instances) if not dep.direct else []
        for vuln in vulns:
            symbols, error, dependents = None, None, None
            # The LLM is only consulted where it can change the outcome: a package
            # the project imports, or one that installed dependents may use.
            if extractor is not None and (
                (dep.direct and _imports(evidence)) or (not dep.direct and instances)
            ):
                try:
                    symbols = extractor.extract(vuln)
                except (LLMError, httpx.HTTPError) as exc:
                    error = str(exc) or type(exc).__name__
            if symbols is not None and symbols.usable and graph is not None:
                dependents = _collect_dependents(
                    graph, instances, dep, project_dir, adapter, package_reports
                )
            findings.append(
                _assess(
                    dep,
                    vuln,
                    evidence,
                    usage.dynamic,
                    symbols,
                    error,
                    dependents=dependents,
                    dependents_known=graph is not None,
                    chain=chain,
                    dev_only=bool(instances) and all(n.dev for n in instances),
                )
            )
    findings.sort(key=lambda f: (f.dependency.name, f.vulnerability.id))
    return ScanResult(name, version, adapter.ecosystem, findings, adapter.warnings(project_dir))


def _chain(graph: DependencyGraph | None, instances: list[GraphNode]) -> list[str]:
    paths = [p for p in (graph.shortest_path(n.key) for n in instances) if p] if graph else []
    return [n.name for n in min(paths, key=len)] if paths else []


def _collect_dependents(
    graph: DependencyGraph,
    instances: list[GraphNode],
    dep: Dependency,
    project_dir: Path,
    adapter: LanguageAdapter,
    reports: dict,
) -> list[DependentUsage]:
    found: dict[str, DependentUsage] = {}
    for instance in instances:
        for parent in graph.dependents(instance.key):
            if parent.key in found:
                continue
            installed = adapter.is_installed(project_dir, parent.key)
            if not installed:
                found[parent.key] = DependentUsage(parent, False)
                continue
            if parent.key not in reports:
                reports[parent.key] = adapter.analyze_package(project_dir, parent.key)
            report = reports[parent.key]
            found[parent.key] = DependentUsage(
                parent,
                True,
                report.by_package.get(dep.name, []),
                report.dynamic,
                report.incomplete,
            )
    return list(found.values())


def _imports(evidence: list[Evidence]) -> list[Evidence]:
    return [e for e in evidence if e.kind in ("import", "escape")]


def _hits_symbol(ev: Evidence, symbols: VulnerableSymbols, package: str) -> bool:
    """True if ``ev`` uses (or loads the sub-module of) a vulnerable symbol."""
    # Loading a module named after the vulnerable function (`lodash/template`) counts; loading the
    # module that merely *contains* it (`django.utils.html`) does not, its members are tracked instead.
    module_leaf = re.split(r"[/.]", ev.module)[-1] if ev.module and ev.module != package else None
    return any(ev.symbol == sym.name or module_leaf == sym.name for sym in symbols.symbols)


@dataclass
class _Usage:
    hits: list[Evidence]  # call or reference to a vulnerable symbol
    imported_only: list[Evidence]  # vulnerable symbol imported, never called
    opaque: list[Evidence]  # whole-module use that hides which member is called

    @property
    def clear(self) -> bool:
        return not (self.hits or self.imported_only or self.opaque)


def _classify(evidence: list[Evidence], symbols: VulnerableSymbols, package: str) -> _Usage:
    return _Usage(
        hits=[e for e in evidence if e.kind in ("call", "ref") and _hits_symbol(e, symbols, package)],
        imported_only=[
            e for e in _imports(evidence) if _hits_symbol(e, symbols, package) and e.kind == "import"
        ],
        opaque=[e for e in evidence if e.kind in ("call", "ref", "escape") and e.symbol in _OPAQUE_SYMBOLS],
    )


def _assess(
    dep: Dependency,
    vuln: Vulnerability,
    evidence: list[Evidence],
    dynamic: list[Evidence] | None = None,
    symbols: VulnerableSymbols | None = None,
    llm_error: str | None = None,
    dependents: list[DependentUsage] | None = None,
    dependents_known: bool = True,
    chain: list[str] | None = None,
    dev_only: bool = False,
) -> Finding:
    """Assess how the project reaches a vulnerable dependency.

    Without validated vulnerable symbols every finding stays ``inconclusive``.
    ``affected`` needs the project itself to use a vulnerable symbol.
    ``not_affected`` needs all of: high-confidence validated symbols; no use of a
    vulnerable symbol, no whole-module use and no dynamic code in the project
    *and in every installed package that requires this one*; and either a
    direct dependency the project imports or a transitive one whose dependents
    were all inspected. ``dependents`` is ``None`` when they were not inspected.
    """
    dynamic = dynamic or []
    dependents = dependents or []
    imports = _imports(evidence)
    calls = [e for e in evidence if e.kind == "call"]

    if not dep.direct:
        via = f" via {' > '.join(chain)}" if chain else ""
        notes = f"transitive dependency{via}"
        if not dependents:
            notes += "; reachability through the packages that require it was not analysed"
    elif imports:
        files = len({e.file for e in imports})
        notes = f"imported in {files} file(s)"
        used = sorted({e.symbol for e in imports + calls if e.symbol and e.symbol != "*"})
        if used:
            notes += f"; members used: {', '.join(used[:8])}" + (", ..." if len(used) > 8 else "")
        notes += f"; {len(calls)} call site(s)"
    else:
        notes = "direct dependency never imported in source (candidate for not_affected; needs review)"
    if dev_only:
        notes += "; only required by devDependencies (not part of the shipped runtime)"

    verdict = Verdict.INCONCLUSIVE
    shown = evidence
    analysable = (dep.direct and imports) or (not dep.direct and (dependents or llm_error))
    if analysable:
        if llm_error:
            notes += f"; symbol extraction failed ({llm_error})"
        elif symbols is None or not symbols.usable:
            notes += "; vulnerable symbol not identified"
        else:
            names = ", ".join(sorted({s.name for s in symbols.symbols}))
            notes += f"; advisory names vulnerable symbol(s): {names} (confidence {symbols.confidence})"
            verdict, shown, notes = _decide(
                dep, symbols, evidence, dynamic, dependents, dependents_known, notes
            )
    if dynamic and verdict is not Verdict.AFFECTED:
        notes += (
            f"; {len(dynamic)} dynamic or unresolved import/eval site(s) in the project "
            "could reach it, so absence of usage is not conclusive"
        )
    return Finding(dep, vuln, verdict, notes, shown)


def _decide(
    dep: Dependency,
    symbols: VulnerableSymbols,
    evidence: list[Evidence],
    dynamic: list[Evidence],
    dependents: list[DependentUsage],
    dependents_known: bool,
    notes: str,
) -> tuple[Verdict, list[Evidence], str]:
    project = _classify(evidence, symbols, dep.name) if dep.direct else _Usage([], [], [])
    if project.hits:
        return Verdict.AFFECTED, project.hits, notes + f"; vulnerable symbol used at {len(project.hits)} site(s)"

    blockers: list[str] = []
    cited: list[Evidence] = []
    if project.imported_only:
        blockers.append("vulnerable symbol imported but no call found")
    if project.opaque:
        blockers.append(f"{len(project.opaque)} use(s) of the whole module hide which member is called")
    if dynamic:
        blockers.append("dynamic code in the project")

    if not dependents_known:
        blockers.append("lockfile does not say which packages require it (v1 lockfile)")
    for d in dependents:
        label = f"{d.node.name}@{d.node.version}"
        if not d.installed:
            blockers.append(f"dependent {label} is not installed, so its code was not inspected (run npm install)")
            continue
        if d.incomplete:
            blockers.append(f"dependent {label} could not be fully analysed")
        usage = _classify(d.evidence, symbols, dep.name)
        if usage.hits or usage.imported_only:
            sites = usage.hits + usage.imported_only
            cited += sites
            blockers.append(
                f"dependent {label} uses a vulnerable symbol ({sites[0].file}:{sites[0].line}); "
                "whether the project reaches it needs call-graph analysis"
            )
        if usage.opaque:
            blockers.append(f"dependent {label} uses the whole module, hiding which member is called")
        if d.dynamic:
            blockers.append(f"dependent {label} loads modules dynamically")
        cited += d.evidence

    if blockers:
        return Verdict.INCONCLUSIVE, evidence + cited, notes + "; " + "; ".join(blockers)
    if symbols.confidence != "high":
        return Verdict.INCONCLUSIVE, evidence, notes + "; symbol list not confident enough to rule the package out"
    if dep.direct:
        extra = f"; none of them is used by the project or its {len(dependents)} dependent package(s)" if dependents else "; none of them is used by the project"
        return Verdict.NOT_AFFECTED, _imports(evidence) + [e for e in evidence if e.kind == "call"] + cited, notes + extra
    return (
        Verdict.NOT_AFFECTED,
        cited,
        notes + f"; none of the {len(dependents)} package(s) that require it uses a vulnerable symbol",
    )
