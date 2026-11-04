"""Scan orchestration."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .analyzers.base import LanguageAdapter
from .analyzers.java import JavaAdapter
from .analyzers.javascript import JavaScriptAdapter
from .analyzers.php import PhpAdapter
from .analyzers.python import PythonAdapter
from .graph import DependencyGraph, GraphNode
from .llm.base import LLMError
from .reach import NameGraph
from .models import Dependency, Evidence, Finding, Verdict, Vulnerability
from .osv import OSVClient
from .symbols import SymbolExtractor, VulnerableSymbols

ADAPTERS: list[LanguageAdapter] = [JavaScriptAdapter(), PythonAdapter(), JavaAdapter(), PhpAdapter()]

# Names accepted by `--ecosystem`, and the OSV ecosystem each adapter reports.
ECOSYSTEMS = {"npm": "npm", "python": "PyPI", "java": "Maven", "php": "Packagist"}

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
    unattributed: dict[str, list[Evidence]] = field(default_factory=dict)
    incomplete: bool = False


def scan_project(
    project_dir: Path,
    osv: OSVClient | None = None,
    extractor: SymbolExtractor | None = None,
    site_packages: Path | None = None,
    repository: Path | None = None,
    progress: Callable[[str, bool], None] | None = None,
    ecosystem: str | None = None,
) -> ScanResult:
    """``progress(message, transient)`` reports what is running; transient messages are per-item.

    ``ecosystem`` (a key of ``ECOSYSTEMS``) picks the adapter instead of the first one that matches.
    """
    note = progress or (lambda message, transient=False: None)
    project_dir = project_dir.resolve()
    if ecosystem is not None:
        wanted = ECOSYSTEMS.get(ecosystem.lower())
        if wanted is None:
            raise ValueError(f"Unknown ecosystem {ecosystem!r} (choose from {', '.join(ECOSYSTEMS)}).")
        adapter = next((a for a in ADAPTERS if a.ecosystem == wanted), None)
        if adapter is None or not adapter.detect(project_dir):
            raise ValueError(f"No {ecosystem} project found in {project_dir}: its lockfile is missing.")
    else:
        adapter = next((a for a in ADAPTERS if a.detect(project_dir)), None)
    if adapter is None:
        raise ValueError(
            f"No supported project found in {project_dir} (supports npm projects with a "
            "package-lock.json, Python projects with a poetry.lock or pinned requirements.txt, and "
            "Java projects with a pom.xml or gradle.lockfile, and PHP projects with a composer.lock)."
        )
    if hasattr(adapter, "configured"):
        adapter = adapter.configured(site_packages=site_packages, repository=repository)

    note(f"Reading {adapter.ecosystem} dependencies", False)
    name, version, deps = adapter.load_dependencies(project_dir)
    note(f"Analysing source code ({len(deps)} dependencies)", False)
    usage = adapter.analyze(project_dir)
    graph = adapter.dependency_graph(project_dir)
    package_reports: dict[str, object] = {}  # install location -> UsageReport, analysed once

    owns_client = osv is None
    osv = osv or OSVClient()
    note("Querying OSV.dev for known vulnerabilities", False)
    try:
        vulns_by_dep = osv.vulnerabilities_for(deps)
    finally:
        if owns_client:
            osv.close()

    findings: list[Finding] = []
    total = sum(len(v) for v in vulns_by_dep.values())
    note(f"Assessing {total} finding(s)" + (" (asking the LLM for vulnerable symbols)" if extractor else ""), False)
    for dep, vulns in vulns_by_dep.items():
        evidence = usage.by_package.get(dep.name, [])
        instances = graph.instances(dep.name, dep.version) if graph else []
        chain = _chain(graph, instances) if not dep.direct else []
        for vuln in vulns:
            note(f"[{len(findings) + 1}/{total}] {dep.name}@{dep.version} {vuln.display_id}", True)
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
            graphs = None  # None: this ecosystem cannot look inside installed packages
            package_graph = getattr(adapter, "package_graph", None)
            if package_graph is not None and symbols is not None and symbols.usable:
                graphs = [g for g in (package_graph(project_dir, n.key) for n in instances) if g is not None]
            findings.append(
                _assess(
                    dep,
                    vuln,
                    evidence,
                    usage.dynamic,
                    symbols,
                    error,
                    unattributed=usage.unattributed,
                    incomplete=usage.incomplete,
                    dependents=dependents,
                    dependents_known=graph is not None,
                    chain=chain,
                    dev_only=bool(instances) and all(n.dev for n in instances),
                    graphs=graphs,
                )
            )
    note("Assessment complete", False)
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
                report.unattributed,
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


def _entries(evidence: list[Evidence]) -> set[str] | None:
    """Names the code uses from a package; ``None`` when it uses the whole module."""
    names: set[str] = set()
    for ev in evidence:
        if ev.kind == "dynamic":
            continue
        if ev.kind == "import" and ev.symbol in (None, "*"):
            continue  # `import yaml` only loads the module; what is used from it is its own evidence
        if ev.symbol in _OPAQUE_SYMBOLS:
            return None
        names.add(ev.symbol)
    return names


def _reach_blockers(
    symbols: VulnerableSymbols, entries: set[str] | None, graphs: list[NameGraph]
) -> list[tuple[str, str]]:
    if entries is None:
        return []  # whole-module use is already a blocker of its own
    if not graphs:
        return [("package-not-installed", "the package's installed code is not available, so what its members reach could not be checked")]
    names = sorted({s.name.rsplit(".", 1)[-1] for s in symbols.symbols})  # `ImageMath.eval` -> `eval`
    found: list[tuple[str, str]] = []
    for graph in graphs:
        if not graph.trusted():
            found.append(("package-unanalysable", "the package's code uses eval or could not be fully parsed, so what its members reach is unknown"))
            continue
        missing = [n for n in names if n not in graph.defined]
        if missing:
            found.append(("symbol-not-found", f"{', '.join(missing)} not found in the installed code, so reachability could not be verified"))
        reached = graph.reachable(entries)
        if graph.uses_dynamic_code(reached):
            found.append(("package-unanalysable", "code the members used can run calls eval or exec, so what it reaches is unknown"))
        hit = [n for n in names if n in reached and n in graph.defined]
        if hit:
            used = ", ".join(sorted(entries)[:4]) or "load-time code"
            found.append(("internal-reach", f"the package's {used} may reach {', '.join(hit)} internally"))
    return list(dict.fromkeys(found))


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


def _same_name_calls(
    symbols: VulnerableSymbols, unattributed: dict[str, list[Evidence]], where: str
) -> list[str]:
    """Calls of a method named like a vulnerable symbol on receivers we could not type."""
    found = []
    for name in sorted({sym.name for sym in symbols.symbols}):
        examples = unattributed.get(name)
        if examples:
            first = examples[0]
            found.append(
                f"{where} calls a method named {name}() on a receiver of unknown type "
                f"({first.file}:{first.line}); it may be the vulnerable one"
            )
    return found


# Why a finding stayed inconclusive; the codes are written to the VEX and shown in the report.
REASONS = {
    "symbol-unknown": "No vulnerable function identified (scan without --llm, or the advisory names none)",
    "llm-error": "Symbol extraction failed",
    "low-confidence": "The vulnerable-symbol list is not confident enough to rule the package out",
    "not-imported": "Direct dependency never imported (candidate, needs review)",
    "transitive-unanalysed": "Transitive dependency; the packages that require it were not analysed",
    "imported-unused": "A vulnerable symbol is imported but no call was found",
    "whole-module-use": "The whole module is used, hiding which member is called",
    "dynamic-code": "Dynamic code could reach the package",
    "same-name-call": "A method named like a vulnerable one is called on an untyped receiver",
    "incomplete-analysis": "The project could not be fully analysed",
    "dependents-unknown": "The lockfile does not say which packages require it",
    "dependent-not-installed": "A dependent package is not installed, so its code was not inspected",
    "dependent-incomplete": "A dependent package could not be fully analysed",
    "dependent-uses-symbol": "A dependent package uses a vulnerable symbol (needs call-graph analysis)",
    "internal-reach": "The members used may reach a vulnerable function inside the package",
    "symbol-not-found": "The vulnerable function is not in the installed code, so reachability could not be verified",
    "package-not-installed": "The package's installed code is not available to check what its members reach",
    "package-unanalysable": "The package's code could not be analysed (eval or unparsable files)",
    "dependent-whole-module": "A dependent package uses the whole module",
    "dependent-dynamic": "A dependent package loads modules dynamically",
}


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
    unattributed: dict[str, list[Evidence]] | None = None,
    incomplete: bool = False,
    graphs: list[NameGraph] | None = None,
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

    reasons: list[str] = []
    if not dep.direct:
        via = f" via {' > '.join(chain)}" if chain else ""
        notes = f"transitive dependency{via}"
        if not dependents:
            notes += "; reachability through the packages that require it was not analysed"
            reasons.append("transitive-unanalysed")
    elif imports:
        files = len({e.file for e in imports})
        notes = f"imported in {files} file(s)"
        used = sorted({e.symbol for e in imports + calls if e.symbol and e.symbol != "*"})
        if used:
            notes += f"; members used: {', '.join(used[:8])}" + (", ..." if len(used) > 8 else "")
        notes += f"; {len(calls)} call site(s)"
    else:
        notes = "direct dependency never imported in source (candidate for not_affected; needs review)"
        reasons.append("not-imported")
    if dev_only:
        notes += "; only required by devDependencies (not part of the shipped runtime)"

    if not dep.direct and not dependents and not llm_error and (symbols is None or not symbols.usable):
        reasons.append("symbol-unknown")  # nothing to look for in the packages that require it

    verdict = Verdict.INCONCLUSIVE
    shown = evidence
    analysable = (dep.direct and imports) or (not dep.direct and (dependents or llm_error))
    if analysable:
        if llm_error:
            notes += f"; symbol extraction failed ({llm_error})"
            reasons.append("llm-error")
        elif symbols is None or not symbols.usable:
            notes += "; vulnerable symbol not identified"
            reasons.append("symbol-unknown")
        else:
            names = ", ".join(sorted({s.name for s in symbols.symbols}))
            notes += f"; advisory names vulnerable symbol(s): {names} (confidence {symbols.confidence})"
            verdict, shown, notes = _decide(
                dep, symbols, evidence, dynamic, dependents, dependents_known, notes, unattributed or {}, incomplete, reasons, graphs
            )
    if dynamic and verdict is not Verdict.AFFECTED:
        if "dynamic-code" not in reasons:
            reasons.append("dynamic-code")
        notes += (
            f"; {len(dynamic)} dynamic or unresolved import/eval site(s) in the project "
            "could reach it, so absence of usage is not conclusive"
        )
    return Finding(
        dep, vuln, verdict, notes, shown, reasons if verdict is Verdict.INCONCLUSIVE else [], dev_only
    )


def _decide(
    dep: Dependency,
    symbols: VulnerableSymbols,
    evidence: list[Evidence],
    dynamic: list[Evidence],
    dependents: list[DependentUsage],
    dependents_known: bool,
    notes: str,
    unattributed: dict[str, list[Evidence]],
    incomplete: bool = False,
    reasons: list[str] | None = None,
    graphs: list[NameGraph] | None = None,
) -> tuple[Verdict, list[Evidence], str]:
    project = _classify(evidence, symbols, dep.name) if dep.direct else _Usage([], [], [])
    if project.hits:
        return Verdict.AFFECTED, project.hits, notes + f"; vulnerable symbol used at {len(project.hits)} site(s)"

    blockers: list[str] = []
    cited: list[Evidence] = []
    reasons = reasons if reasons is not None else []

    def block(code: str, text: str) -> None:
        blockers.append(text)
        if code not in reasons:
            reasons.append(code)

    if project.imported_only:
        block("imported-unused", "vulnerable symbol imported but no call found")
    if project.opaque:
        block("whole-module-use", f"{len(project.opaque)} use(s) of the whole module hide which member is called")
    if dynamic:
        block("dynamic-code", "dynamic code in the project")
    for text in _same_name_calls(symbols, unattributed, "the project"):
        block("same-name-call", text)
    if incomplete:
        block("incomplete-analysis", "the project could not be fully analysed (unreadable or oversized files, or unmapped dependencies)")

    if not dependents_known:
        block("dependents-unknown", "lockfile does not say which packages require it (v1 lockfile)")
    for d in dependents:
        label = f"{d.node.name}@{d.node.version}"
        if not d.installed:
            block("dependent-not-installed", f"dependent {label} is not installed, so its code was not inspected (run npm install)")
            continue
        if d.incomplete:
            block("dependent-incomplete", f"dependent {label} could not be fully analysed")
        usage = _classify(d.evidence, symbols, dep.name)
        if usage.hits or usage.imported_only:
            sites = usage.hits + usage.imported_only
            cited += sites
            block(
                "dependent-uses-symbol",
                f"dependent {label} uses a vulnerable symbol ({sites[0].file}:{sites[0].line}); "
                "whether the project reaches it needs call-graph analysis"
            )
        if usage.opaque:
            block("dependent-whole-module", f"dependent {label} uses the whole module, hiding which member is called")
        if d.dynamic:
            block("dependent-dynamic", f"dependent {label} loads modules dynamically")
        for text in _same_name_calls(symbols, d.unattributed, f"dependent {label}"):
            block("same-name-call", text)
        cited += d.evidence

    if graphs is not None:
        # The members used may reach a vulnerable symbol that is never named in the code.
        users = [("the project", evidence)] if dep.direct else []
        users += [(f"dependent {d.node.name}@{d.node.version}", d.evidence) for d in dependents if d.installed]
        for where, used in users:
            if not used:
                continue
            for code, text in _reach_blockers(symbols, _entries(used), graphs):
                block(code, f"{where}: {text}")

    if blockers:
        return Verdict.INCONCLUSIVE, evidence + cited, notes + "; " + "; ".join(blockers)
    if symbols.confidence != "high":
        reasons.append("low-confidence")
        return Verdict.INCONCLUSIVE, evidence, notes + "; symbol list not confident enough to rule the package out"
    if dep.direct:
        extra = f"; none of them is used by the project or its {len(dependents)} dependent package(s)" if dependents else "; none of them is used by the project"
        return Verdict.NOT_AFFECTED, _imports(evidence) + [e for e in evidence if e.kind == "call"] + cited, notes + extra
    return (
        Verdict.NOT_AFFECTED,
        cited,
        notes + f"; none of the {len(dependents)} package(s) that require it uses a vulnerable symbol",
    )
