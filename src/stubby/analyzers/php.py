"""PHP adapter: ``composer.lock`` and the installed ``vendor/`` directory.

Source code names classes by namespace, so a class is mapped to its Composer
package through the PSR-4/PSR-0 prefixes in ``composer.lock`` and the class map
in ``vendor/composer``. A namespaced class that no package provides and the
project does not define is reported as unresolved code, which blocks
``not_affected``. Packages are inspected from ``vendor/``; without it only the
mapping from the lockfile exists and nothing about dependents can be ruled out.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph
from ..lockfiles.php import ECOSYSTEM, ComposerLock, ComposerProject, parse_composer_lock, read_composer_json
from ..models import Dependency, Evidence
from ..phpvendor import MAX_FILES, PhpVendor
from ..reach import NameGraph
from .base import UsageReport, remember_unattributed
from .php_ast import analyze_source
from .php_reach import build_graph

SKIP_DIRS = {".git", "vendor", "node_modules", "storage", "cache", ".idea", ".vscode"}
MAX_FILE_BYTES = 2_000_000


@dataclass
class _State:
    name: str
    version: str
    project: ComposerProject
    lock: ComposerLock
    vendor: PhpVendor
    warnings: list[str] = field(default_factory=list)
    graphs: dict[str, NameGraph] = field(default_factory=dict)


class PhpAdapter:
    ecosystem = ECOSYSTEM

    def __init__(self) -> None:
        self._cache: dict[Path, _State] = {}

    def detect(self, project_dir: Path) -> bool:
        return (project_dir / "composer.lock").is_file()

    # -- lockfile ----------------------------------------------------------

    def _state(self, project_dir: Path) -> _State:
        key = project_dir.resolve()
        if key not in self._cache:
            project = read_composer_json(key)
            lock = parse_composer_lock(key / "composer.lock", project)
            vendor = PhpVendor.load(key, lock)
            state = _State(project.name or key.name, project.version or "0.0.0", project, lock, vendor)
            if not (key / "vendor").is_dir():
                state.warnings.append(
                    "no vendor/ directory: run `composer install` so the dependencies' code can be "
                    "inspected; without it nothing about the packages that depend on a vulnerable one is known"
                )
            else:
                missing = sorted(set(lock.graph.nodes) - vendor.packages)
                if missing:
                    state.warnings.append(
                        f"{len(missing)} of {len(lock.graph.nodes)} locked packages are not in vendor/ "
                        f"(e.g. {', '.join(missing[:3])}): their code cannot be inspected"
                    )
            if not project.present:
                state.warnings.append("no composer.json: direct dependencies were guessed from the lockfile")
            self._cache[key] = state
        return self._cache[key]

    def load_dependencies(self, project_dir: Path) -> tuple[str, str, list[Dependency]]:
        state = self._state(project_dir)
        return state.name, state.version, state.lock.deps

    def dependency_graph(self, project_dir: Path) -> DependencyGraph | None:
        return self._state(project_dir).lock.graph

    def warnings(self, project_dir: Path) -> list[str]:
        return list(self._state(project_dir).warnings)

    def is_installed(self, project_dir: Path, location: str) -> bool:
        return location in self._state(project_dir).vendor.packages

    # -- source analysis ---------------------------------------------------

    def analyze(self, project_dir: Path) -> UsageReport:
        project_dir = project_dir.resolve()
        state = self._state(project_dir)
        files = list(_iter_php_files(project_dir))
        roots = {ns.split("\\", 1)[0].lower() for ns in state.project.namespaces}
        return self._analyze_files(state, files, project_dir, roots, own=None)

    def analyze_package(self, project_dir: Path, location: str) -> UsageReport:
        project_dir = project_dir.resolve()
        state = self._state(project_dir)
        if location not in state.vendor.packages:
            return UsageReport(incomplete=True)
        files = state.vendor.files_of(location)
        roots = {p.split("\\", 1)[0] for p in state.vendor.own_prefixes(location) if "\\" in p}
        report = self._analyze_files(state, files, project_dir, roots, own=location)
        report.incomplete = report.incomplete or len(files) >= MAX_FILES
        return report

    def package_graph(self, project_dir: Path, location: str) -> NameGraph | None:
        """Name graph of the installed package ``location`` (None when it is not in vendor/)."""
        state = self._state(project_dir.resolve())
        if location not in state.vendor.packages:
            return None
        if location not in state.graphs:
            state.graphs[location] = build_graph(state.vendor.files_of(location))
        return state.graphs[location]

    def _analyze_files(
        self, state: _State, files: list[Path], project_dir: Path, local_roots: set[str], own: str | None
    ) -> UsageReport:
        by_package: dict[str, set[Evidence]] = defaultdict(set)
        dynamic: set[Evidence] = set()
        unattributed: dict[str, list[Evidence]] = {}
        incomplete = False
        parsed = []

        for path in files:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    incomplete = True
                    continue
                source = path.read_bytes()
            except OSError:
                incomplete = True
                continue
            analysis = analyze_source(source)
            parsed.append((path, source, analysis))
            local_roots = local_roots | {ns.split("\\", 1)[0].lower() for ns in analysis.namespaces}

        for path, source, analysis in parsed:
            rel = _display_path(path, project_dir)
            lines = source.decode("utf-8", errors="replace").splitlines()

            def snippet(lineno: int) -> str:
                return lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""

            for obs in analysis.observations:
                line = obs.line
                if obs.kind == "maybe":
                    remember_unattributed(unattributed, Evidence(rel, line, snippet(line), "maybe", obs.symbol))
                elif obs.package is None:
                    dynamic.add(Evidence(rel, line, snippet(line), "dynamic", obs.symbol))
                else:
                    packages = _resolve(obs.package, state, local_roots, own)
                    if packages is None:
                        dynamic.add(Evidence(rel, line, snippet(line), "dynamic", f"unresolved class {obs.package}"))
                    for package in packages or []:
                        by_package[package].add(Evidence(rel, line, snippet(line), obs.kind, obs.symbol, obs.module))

        return UsageReport(
            by_package={p: _ordered(e) for p, e in by_package.items()},
            dynamic=_ordered(dynamic),
            unattributed=unattributed,
            incomplete=incomplete,
        )


def _resolve(fqn: str, state: _State, local_roots: set[str], own: str | None) -> list[str] | None:
    """Packages providing ``fqn``; ``[]`` to ignore it (own code, PHP itself), ``None`` if unattributable."""
    package = state.vendor.package_of(fqn)
    if package is not None:
        return [] if package == own else [package]
    if "\\" not in fqn:
        return []  # a global class or function: PHP itself or an extension
    if fqn.split("\\", 1)[0].lower() in local_roots:
        return []
    return None


def _ordered(evidence) -> list[Evidence]:
    return sorted(evidence, key=lambda e: (e.file, e.line, e.kind, e.symbol or ""))


def _display_path(path: Path, project_dir: Path) -> str:
    try:
        return path.relative_to(project_dir).as_posix()
    except ValueError:
        return path.as_posix()


def _iter_php_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".php"):
                yield Path(dirpath) / name
