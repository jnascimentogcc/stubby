"""JS/TS/Node adapter.

Source files are analysed with tree-sitter (``js_ast``). A file that does not
parse cleanly also goes through a regex scan, so a syntax error can hide an
import from the report but never make it look unused.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path

from ..graph import DependencyGraph
from ..lockfiles.npm import parse_package_lock, parse_package_lock_graph
from ..models import Dependency, Evidence
from .base import UsageReport, remember_unattributed
from .js_ast import analyze_source, package_name_from_specifier

__all__ = ["JavaScriptAdapter", "package_name_from_specifier"]

SOURCE_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "out"}
# Published packages ship their code in dist/build/lib, so only nested installs are skipped.
PACKAGE_SKIP_DIRS = {"node_modules", ".git"}
MAX_FILE_BYTES = 2_000_000

# Fallback for files tree-sitter reports syntax errors in.
# import x from 'pkg' | import 'pkg' | export ... from 'pkg'
_IMPORT_FROM = re.compile(r"""\b(?:import|export)\b[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]""")
_IMPORT_BARE = re.compile(r"""\bimport\s*['"]([^'"]+)['"]""")
# require('pkg') | import('pkg')
_CALL = re.compile(r"""\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_PATTERNS = (_IMPORT_FROM, _IMPORT_BARE, _CALL)


class JavaScriptAdapter:
    ecosystem = "npm"

    def detect(self, project_dir: Path) -> bool:
        return (project_dir / "package-lock.json").is_file()

    def load_dependencies(self, project_dir: Path) -> tuple[str, str, list[Dependency]]:
        return parse_package_lock(project_dir / "package-lock.json")

    def dependency_graph(self, project_dir: Path) -> DependencyGraph | None:
        return parse_package_lock_graph(project_dir / "package-lock.json")

    def analyze(self, project_dir: Path) -> UsageReport:
        return _analyze_tree(project_dir, project_dir, SKIP_DIRS)

    def analyze_package(self, project_dir: Path, location: str) -> UsageReport:
        return _analyze_tree(project_dir, project_dir / location, PACKAGE_SKIP_DIRS)

    def configured(self, **_options) -> "JavaScriptAdapter":
        return self

    def is_installed(self, project_dir: Path, location: str) -> bool:
        return (project_dir / location).is_dir()

    def warnings(self, project_dir: Path) -> list[str]:
        return []

    def find_imports(self, project_dir: Path) -> dict[str, list[Evidence]]:
        """Import evidence only, keyed by package name."""
        report = self.analyze(project_dir)
        imports = {
            pkg: [e for e in evs if e.kind in ("import", "escape")] for pkg, evs in report.by_package.items()
        }
        return {pkg: evs for pkg, evs in imports.items() if evs}


def _analyze_tree(project_dir: Path, root: Path, skip_dirs: set[str]) -> UsageReport:
    """Analyse every source file under ``root``; evidence paths are relative to ``project_dir``."""
    by_package: dict[str, set[Evidence]] = defaultdict(set)
    dynamic: set[Evidence] = set()
    unattributed: dict[str, list[Evidence]] = {}
    incomplete = False
    for path in _iter_source_files(root, skip_dirs):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                incomplete = True
                continue
            source = path.read_bytes()
        except OSError:
            incomplete = True
            continue
        rel = str(path.relative_to(project_dir)).replace(os.sep, "/")
        lines = source.decode("utf-8", errors="replace").splitlines()

        def snippet(lineno: int) -> str:
            return lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""

        analysis = analyze_source(source, path.suffix)
        for obs in analysis.observations:
            ev = Evidence(rel, obs.line, snippet(obs.line), obs.kind, obs.symbol, obs.module)
            if obs.kind == "maybe":
                remember_unattributed(unattributed, ev)
            elif obs.package is None:
                dynamic.add(ev)
            else:
                by_package[obs.package].add(ev)

        if analysis.has_syntax_errors:
            text = source.decode("utf-8", errors="replace")
            known = {(p, e.line) for p, evs in by_package.items() for e in evs if e.file == rel}
            for pkg, lineno, spec in _regex_imports(text):
                if (pkg, lineno) not in known:
                    by_package[pkg].add(Evidence(rel, lineno, snippet(lineno), "import", None, spec))

    return UsageReport(
        by_package={pkg: _ordered(evs) for pkg, evs in by_package.items()},
        dynamic=_ordered(dynamic),
        unattributed=unattributed,
        incomplete=incomplete,
    )


def _ordered(evidence) -> list[Evidence]:
    return sorted(evidence, key=lambda e: (e.file, e.line, e.kind, e.symbol or ""))


def _regex_imports(text: str):
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            pkg = package_name_from_specifier(match.group(1))
            if pkg:
                yield pkg, text.count("\n", 0, match.start(1)) + 1, match.group(1)


def _iter_source_files(root: Path, skip_dirs: set[str] = SKIP_DIRS):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if Path(name).suffix in SOURCE_EXTENSIONS and not name.endswith(".d.ts"):
                yield Path(dirpath) / name
