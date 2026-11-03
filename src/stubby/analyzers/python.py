"""Python adapter: poetry.lock or pinned requirements.txt, tree-sitter import analysis.

Imports name modules, not distributions (``import yaml`` is PyYAML), so modules
are mapped to distributions through an installed environment's ``RECORD`` files
when one is available (a ``.venv``, ``venv`` or ``env`` in the project, or
``--site-packages``). Without it only name-based guesses exist, and any import
that cannot be attributed is reported as unresolved, which blocks ``not_affected``.
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph, GraphNode
from ..lockfiles.python import (
    ECOSYSTEM,
    parse_poetry_lock,
    parse_requirements,
    read_pyproject,
    requirement_is_direct,
)
from ..models import Dependency, Evidence
from ..pyenv import PythonEnvironment, find_site_packages, normalize
from .base import UsageReport, remember_unattributed
from .py_ast import analyze_source

SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env", ".tox", ".nox", "node_modules", "build",
    "dist", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".eggs",
}
MAX_FILE_BYTES = 2_000_000

# Import name -> distribution, for names that differ (used only without an installed environment).
ALIASES = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn", "skimage": "scikit-image", "dateutil": "python-dateutil",
    "jwt": "pyjwt", "OpenSSL": "pyopenssl", "attr": "attrs", "Crypto": "pycryptodome",
    "serial": "pyserial", "MySQLdb": "mysqlclient", "git": "gitpython", "docx": "python-docx",
    "dotenv": "python-dotenv", "magic": "python-magic", "psycopg2": "psycopg2-binary",
}

_FALLBACK_IMPORTS = (
    re.compile(r"^\s*import\s+([A-Za-z_][\w]*)", re.MULTILINE),
    re.compile(r"^\s*from\s+([A-Za-z_][\w]*)[\w.]*\s+import\b", re.MULTILINE),
)


@dataclass
class _State:
    name: str
    version: str
    deps: list[Dependency]
    graph: DependencyGraph | None
    env: PythonEnvironment | None
    warnings: list[str] = field(default_factory=list)

    @property
    def known(self) -> set[str]:
        return {d.name for d in self.deps}


class PythonAdapter:
    ecosystem = ECOSYSTEM

    def __init__(self, site_packages: Path | None = None) -> None:
        self.site_packages = site_packages
        self._cache: dict[Path, _State] = {}

    def configured(self, site_packages: Path | None = None, repository: Path | None = None) -> "PythonAdapter":
        return PythonAdapter(site_packages) if site_packages else self

    def detect(self, project_dir: Path) -> bool:
        return (
            (project_dir / "poetry.lock").is_file()
            or (project_dir / "requirements.txt").is_file()
            or bool(read_pyproject(project_dir).pinned)
        )

    # -- lockfiles ---------------------------------------------------------

    def _state(self, project_dir: Path) -> _State:
        key = project_dir.resolve()
        if key not in self._cache:
            state = self._build_state(key)
            if state.env is not None:
                missing = [d.name for d in state.deps if d.name not in state.env.dists]
                if missing:
                    state.warnings.append(
                        f"{len(missing)} of {len(state.deps)} dependencies are not installed in "
                        f"{state.env.site_packages} (e.g. {', '.join(missing[:3])}): their modules "
                        "cannot be mapped, so imports stay unresolved and nothing is ruled out; "
                        "install the project's dependencies into that environment and scan again"
                    )
            self._cache[key] = state
        return self._cache[key]

    def _build_state(self, project_dir: Path) -> _State:
        pyproject = read_pyproject(project_dir)
        name = pyproject.name or project_dir.name
        version = pyproject.version or "0.0.0"

        site = self.site_packages or find_site_packages(project_dir)
        env = PythonEnvironment.load(site) if site and site.is_dir() else None
        warnings: list[str] = []
        if env is None:
            warnings.append(
                "no installed Python environment found (.venv, venv or env in the project, or "
                "--site-packages): import names and dependent packages could not be inspected, "
                "so nothing can be ruled out"
            )

        lock = project_dir / "poetry.lock"
        if lock.is_file():
            deps, graph = parse_poetry_lock(lock, pyproject.direct)
            return _State(name, version, deps, graph, env, warnings)

        if not (project_dir / "requirements.txt").is_file():
            return self._pyproject_state(name, version, pyproject, env, warnings)

        reqs = parse_requirements(project_dir / "requirements.txt")
        warnings += reqs.warnings
        deps_by_key: dict[tuple[str, str], Dependency] = {}
        for req in reqs.pinned:
            dep = Dependency(ECOSYSTEM, req.name, req.version, direct=requirement_is_direct(req))
            old = deps_by_key.get((dep.name, dep.version))
            deps_by_key[(dep.name, dep.version)] = dep if old is None or dep.direct else old
        deps = sorted(deps_by_key.values(), key=lambda d: (d.name, d.version))

        graph = None
        if env is not None:  # a requirements file lists no edges; the installed metadata does
            graph = DependencyGraph()
            for dep in deps:
                graph.nodes[dep.name] = GraphNode(dep.name, dep.name, dep.version)
            for dep_name, node in graph.nodes.items():
                dist = env.dists.get(dep_name)
                graph.edges[dep_name] = sorted(
                    {r for r in (dist.requires if dist else []) if r in graph.nodes and r != dep_name}
                )
            graph.root = sorted(d.name for d in deps if d.direct)
        return _State(name, version, deps, graph, env, warnings)

    def _pyproject_state(self, name, version, pyproject, env, warnings) -> _State:
        """Pinned ``pyproject.toml`` dependencies; transitive ones come from the installed environment."""
        warnings.append(
            "no lockfile: dependencies are the `==` pins in pyproject.toml"
            + ("" if env else " (without an installed environment transitive dependencies are unknown)")
        )
        versions = dict(pyproject.pinned)
        if env is not None:
            queue = list(versions)
            while queue:
                current = queue.pop()
                dist = env.dists.get(current)
                for req in dist.requires if dist else []:
                    if req not in versions and req in env.dists:
                        versions[req] = env.dists[req].version
                        queue.append(req)
        deps = [
            Dependency(ECOSYSTEM, n, v, direct=n in pyproject.pinned) for n, v in sorted(versions.items())
        ]
        graph = None
        if env is not None:
            edges = {
                d.name: sorted(
                    {r for r in (env.dists[d.name].requires if d.name in env.dists else []) if r in versions and r != d.name}
                )
                for d in deps
            }
            shipped, queue = set(), [n for n in pyproject.pinned if n not in pyproject.dev]
            while queue:
                current = queue.pop()
                if current not in shipped:
                    shipped.add(current)
                    queue += edges.get(current, [])
            graph = DependencyGraph()
            for dep in deps:
                graph.nodes[dep.name] = GraphNode(dep.name, dep.name, dep.version, dev=dep.name not in shipped)
            graph.edges = edges
            graph.root = sorted(d.name for d in deps if d.direct)
        return _State(name, version, deps, graph, env, warnings)

    def load_dependencies(self, project_dir: Path) -> tuple[str, str, list[Dependency]]:
        state = self._state(project_dir)
        return state.name, state.version, state.deps

    def dependency_graph(self, project_dir: Path) -> DependencyGraph | None:
        return self._state(project_dir).graph

    def warnings(self, project_dir: Path) -> list[str]:
        return list(self._state(project_dir).warnings)

    # -- source analysis ---------------------------------------------------

    def analyze(self, project_dir: Path) -> UsageReport:
        project_dir = project_dir.resolve()
        files = list(_iter_python_files(project_dir))
        return self._analyze_files(project_dir, files, _local_modules(project_dir), project_dir)

    def analyze_package(self, project_dir: Path, location: str) -> UsageReport:
        project_dir = project_dir.resolve()
        env = self._state(project_dir).env
        dist = env.dists.get(location) if env else None
        if dist is None:
            return UsageReport(incomplete=True)
        files = [p for p in dist.python_files() if p.is_file()]
        report = self._analyze_files(project_dir, files, dist.modules, env.site_packages)
        report.incomplete = report.incomplete or len(files) < len(dist.python_files())
        return report

    def is_installed(self, project_dir: Path, location: str) -> bool:
        env = self._state(project_dir).env
        return env is not None and location in env.dists

    def _analyze_files(
        self, project_dir: Path, files: list[Path], local: set[str], base: Path
    ) -> UsageReport:
        state = self._state(project_dir)
        by_package: dict[str, set[Evidence]] = defaultdict(set)
        dynamic: set[Evidence] = set()
        unattributed: dict[str, list[Evidence]] = {}
        incomplete = False

        for path in files:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    incomplete = True
                    continue
                source = path.read_bytes()
            except OSError:
                incomplete = True
                continue
            rel = _display_path(path, project_dir, base)
            text = source.decode("utf-8", errors="replace")
            lines = text.splitlines()

            def snippet(lineno: int) -> str:
                return lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""

            analysis = analyze_source(source)
            observations = [(o.package, o.line, o.kind, o.symbol, o.module) for o in analysis.observations]
            if analysis.has_syntax_errors:  # e.g. Python 2 code: never lose an import
                seen = {(p, line) for p, line, *_ in observations}
                for pattern in _FALLBACK_IMPORTS:
                    for match in pattern.finditer(text):
                        line = text.count("\n", 0, match.start(1)) + 1
                        if (match.group(1), line) not in seen:
                            observations.append((match.group(1), line, "import", None, match.group(1)))

            for top, line, kind, symbol, module in observations:
                if kind == "maybe":
                    remember_unattributed(unattributed, Evidence(rel, line, snippet(line), "maybe", symbol))
                    continue
                if top is None:
                    dynamic.add(Evidence(rel, line, snippet(line), "dynamic", symbol))
                    continue
                dists = _resolve(top, local, state)
                if dists is None:
                    dynamic.add(Evidence(rel, line, snippet(line), "dynamic", f"unresolved module {top}"))
                    continue
                if kind == "ref" and symbol == "*" and state.env is not None and not state.env.is_module(module or top):
                    continue  # a class or function passed around, not a module
                for dist in dists:
                    by_package[dist].add(Evidence(rel, line, snippet(line), kind, symbol, module))

        return UsageReport(
            by_package={d: _ordered(evs) for d, evs in by_package.items()},
            dynamic=_ordered(dynamic),
            unattributed=unattributed,
            incomplete=incomplete,
        )


def _resolve(top: str, local: set[str], state: _State) -> list[str] | None:
    """Distributions providing module ``top``; ``[]`` to ignore it, ``None`` if unattributable."""
    if top in sys.stdlib_module_names or top in local:
        return []
    if state.env is not None:
        dists = state.env.dists_for_module(top)
        if dists:
            return sorted(dists)
    known = state.known
    if normalize(top) in known:
        return [normalize(top)]
    alias = ALIASES.get(top)
    if alias and alias in known:
        return [alias]
    return None


def _ordered(evidence) -> list[Evidence]:
    return sorted(evidence, key=lambda e: (e.file, e.line, e.kind, e.symbol or ""))


def _display_path(path: Path, project_dir: Path, base: Path) -> str:
    try:
        return path.relative_to(project_dir).as_posix()
    except ValueError:
        return "site-packages/" + path.relative_to(base).as_posix()


def _iter_python_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d / "pyvenv.cfg").is_file()
        ]
        for name in filenames:
            if name.endswith(".py"):
                yield Path(dirpath) / name


def _local_modules(project_dir: Path) -> set[str]:
    """Top-level names the project itself provides (``pkg/``, ``mod.py``, ``src/pkg/``)."""
    names: set[str] = set()
    for base in (project_dir, project_dir / "src"):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            if entry.is_dir() and entry.name.isidentifier():
                names.add(entry.name)
            elif entry.suffix == ".py" and entry.stem.isidentifier():
                names.add(entry.stem)
    return names
