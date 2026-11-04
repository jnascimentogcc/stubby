"""Java adapter: Maven (``pom.xml`` + optional dependency tree) and Gradle (``gradle.lockfile``).

Source imports name classes, not artifacts, so classes are mapped to artifacts
through the jars Maven or Gradle downloaded (``~/.m2``, the Gradle cache, a
``.m2/repository`` in the project or ``--repository``). The same jars give the
bytecode of dependents, read from the constant pool of their ``.class`` files.
Without jars only a groupId-prefix guess exists, any class that cannot be
attributed is reported as unresolved, and nothing can be ruled out.
"""

from __future__ import annotations

import itertools
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph
from ..jars import (
    JDK_PREFIXES,
    REFLECTION,
    JarInfo,
    candidate_repositories,
    dotted,
    locate_jar,
    read_class,
    read_jar_classes,
    read_jar_references,
)
from ..lockfiles.java import ECOSYSTEM, TREE_FILES, parse_gradle_lockfile, parse_maven_tree, parse_pom
from ..models import Dependency, Evidence
from .base import UsageReport, remember_unattributed
from ..reach import NameGraph
from .java_ast import analyze_source
from .java_reach import build_graph

SKIP_DIRS = {"target", "build", ".gradle", ".git", "out", "node_modules", ".idea", ".mvn", "bin"}
MAX_FILE_BYTES = 2_000_000
_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_IMPORT_FALLBACK = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;", re.MULTILINE)


@dataclass
class _State:
    name: str
    version: str
    deps: list[Dependency]
    graph: DependencyGraph | None
    repositories: list[Path]
    warnings: list[str] = field(default_factory=list)
    _jars: dict[str, JarInfo | None] = field(default_factory=dict)
    _by_class: dict[str, set[str]] | None = None
    _by_package: dict[str, set[str]] | None = None
    graphs: dict[str, NameGraph] = field(default_factory=dict)

    def jar(self, key: str) -> JarInfo | None:
        """The jar of dependency ``key`` (``group:artifact``), with its class list."""
        if key not in self._jars:
            dep = next((d for d in self.deps if d.name == key), None)
            path = None
            if dep is not None:
                group, artifact = dep.name.split(":", 1)
                path = locate_jar(self.repositories, group, artifact, dep.version)
            self._jars[key] = read_jar_classes(path) if path else None
        return self._jars[key]

    def _build_index(self) -> None:
        self._by_class, self._by_package = defaultdict(set), defaultdict(set)
        for dep in self.deps:
            info = self.jar(dep.name)
            if info is None:
                continue
            for cls in info.classes:
                self._by_class[cls].add(dep.name)
            for pkg in info.packages:
                self._by_package[pkg].add(dep.name)

    @property
    def by_class(self) -> dict[str, set[str]]:
        if self._by_class is None:
            self._build_index()
        return self._by_class  # type: ignore[return-value]

    @property
    def by_package(self) -> dict[str, set[str]]:
        if self._by_package is None:
            self._build_index()
        return self._by_package  # type: ignore[return-value]

    @property
    def any_jar(self) -> bool:
        return any(self.jar(d.name) is not None for d in self.deps)


class JavaAdapter:
    ecosystem = ECOSYSTEM

    def __init__(self, repository: Path | None = None) -> None:
        self.repository = repository
        self._cache: dict[Path, _State] = {}

    def configured(self, site_packages: Path | None = None, repository: Path | None = None) -> "JavaAdapter":
        return JavaAdapter(repository) if repository else self

    def detect(self, project_dir: Path) -> bool:
        return (project_dir / "pom.xml").is_file() or (project_dir / "gradle.lockfile").is_file()

    # -- dependencies ------------------------------------------------------

    def _state(self, project_dir: Path) -> _State:
        key = project_dir.resolve()
        if key not in self._cache:
            self._cache[key] = self._build_state(key)
        return self._cache[key]

    def _build_state(self, project_dir: Path) -> _State:
        warnings: list[str] = []
        name, version = project_dir.name, "0.0.0"
        pom_path = project_dir / "pom.xml"
        pom = parse_pom(pom_path) if pom_path.is_file() else None
        if pom and pom.artifact:
            name = f"{pom.group}:{pom.artifact}" if pom.group else pom.artifact
            version = pom.version or version

        graph = None
        tree = next((project_dir / t for t in TREE_FILES if (project_dir / t).is_file()), None)
        gradle = project_dir / "gradle.lockfile"
        if tree is not None:
            parsed = parse_maven_tree(tree)
            deps, graph = parsed.deps, parsed.graph
            if pom is None and parsed.root:
                name, version = f"{parsed.root[0]}:{parsed.root[1]}", parsed.root[2]
        elif pom is not None:
            deps = [Dependency(ECOSYSTEM, f"{g}:{a}", v, direct=True) for g, a, v, _ in pom.deps]
            warnings += pom.warnings
            warnings.append(
                "pom.xml lists direct dependencies only; run "
                "`mvn dependency:tree -DoutputFile=dependency-tree.txt` to include transitive ones"
            )
        else:
            build = "".join(
                p.read_text(encoding="utf-8", errors="replace")
                for p in (project_dir / "build.gradle", project_dir / "build.gradle.kts")
                if p.is_file()
            )
            deps = parse_gradle_lockfile(gradle, build)

        repositories = candidate_repositories(project_dir, self.repository)
        state = _State(name, version, deps, graph, repositories, warnings)
        if deps and not state.any_jar:
            warnings.append(
                "no downloaded jars found (~/.m2, the Gradle cache, .m2/repository in the project or "
                "--repository): classes cannot be mapped to artifacts and dependents cannot be "
                "inspected, so nothing can be ruled out"
            )
        if any(True for _ in _iter_files(project_dir, ".kt")):
            warnings.append("Kotlin sources are not analysed")
        return state

    def load_dependencies(self, project_dir: Path) -> tuple[str, str, list[Dependency]]:
        state = self._state(project_dir)
        return state.name, state.version, state.deps

    def dependency_graph(self, project_dir: Path) -> DependencyGraph | None:
        return self._state(project_dir).graph

    def warnings(self, project_dir: Path) -> list[str]:
        return list(self._state(project_dir).warnings)

    def is_installed(self, project_dir: Path, location: str) -> bool:
        return self._state(project_dir).jar(location) is not None

    # -- analysis ----------------------------------------------------------

    def analyze(self, project_dir: Path) -> UsageReport:
        project_dir = project_dir.resolve()
        state = self._state(project_dir)
        by_package: dict[str, set[Evidence]] = defaultdict(set)
        dynamic: set[Evidence] = set()
        unattributed: dict[str, list[Evidence]] = {}
        incomplete = False

        sources: list[tuple[Path, bytes]] = []
        local_packages: set[str] = set()
        for path in _iter_files(project_dir, ".java"):
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    incomplete = True
                    continue
                data = path.read_bytes()
            except OSError:
                incomplete = True
                continue
            sources.append((path, data))
            local_packages.update(_PACKAGE.findall(data.decode("utf-8", errors="replace")))

        for path, data in sources:
            rel = path.relative_to(project_dir).as_posix()
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()

            def snippet(lineno: int) -> str:
                return lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""

            analysis = analyze_source(data)
            observations = [(o.package, o.line, o.kind, o.symbol, o.module) for o in analysis.observations]
            if analysis.has_syntax_errors:
                seen = {(p, line) for p, line, *_ in observations}
                for match in _IMPORT_FALLBACK.finditer(text):
                    line = text.count("\n", 0, match.start(1)) + 1
                    if (match.group(1), line) not in seen:
                        observations.append((match.group(1), line, "import", None, match.group(1)))

            for fqn, line, kind, symbol, module in observations:
                ev = Evidence(rel, line, snippet(line), kind, symbol, module)
                if kind == "maybe":
                    remember_unattributed(unattributed, ev)
                elif fqn is None:
                    dynamic.add(ev)
                else:
                    artifacts = _resolve(fqn, state, local_packages)
                    if artifacts is None:
                        dynamic.add(Evidence(rel, line, snippet(line), "dynamic", f"unresolved class {fqn}"))
                    for artifact in artifacts or []:
                        by_package[artifact].add(ev)

        # A dependency without a jar cannot be told apart from its neighbours by class name.
        incomplete = incomplete or any(state.jar(d.name) is None for d in state.deps)
        return UsageReport(
            by_package={a: _ordered(e) for a, e in by_package.items()},
            dynamic=_ordered(dynamic),
            unattributed=unattributed,
            incomplete=incomplete,
        )

    def package_graph(self, project_dir: Path, location: str) -> NameGraph | None:
        """Name graph of the jar of ``location`` (None when it was not downloaded)."""
        state = self._state(project_dir.resolve())
        info = state.jar(location)
        if info is None:
            return None
        if location not in state.graphs:
            state.graphs[location] = build_graph(*read_jar_references(info.path))
        return state.graphs[location]

    def analyze_package(self, project_dir: Path, location: str) -> UsageReport:
        state = self._state(project_dir.resolve())
        info = state.jar(location)
        if info is None:
            return UsageReport(incomplete=True)
        classes, skipped = read_jar_references(info.path)
        own = {c.name for c in classes}
        own_packages = info.packages
        by_package: dict[str, set[Evidence]] = defaultdict(set)
        dynamic: set[Evidence] = set()

        def attribute(owner: str) -> list[str] | None:
            """Artifacts for an internal class name; ``[]`` for the jar itself and the JDK."""
            if owner.startswith("[") or owner in own:
                return []
            name = dotted(owner)
            if name.startswith(JDK_PREFIXES) or name.rsplit(".", 1)[0] in own_packages:
                return []
            return _resolve(name, state, set())

        for cls in classes:
            where = f"{info.path.name}!/{cls.name}.class"
            for owner, method in cls.methods:
                if (owner, method) in REFLECTION:
                    dynamic.add(Evidence(where, 0, f"{owner}.{method}", "dynamic", method))
                artifacts = attribute(owner)
                if artifacts is None:
                    dynamic.add(Evidence(where, 0, owner, "dynamic", f"unresolved class {dotted(owner)}"))
                    continue
                simple = dotted(owner).rsplit(".", 1)[-1]
                symbol = simple if method == "<init>" else method
                for artifact in artifacts:
                    by_package[artifact].add(Evidence(where, 0, f"{owner}.{method}", "call", symbol, dotted(owner)))
            for owner in cls.classes:
                for artifact in attribute(owner) or []:
                    simple = dotted(owner).rsplit(".", 1)[-1]
                    by_package[artifact].add(Evidence(where, 0, owner, "ref", simple, dotted(owner)))

        return UsageReport(
            by_package={a: _ordered(e) for a, e in by_package.items()},
            dynamic=_ordered(dynamic),
            incomplete=skipped,
        )


def _class_candidates(fqn: str):
    """``a.b.Outer.Inner`` may be the class ``a.b.Outer$Inner`` in a jar."""
    yield fqn
    parts = fqn.split(".")
    for n in range(1, min(3, len(parts) - 1) + 1):
        yield ".".join(parts[:-n]) + "$" + "$".join(parts[-n:])
        yield ".".join(parts[:-n])


def _resolve(fqn: str, state: _State, local_packages: set[str]) -> list[str] | None:
    """Artifacts providing ``fqn`` (a class or, for wildcard imports, a package).

    ``[]`` means ignore it (JDK or project code); ``None`` means it cannot be attributed.
    """
    if fqn.startswith(JDK_PREFIXES):
        return []
    by_class, by_package = state.by_class, state.by_package
    for candidate in _class_candidates(fqn):
        if candidate in by_class:  # a jar wins over a same-named project package: over-reporting is safe
            return sorted(by_class[candidate])
    parts = fqn.split(".")
    for i in range(len(parts), 0, -1):
        pkg = ".".join(parts[:i])
        if pkg in by_package:
            return sorted(by_package[pkg])
    package = ".".join(itertools.takewhile(lambda part: not part[:1].isupper(), parts))
    if package in local_packages:
        return []
    # No jar knows it: guess from the groupId, the longest matching one.
    matches: dict[int, list[str]] = defaultdict(list)
    for dep in state.deps:
        group = dep.name.split(":", 1)[0]
        if fqn == group or fqn.startswith(group + "."):
            matches[len(group)].append(dep.name)
    return sorted(matches[max(matches)]) if matches else None


def _ordered(evidence) -> list[Evidence]:
    return sorted(evidence, key=lambda e: (e.file, e.line, e.kind, e.symbol or ""))


def _iter_files(root: Path, suffix: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(suffix):
                yield Path(dirpath) / name
