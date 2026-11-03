"""Java dependency readers: ``pom.xml``, ``mvn dependency:tree`` output and ``gradle.lockfile``."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph, GraphNode
from ..models import Dependency

ECOSYSTEM = "Maven"
TREE_FILES = ("dependency-tree.txt", "target/dependency-tree.txt")
_PROPERTY = re.compile(r"\$\{([^}]+)\}")
_DEV_SCOPES = {"test"}


@dataclass
class Pom:
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    deps: list[tuple[str, str, str, str]] = field(default_factory=list)  # group, artifact, version, scope
    warnings: list[str] = field(default_factory=list)


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: ET.Element | None, tag: str) -> str | None:
    child = el.find(tag) if el is not None else None
    return child.text.strip() if child is not None and child.text else None


def parse_pom(path: Path) -> Pom:
    """Direct dependencies of one ``pom.xml``; versions are resolved from its own properties only."""
    root = ET.parse(path).getroot()
    _strip_ns(root)
    pom = Pom()
    parent = root.find("parent")
    pom.group = _text(root, "groupId") or _text(parent, "groupId")
    pom.artifact = _text(root, "artifactId")
    pom.version = _text(root, "version") or _text(parent, "version")

    props = {"project.version": pom.version or "", "project.groupId": pom.group or "",
             "project.artifactId": pom.artifact or "", "project.parent.version": _text(parent, "version") or ""}
    for prop in root.findall("properties/*"):
        if prop.text:
            props[prop.tag] = prop.text.strip()

    def resolve(value: str | None) -> str | None:
        for _ in range(5):  # properties may refer to properties
            if value is None or "${" not in value:
                break
            value = _PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        return value

    managed: dict[tuple[str, str], str] = {}
    for dep in root.findall("dependencyManagement/dependencies/dependency"):
        g, a, v = (resolve(_text(dep, t)) for t in ("groupId", "artifactId", "version"))
        if g and a and v and "${" not in v:
            managed[(g, a)] = v

    for dep in root.findall("dependencies/dependency"):
        g, a = resolve(_text(dep, "groupId")), resolve(_text(dep, "artifactId"))
        if not g or not a:
            continue
        v = resolve(_text(dep, "version")) or managed.get((g, a))
        scope = _text(dep, "scope") or "compile"
        if not v or "${" in v or v[0] in "[(":
            pom.warnings.append(
                f"pom.xml: the version of {g}:{a} comes from a parent, a BOM or a range, so it was not "
                "checked; run `mvn dependency:tree -DoutputFile=dependency-tree.txt` for the resolved tree"
            )
            continue
        pom.deps.append((g, a, v, scope))
    return pom


@dataclass
class MavenTree:
    root: tuple[str, str, str] | None
    deps: list[Dependency]
    graph: DependencyGraph


_TREE_PREFIX = re.compile(r"^((?:[| ] {2}|[+\\]- )*)")


def parse_maven_tree(path: Path) -> MavenTree:
    """Parse the text output of ``mvn dependency:tree`` (one resolved version per artifact)."""
    graph = DependencyGraph()
    stack: list[str] = []
    root = None
    nodes: dict[str, tuple[str, str, str, str]] = {}  # key -> (group, artifact, version, scope)
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _TREE_PREFIX.match(line)
        prefix = match.group(1) if match else ""
        depth = len(prefix) // 3
        coord = line[len(prefix):].split(" (")[0].strip()
        parts = coord.split(":")
        if len(parts) < 4:
            continue
        group, artifact = parts[0], parts[1]
        if depth == 0 and root is None:
            root = (group, artifact, parts[-1])
            stack = []
            continue
        scope = parts[-1] if len(parts) >= 5 else "compile"
        version = parts[-2] if len(parts) >= 5 else parts[-1]
        key = f"{group}:{artifact}"
        nodes.setdefault(key, (group, artifact, version, scope))
        graph.edges.setdefault(key, [])
        stack = stack[: depth - 1]
        if stack:
            parent = stack[-1]
            if key not in graph.edges.setdefault(parent, []):
                graph.edges[parent].append(key)
        elif key not in graph.root:
            graph.root.append(key)
        stack.append(key)

    for key, (group, artifact, version, scope) in nodes.items():
        graph.nodes[key] = GraphNode(key, key, version, scope in _DEV_SCOPES)
    root_keys = set(graph.root)
    deps = [
        Dependency(ECOSYSTEM, key, node.version, direct=key in root_keys)
        for key, node in sorted(graph.nodes.items())
    ]
    return MavenTree(root, deps, graph)


_GRADLE_LOCK = re.compile(r"^([^:#=\s]+):([^:#=\s]+):([^=\s]+)=(.*)$")


def parse_gradle_lockfile(path: Path, build_text: str) -> list[Dependency]:
    """``gradle.lockfile`` lists every resolved coordinate; ``build.gradle[.kts]`` says which are direct."""
    deps: dict[str, Dependency] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _GRADLE_LOCK.match(line.strip())
        if not match:
            continue
        group, artifact, version, configs = match.groups()
        key = f"{group}:{artifact}"
        direct = f"{group}:{artifact}" in build_text or (
            re.search(rf"group\s*[=:]\s*['\"]{re.escape(group)}['\"].*name\s*[=:]\s*['\"]{re.escape(artifact)}['\"]", build_text)
            is not None
        )
        deps[key] = Dependency(ECOSYSTEM, key, version, direct=direct)
    return sorted(deps.values(), key=lambda d: d.name)
