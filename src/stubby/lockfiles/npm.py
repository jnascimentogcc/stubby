"""Parser for npm ``package-lock.json`` (lockfile versions 1, 2 and 3)."""

from __future__ import annotations

import json
from pathlib import Path

from ..graph import DependencyGraph, GraphNode
from ..models import Dependency

_ROOT_DEP_KEYS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


def parse_package_lock(path: Path) -> tuple[str, str, list[Dependency]]:
    """Return ``(project_name, project_version, dependencies)``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    name = data.get("name") or path.parent.resolve().name
    version = data.get("version") or "0.0.0"

    if "packages" in data:
        return name, version, _parse_packages(data)
    return name, version, _parse_v1(data)


def _parse_packages(data: dict) -> list[Dependency]:
    packages: dict = data["packages"]
    root = packages.get("", {})
    direct_names: set[str] = set()
    for key in _ROOT_DEP_KEYS:
        direct_names.update((root.get(key) or {}).keys())

    deps: dict[tuple[str, str], Dependency] = {}
    for key, info in packages.items():
        if not key or info.get("link"):
            continue
        pkg_version = info.get("version")
        if not pkg_version or "node_modules/" not in key:
            continue
        pkg_name = info.get("name") or key.rsplit("node_modules/", 1)[1]
        # Only top-level node_modules entries can be direct dependencies.
        is_top_level = key == f"node_modules/{pkg_name}"
        dep = Dependency(
            ecosystem="npm",
            name=pkg_name,
            version=pkg_version,
            direct=is_top_level and pkg_name in direct_names,
        )
        deps[(dep.name, dep.version)] = _prefer_direct(deps.get((dep.name, dep.version)), dep)
    return sorted(deps.values(), key=lambda d: (d.name, d.version))


def _parse_v1(data: dict) -> list[Dependency]:
    deps: dict[tuple[str, str], Dependency] = {}

    def walk(tree: dict, depth: int) -> None:
        for pkg_name, info in (tree or {}).items():
            pkg_version = info.get("version")
            if pkg_version:
                dep = Dependency("npm", pkg_name, pkg_version, direct=depth == 0)
                deps[(pkg_name, pkg_version)] = _prefer_direct(deps.get((pkg_name, pkg_version)), dep)
            walk(info.get("dependencies") or {}, depth + 1)

    walk(data.get("dependencies") or {}, 0)
    return sorted(deps.values(), key=lambda d: (d.name, d.version))


def parse_package_lock_graph(path: Path) -> DependencyGraph | None:
    """Dependency graph from a v2/v3 lockfile; ``None`` for v1 (no install locations)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    packages: dict | None = data.get("packages")
    if not packages:
        return None

    graph = DependencyGraph()
    for key, info in packages.items():
        if not key or info.get("link") or "node_modules/" not in key or not info.get("version"):
            continue
        name = info.get("name") or key.rsplit("node_modules/", 1)[1]
        graph.nodes[key] = GraphNode(key, name, info["version"], bool(info.get("dev")))

    def requires(info: dict) -> set[str]:
        names: set[str] = set()
        for dep_key in _ROOT_DEP_KEYS:
            names.update((info.get(dep_key) or {}).keys())
        return names

    for key in graph.nodes:
        targets = (_resolve(graph.nodes, key, n) for n in sorted(requires(packages[key])))
        graph.edges[key] = [t for t in targets if t]
    graph.root = [
        t for t in (_resolve(graph.nodes, "", n) for n in sorted(requires(packages.get("", {})))) if t
    ]
    return graph


def _resolve(nodes: dict, from_key: str, name: str) -> str | None:
    """Node's module resolution: look in the requirer's node_modules, then each parent's."""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in nodes:
            return candidate
        if not base:
            return None
        base = base[: base.rfind("node_modules/")].rstrip("/")


def _prefer_direct(existing: Dependency | None, new: Dependency) -> Dependency:
    if existing is not None and existing.direct and not new.direct:
        return existing
    return new
