"""Parser for Composer's ``composer.lock`` and ``composer.json``."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph, GraphNode
from ..models import Dependency

ECOSYSTEM = "Packagist"
_PLATFORM = re.compile(r"^(php|hhvm|composer(-plugin-api|-runtime-api)?|ext-[\w-]+|lib-[\w-]+)$")


@dataclass
class ComposerProject:
    name: str = ""
    version: str = ""
    require: list[str] = field(default_factory=list)  # runtime requirements (packages only)
    require_dev: list[str] = field(default_factory=list)
    namespaces: set[str] = field(default_factory=set)  # PSR-4 / PSR-0 prefixes the project provides
    present: bool = False


@dataclass
class ComposerLock:
    deps: list[Dependency] = field(default_factory=list)
    graph: DependencyGraph = field(default_factory=DependencyGraph)
    # package -> [(namespace prefix, [directories relative to the package])]
    autoload: dict[str, list[tuple[str, list[str]]]] = field(default_factory=dict)
    # package -> directories scanned by the classmap autoloader
    classmap: dict[str, list[str]] = field(default_factory=dict)
    # packages that only declare "files" autoloading (global functions)
    files: dict[str, list[str]] = field(default_factory=dict)


def is_platform(name: str) -> bool:
    return bool(_PLATFORM.match(name.lower()))


def clean_version(version: str) -> str:
    return version[1:] if version[:1] in ("v", "V") and version[1:2].isdigit() else version


def _as_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [v for v in value or [] if isinstance(v, str)]


def read_composer_json(project_dir: Path) -> ComposerProject:
    path = project_dir / "composer.json"
    if not path.is_file():
        return ComposerProject()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ComposerProject()
    if not isinstance(data, dict):
        return ComposerProject()
    project = ComposerProject(
        name=str(data.get("name") or ""),
        version=str(data.get("version") or ""),
        require=sorted(n.lower() for n in (data.get("require") or {}) if not is_platform(n)),
        require_dev=sorted(n.lower() for n in (data.get("require-dev") or {}) if not is_platform(n)),
        present=True,
    )
    for section in ("autoload", "autoload-dev"):
        for kind in ("psr-4", "psr-0"):
            project.namespaces.update(p for p in (data.get(section) or {}).get(kind, {}) if p)
    return project


def parse_composer_lock(path: Path, project: ComposerProject) -> ComposerLock:
    data = json.loads(path.read_text(encoding="utf-8"))
    lock = ComposerLock()
    entries: dict[str, dict] = {}
    dev_listed: set[str] = set()
    for section, is_dev in (("packages", False), ("packages-dev", True)):
        for info in data.get(section) or []:
            name = str(info.get("name") or "").lower()
            if name and info.get("version"):
                entries[name] = info
                if is_dev:
                    dev_listed.add(name)

    runtime_roots = [n for n in project.require if n in entries]
    if project.present:
        roots = runtime_roots + [n for n in project.require_dev if n in entries and n not in runtime_roots]
    else:  # no composer.json: whatever nobody else requires is a direct dependency
        required = {r.lower() for e in entries.values() for r in (e.get("require") or {})}
        roots = sorted(n for n in entries if n not in required)
        runtime_roots = [n for n in roots if n not in dev_listed]

    edges: dict[str, list[str]] = {}
    for name, info in entries.items():
        edges[name] = sorted({r.lower() for r in (info.get("require") or {}) if r.lower() in entries and r.lower() != name})

    shipped: set[str] = set()
    queue = list(runtime_roots)
    while queue:
        current = queue.pop()
        if current not in shipped:
            shipped.add(current)
            queue += edges.get(current, [])

    graph = DependencyGraph()
    for name, info in sorted(entries.items()):
        version = clean_version(str(info["version"]))
        graph.nodes[name] = GraphNode(name, name, version, dev=name not in shipped)
        lock.deps.append(Dependency(ECOSYSTEM, name, version, direct=name in roots))
        _read_autoload(lock, name, info.get("autoload") or {})
    graph.edges = edges
    graph.root = sorted(roots)
    lock.graph = graph
    return lock


def _read_autoload(lock: ComposerLock, name: str, autoload: dict) -> None:
    prefixes: list[tuple[str, list[str]]] = []
    for kind in ("psr-4", "psr-0"):
        for prefix, paths in (autoload.get(kind) or {}).items():
            prefixes.append((prefix, _as_list(paths)))
    if prefixes:
        lock.autoload[name] = prefixes
    if autoload.get("classmap"):
        lock.classmap[name] = _as_list(autoload["classmap"])
    if autoload.get("files"):
        lock.files[name] = _as_list(autoload["files"])
