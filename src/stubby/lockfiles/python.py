"""Python lockfile readers: ``poetry.lock``, ``requirements.txt`` and ``pyproject.toml``."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import DependencyGraph, GraphNode
from ..models import Dependency
from ..pyenv import normalize

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)")
ECOSYSTEM = "PyPI"


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


@dataclass
class PyProject:
    name: str | None = None
    version: str | None = None
    direct: set[str] | None = None  # normalised names; None when pyproject.toml says nothing


def read_pyproject(project_dir: Path) -> PyProject:
    path = project_dir / "pyproject.toml"
    if not path.is_file():
        return PyProject()
    try:
        data = _load_toml(path)
    except (OSError, ValueError):
        return PyProject()

    direct: set[str] = set()
    project = data.get("project", {})
    poetry = data.get("tool", {}).get("poetry", {})

    def add_specs(specs) -> None:
        for spec in specs or []:
            match = _NAME.match(str(spec))
            if match:
                direct.add(normalize(match.group(1)))

    add_specs(project.get("dependencies"))
    for extra in (project.get("optional-dependencies") or {}).values():
        add_specs(extra)
    for group in (data.get("dependency-groups") or {}).values():
        add_specs([g for g in group if isinstance(g, str)])
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values()]
    for table in tables:
        for name in (table or {}):
            if name.lower() != "python":
                direct.add(normalize(name))

    return PyProject(
        name=project.get("name") or poetry.get("name"),
        version=project.get("version") or poetry.get("version"),
        direct=direct or None,
    )


def parse_poetry_lock(
    path: Path, direct_names: set[str] | None
) -> tuple[list[Dependency], DependencyGraph]:
    data = _load_toml(path)
    graph = DependencyGraph()
    raw_deps: dict[str, list[str]] = {}
    for pkg in data.get("package", []):
        name = normalize(pkg["name"])
        groups = pkg.get("groups")
        dev = pkg.get("category") == "dev" or (bool(groups) and "main" not in groups)
        graph.nodes[name] = GraphNode(name, name, str(pkg["version"]), dev)
        raw_deps[name] = [normalize(d) for d in (pkg.get("dependencies") or {})]

    for name, targets in raw_deps.items():
        graph.edges[name] = sorted({t for t in targets if t in graph.nodes and t != name})

    if direct_names is None:  # no pyproject.toml: anything nobody requires is the project's own pick
        required = {t for targets in graph.edges.values() for t in targets}
        direct_names = {n for n in graph.nodes if n not in required}
    graph.root = sorted(n for n in direct_names if n in graph.nodes)

    root = set(graph.root)
    deps = [Dependency(ECOSYSTEM, n.name, n.version, direct=n.name in root) for n in graph.nodes.values()]
    return sorted(deps, key=lambda d: d.name), graph


@dataclass
class Requirement:
    name: str
    version: str
    via: list[str] = field(default_factory=list)  # pip-compile "# via" annotations


@dataclass
class Requirements:
    pinned: list[Requirement] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_requirements(path: Path, _seen: set[Path] | None = None) -> Requirements:
    result = Requirements()
    seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in seen:
        return result
    seen.add(path)

    current: Requirement | None = None
    in_via = False
    pending = ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            if current is not None and raw[:1] in (" ", "\t"):  # pip-compile annotation under a requirement
                text = stripped.lstrip("#").strip()
                if text.startswith("via"):
                    in_via, text = True, text[3:].strip()
                if in_via and text:
                    current.via += [v.strip() for v in text.split(",") if v.strip()]
            continue
        in_via = False
        line = pending + raw.split(" #")[0].strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1].strip() + " "
            continue
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            nested = path.parent / line.split(None, 1)[1].strip()
            if nested.is_file():
                sub = parse_requirements(nested, seen)
                result.pinned += sub.pinned
                result.warnings += sub.warnings
            continue
        if line.startswith("-"):
            continue  # -e, -c, --index-url, ...
        match = _PINNED.match(line)
        if match:
            current = Requirement(normalize(match.group(1)), match.group(2))
            result.pinned.append(current)
        else:
            current = None
            result.warnings.append(
                f"{path.name}: '{line}' is not pinned with ==, so it was not checked for vulnerabilities"
            )
    return result


def requirement_is_direct(req: Requirement) -> bool:
    """pip-compile marks requirements it was asked for with ``via -r <file>``; plain files list them all."""
    return not req.via or any(v.startswith(("-r", "-c", "--requirement")) for v in req.via)
