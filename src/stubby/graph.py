"""Dependency graph: which installed package requires which."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GraphNode:
    key: str  # install location relative to the project, e.g. "node_modules/a/node_modules/b"
    name: str
    version: str
    dev: bool = False  # only reachable from devDependencies


@dataclass
class DependencyGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, list[str]] = field(default_factory=dict)  # key -> keys it requires
    root: list[str] = field(default_factory=list)  # keys the project requires directly

    def __post_init__(self) -> None:
        self._parents: dict[str, list[str]] | None = None

    def instances(self, name: str, version: str) -> list[GraphNode]:
        """Every install location of ``name@version``."""
        return [n for n in self.nodes.values() if n.name == name and n.version == version]

    def dependents(self, key: str) -> list[GraphNode]:
        """Installed packages that directly require the package at ``key``."""
        if self._parents is None:
            self._parents = {}
            for src, targets in self.edges.items():
                for target in targets:
                    self._parents.setdefault(target, []).append(src)
        return [self.nodes[k] for k in sorted(self._parents.get(key, [])) if k in self.nodes]

    def shortest_path(self, key: str) -> list[GraphNode]:
        """Shortest chain of packages from the project down to ``key`` (empty if unreachable)."""
        previous: dict[str, str | None] = {k: None for k in self.root if k in self.nodes}
        queue = deque(previous)
        while queue:
            current = queue.popleft()
            if current == key:
                break
            for nxt in self.edges.get(current, []):
                if nxt in self.nodes and nxt not in previous:
                    previous[nxt] = current
                    queue.append(nxt)
        if key not in previous:
            return []
        path, cursor = [], key
        while cursor is not None:
            path.append(self.nodes[cursor])
            cursor = previous[cursor]
        return path[::-1]
