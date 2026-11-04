"""Reachability inside one installed package.

A project that uses ``tar.x()`` never names ``Unpack``, yet ``x`` creates one. To
tell whether the members the project uses can reach a vulnerable symbol, the
package's own code is reduced to a *name graph*: an edge ``a -> b`` means the
definition named ``a`` mentions the name ``b``. Names are global to the package
and never scoped, so two unrelated definitions sharing a name merge. That only
adds edges, which can make Stubby say "may reach" too often but never "cannot
reach" wrongly. Code executed when a module loads (``top``) is always reached.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

DEFAULT_EXPORT = "default"


@dataclass
class NameGraph:
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    top: set[str] = field(default_factory=set)  # names mentioned by code that runs on load
    defined: set[str] = field(default_factory=set)
    dynamic: bool = False  # eval at load time: names can be built at run time, from anywhere
    dynamic_in: set[str] = field(default_factory=set)  # definitions that call eval / exec
    incomplete: bool = False  # some file could not be read or parsed

    def add_edge(self, source: str | None, target: str) -> None:
        if source is None:
            self.top.add(target)
        else:
            self.edges[source].add(target)

    def reachable(self, entries: set[str] | None) -> set[str]:
        """Names reachable from ``entries`` plus load-time code; ``None`` means every definition."""
        start = set(self.top) | (set(self.defined) if entries is None else set(entries))
        seen: set[str] = set()
        stack = list(start)
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            stack.extend(self.edges.get(name, ()))
        return seen

    def trusted(self) -> bool:
        return not (self.dynamic or self.incomplete)

    def uses_dynamic_code(self, reached: set[str]) -> bool:
        """Whether code that can run (given ``reached``) calls eval or exec."""
        return bool(self.dynamic_in & reached)
