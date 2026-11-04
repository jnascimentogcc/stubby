"""Name graph of an installed Java dependency (see ``stubby.reach``).

Built from the class files in the jar. Nodes are simple class names and method
names, so they match what project code reports (``new Yaml()`` is ``Yaml``,
``yaml.dump()`` is ``dump``). A class and each method it declares reach
everything the class's constant pool mentions: its superclass, the classes and
the methods it refers to. Per-method bytecode is not read, so this is class
granular and over-reports.
"""

from __future__ import annotations

from ..jars import REFLECTION, ClassRefs
from ..reach import NameGraph


def _aliases(internal: str) -> set[str]:
    """``a/b/Outer$Inner`` is known as ``Outer$Inner`` and ``Inner``."""
    simple = internal.rsplit("/", 1)[-1]
    return {simple, *(p for p in simple.split("$") if p)}


def build_graph(classes: list[ClassRefs], skipped: bool = False) -> NameGraph:
    graph = NameGraph()
    graph.incomplete = skipped or not classes or any(not c.complete for c in classes)
    for cls in classes:
        names = _aliases(cls.name) | {m for m in cls.defined if not m.startswith("<")}
        graph.defined.update(names)
        mentioned: set[str] = set()
        if cls.super_name:
            mentioned |= _aliases(cls.super_name)
        for ref in cls.classes:
            mentioned |= _aliases(ref)
        for owner, method in cls.methods:
            if not method.startswith("<"):  # constructors are reached through their class
                mentioned.add(method)
            mentioned |= _aliases(owner)
        for name in names:
            for target in mentioned:
                graph.add_edge(name, target)
        if any(ref in REFLECTION for ref in cls.methods):
            graph.dynamic_in.update(names)
    return graph
