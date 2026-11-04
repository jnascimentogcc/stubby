"""Name graph of an installed Python distribution (see ``stubby.reach``)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from ..reach import NameGraph

MAX_FILE_BYTES = 2_000_000
_PARSER = Parser(Language(tree_sitter_python.language()))
# Values that merely name or collect other things; evaluating them calls nothing.
_INERT_VALUES = {
    "identifier", "attribute", "string", "concatenated_string", "integer", "float", "true", "false",
    "none", "list", "tuple", "dictionary", "set", "lambda", "ellipsis",
}


def build_graph(files: Iterable[Path]) -> NameGraph:
    graph = NameGraph()
    seen = 0
    for path in files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                graph.incomplete = True
                continue
            data = path.read_bytes()
        except OSError:
            graph.incomplete = True
            continue
        seen += 1
        _add_file(graph, data)
    if seen == 0:
        graph.incomplete = True
    return graph


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _runs(value: Node | None) -> bool:
    """Whether evaluating ``value`` when its module loads can call something."""
    return value is not None and value.type not in _INERT_VALUES


def _assignment_target(node: Node) -> str | None:
    left = node.child_by_field_name("left")
    if left is None:
        return None
    if left.type == "identifier":
        return _text(left)
    if left.type == "attribute":
        attr = left.child_by_field_name("attribute")
        return _text(attr) if attr is not None else None
    return None


def _add_file(graph: NameGraph, data: bytes) -> None:
    root = _PARSER.parse(data).root_node
    if root.has_error:
        graph.incomplete = True
    # Work items: (node, enclosing definitions as [(name, runs_when_loaded)]).
    stack: list[tuple[Node, tuple[tuple[str, bool], ...]]] = [(root, ())]
    skip: set[int] = set()  # identifiers that only name a definition or an import
    while stack:
        node, ctx = stack.pop()
        kind = node.type

        if kind in ("function_definition", "class_definition"):
            name_node = node.child_by_field_name("name")
            name = _text(name_node)
            if name_node is not None:
                skip.add(name_node.id)
                graph.defined.add(name)
                if ctx:
                    graph.add_edge(ctx[-1][0], name)
                # A class body runs when the class is defined; a function body only when called.
                inner = ctx + ((name, kind == "class_definition"),)
                body = node.child_by_field_name("body")
                for child in node.children:
                    # Decorators, defaults, annotations and base classes are evaluated in the outer scope.
                    stack.append((child, inner if child == body else ctx))
                continue
        elif kind == "assignment":
            name = _assignment_target(node)
            if name:
                graph.defined.add(name)
                left = node.child_by_field_name("left")
                if left is not None:
                    attr = left.child_by_field_name("attribute") if left.type == "attribute" else left
                    if attr is not None:
                        skip.add(attr.id)
                if ctx:
                    graph.add_edge(ctx[-1][0], name)
                ctx = ctx + ((name, _runs(node.child_by_field_name("right"))),)
        elif kind == "lambda" and ctx:
            ctx = ctx + ((ctx[-1][0], False),)  # runs when the caller decides
        elif kind in ("import_from_statement", "import_statement"):
            for child in node.children:
                if child.type == "aliased_import":
                    original, alias = child.child_by_field_name("name"), child.child_by_field_name("alias")
                    if alias is not None and original is not None:
                        graph.defined.add(_text(alias))
                        graph.add_edge(_text(alias), _text(original).rsplit(".", 1)[-1])
            for sub in _walk(node):
                if sub.type == "identifier":
                    skip.add(sub.id)  # importing a name mentions it without using it
            continue
        elif kind == "call":
            func = node.child_by_field_name("function")
            if func is not None and func.type == "identifier" and _text(func) in ("eval", "exec"):
                if not ctx or all(c[1] for c in ctx):
                    graph.dynamic = True
                else:
                    graph.dynamic_in.add(ctx[-1][0])

        if kind == "identifier" and node.id not in skip:
            text = _text(node)
            graph.add_edge(ctx[-1][0] if ctx else None, text)
            if all(c[1] for c in ctx):
                graph.top.add(text)
        for child in node.children:
            stack.append((child, ctx))


def _walk(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)
