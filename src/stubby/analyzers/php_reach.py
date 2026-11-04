"""Name graph of an installed Composer package (see ``stubby.reach``).

Definitions are functions, classes, interfaces, traits, enums and methods; a
definition reaches every name its body mentions, and a class reaches its methods
(any of them can run once an instance exists). Statements outside definitions run
when the file is loaded. Strings that look like class or method names count as
mentions, because PHP passes callables as strings (``'Foo::bar'``).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import tree_sitter_php
from tree_sitter import Language, Node, Parser

from ..reach import NameGraph

MAX_FILE_BYTES = 2_000_000
_PARSER = Parser(Language(tree_sitter_php.language_php()))
_CLASS_LIKE = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
_FUNCTION_LIKE = {"function_definition", "method_declaration"}
_CLOSURES = {"anonymous_function", "arrow_function", "anonymous_function_creation_expression"}
_DYNAMIC_FUNCTIONS = {
    "eval", "call_user_func", "call_user_func_array", "forward_static_call", "forward_static_call_array",
    "create_function", "unserialize",
}
_CALLABLE_STRING = re.compile(r"^\\?[A-Za-z_][a-zA-Z0-9_\\]*(::[A-Za-z_]\w*)?$")


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


def _note_dynamic(graph: NameGraph, ctx: tuple[tuple[str, bool], ...]) -> None:
    if not ctx or all(c[1] for c in ctx):
        graph.dynamic = True
    else:
        graph.dynamic_in.add(ctx[-1][0])


def _add_file(graph: NameGraph, data: bytes) -> None:
    root = _PARSER.parse(data).root_node
    if root.has_error:
        graph.incomplete = True
    # Work items: (node, enclosing definitions as [(name, runs_when_loaded)]).
    stack: list[tuple[Node, tuple[tuple[str, bool], ...]]] = [(root, ())]
    skip: set[int] = set()  # names that only name a definition, a namespace or an import
    while stack:
        node, ctx = stack.pop()
        kind = node.type

        if kind in _CLASS_LIKE or kind in _FUNCTION_LIKE:
            name_node = node.child_by_field_name("name")
            name = _text(name_node)
            if name_node is not None and name:
                skip.add(name_node.id)
                graph.defined.add(name)
                if ctx:
                    graph.add_edge(ctx[-1][0], name)
                ctx = ctx + ((name, False),)
        elif kind in ("namespace_definition", "namespace_use_declaration"):
            if kind == "namespace_use_declaration":
                _note_use(graph, node)
            for sub in _walk(node):
                if sub.type == "name" and kind == "namespace_use_declaration":
                    skip.add(sub.id)
                elif sub.type == "namespace_name":
                    skip.update(c.id for c in sub.children if c.type == "name")
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                skip.update(c.id for c in _walk(name_node) if c.type == "name")
            if kind == "namespace_use_declaration":
                continue
        elif kind in _CLOSURES and ctx:
            ctx = ctx + ((ctx[-1][0], False),)  # runs when the caller decides
        elif kind == "function_call_expression":
            func = node.child_by_field_name("function") or (node.children[0] if node.children else None)
            if func is not None and func.type in ("name", "qualified_name"):
                if _text(func).lstrip("\\").lower() in _DYNAMIC_FUNCTIONS:
                    _note_dynamic(graph, ctx)
            elif func is not None:
                _note_dynamic(graph, ctx)  # $callable()
        elif kind == "object_creation_expression":
            target = next((c for c in node.named_children if c.type not in ("arguments", "attribute_list")), None)
            if target is not None and target.type not in ("name", "qualified_name", "class_declaration", "relative_scope"):
                _note_dynamic(graph, ctx)  # new $class
        elif kind in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
            name = node.child_by_field_name("name")
            if name is not None and name.type != "name":
                _note_dynamic(graph, ctx)  # $object->$method()

        if kind == "name" and id_ok(node, skip):
            _mention(graph, ctx, _text(node))
        elif kind == "string_content":
            text = _text(node)
            if _CALLABLE_STRING.match(text):
                for part in re.split(r"::|\\", text):
                    if part:
                        _mention(graph, ctx, part)
        for child in node.children:
            stack.append((child, ctx))


def id_ok(node: Node, skip: set[int]) -> bool:
    parent = node.parent
    return node.id not in skip and not (parent is not None and parent.type == "variable_name")


def _mention(graph: NameGraph, ctx: tuple[tuple[str, bool], ...], text: str) -> None:
    graph.add_edge(ctx[-1][0] if ctx else None, text)
    if all(c[1] for c in ctx):
        graph.top.add(text)


def _note_use(graph: NameGraph, node: Node) -> None:
    """``use A as C`` makes C stand for the last name of A."""
    for clause in _walk(node):
        if clause.type != "namespace_use_clause":
            continue
        names = [c for c in clause.children if c.type in ("name", "qualified_name")]
        alias = None
        for index, child in enumerate(clause.children):
            if child.type == "as" and index + 1 < len(clause.children):
                alias = _text(clause.children[index + 1])
        if names and alias:
            graph.defined.add(alias)
            graph.add_edge(alias, _text(names[0]).rsplit("\\", 1)[-1])


def _walk(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)
