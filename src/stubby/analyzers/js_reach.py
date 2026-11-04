"""Name graph of an installed npm package (see ``stubby.reach``)."""

from __future__ import annotations

import os
from pathlib import Path

from tree_sitter import Node, Parser

from ..reach import DEFAULT_EXPORT, NameGraph
from .js_ast import _LANGUAGES, _PARSERS, language_for

SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
SKIP_DIRS = {"node_modules", ".git", "test", "tests", "__tests__", "docs", "example", "examples"}
MAX_FILE_BYTES = 2_000_000
_REFERENCES = {"identifier", "property_identifier", "shorthand_property_identifier"}
_FUNCTION_LIKE = {
    "arrow_function", "function_expression", "function", "generator_function",
    "class", "class_expression", "function_declaration", "generator_function_declaration",
    "class_declaration", "method_definition",
}
# Values that merely name or collect other things; evaluating them calls nothing.
_INERT_VALUES = {"identifier", "member_expression", "string", "number", "object", "array", "template_string", "true", "false", "null", "undefined"}
_DECLARATIONS = {"function_declaration", "generator_function_declaration", "class_declaration"}


def build_graph(root: Path) -> NameGraph:
    graph = NameGraph()
    files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix not in SOURCE_SUFFIXES or name.endswith(".d.ts") or name.endswith(".d.mts"):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    graph.incomplete = True
                    continue
                data = path.read_bytes()
            except OSError:
                graph.incomplete = True
                continue
            files += 1
            _add_file(graph, data, path.suffix)
    if files == 0:
        graph.incomplete = True
    return graph


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _key_name(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type in ("identifier", "property_identifier", "private_property_identifier"):
        return _text(node)
    if node.type == "string":
        return _text(node).strip("'\"`")
    return None


def _runs(value: Node | None) -> bool:
    """Whether evaluating ``value`` when its module loads can call something."""
    if value is None:
        return False
    if value.type in _FUNCTION_LIKE or value.type in _INERT_VALUES:
        return False
    if value.type == "call_expression" and _text(value.child_by_field_name("function")) == "require":
        return False  # loading the module is already counted through its own top-level code
    return True


def _definition(node: Node) -> tuple[str, bool] | None:
    """(name, runs_when_loaded) for a node that defines a name, else None."""
    kind = node.type
    if kind in _DECLARATIONS:
        name = _key_name(node.child_by_field_name("name"))
        return (name, False) if name else None
    if kind in ("function_expression", "generator_function", "class", "class_expression"):
        name = _key_name(node.child_by_field_name("name"))
        return (name, False) if name else None
    if kind == "method_definition":
        name = _key_name(node.child_by_field_name("name"))
        return (name, False) if name else None
    if kind in ("variable_declarator", "pair", "field_definition", "public_field_definition"):
        field = "key" if kind == "pair" else ("property" if kind == "field_definition" else "name")
        name = _key_name(node.child_by_field_name(field) or node.child_by_field_name("name"))
        value = node.child_by_field_name("value")
        if name:
            return name, _runs(value)
        return None
    if kind == "assignment_expression":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        name = None
        if left is not None and left.type == "identifier":
            name = _text(left)
        elif left is not None and left.type == "member_expression":
            if _text(left) == "module.exports":
                name = DEFAULT_EXPORT
            else:
                name = _key_name(left.child_by_field_name("property"))
        if name:
            return name, _runs(right)
    return None


def _name_nodes(node: Node) -> list[int]:
    """Identifier nodes that name the definition ``node`` rather than use a name."""
    kind = node.type
    if kind == "assignment_expression":
        left = node.child_by_field_name("left")
        if left is not None and left.type == "member_expression":
            prop = left.child_by_field_name("property")
            return [prop.id] if prop is not None else []
        return [left.id] if left is not None else []
    field = "key" if kind == "pair" else ("property" if kind == "field_definition" else "name")
    target = node.child_by_field_name(field) or node.child_by_field_name("name")
    return [target.id] if target is not None else []


def _add_file(graph: NameGraph, data: bytes, suffix: str) -> None:
    lang = language_for(suffix)
    parser = _PARSERS.setdefault(lang, Parser(_LANGUAGES[lang]))
    root = parser.parse(data).root_node
    if root.has_error:
        graph.incomplete = True
    # Work items: (node, enclosing definitions as [(name, runs_when_loaded)]).
    stack: list[tuple[Node, tuple[tuple[str, bool], ...]]] = [(root, ())]
    skip: set[int] = set()  # ids of identifiers that only name a definition
    while stack:
        node, ctx = stack.pop()
        definition = _definition(node)
        if definition is not None:
            name, loads = definition
            graph.defined.add(name)
            if ctx:
                graph.add_edge(ctx[-1][0], name)  # an enclosing definition may use it
            ctx = ctx + ((name, loads),)
            skip.update(_name_nodes(node))
        elif node.type in ("arrow_function", "function_expression", "function", "generator_function") and ctx:
            # A callback handed to a call: it runs when the caller decides, not when the module loads.
            ctx = ctx + ((ctx[-1][0], False),)
        elif node.type == "export_statement" and any(c.type == "default" for c in node.children):
            value = node.child_by_field_name("value") or node.child_by_field_name("declaration")
            loads = _runs(value)
            graph.defined.add(DEFAULT_EXPORT)
            ctx = ctx + ((DEFAULT_EXPORT, loads),)
        elif node.type in ("export_specifier", "import_specifier"):
            # Listing a name in an import or export clause mentions it without using it.
            original, alias = node.child_by_field_name("name"), node.child_by_field_name("alias")
            for part in (original, alias):
                if part is not None:
                    skip.add(part.id)
            if original is not None and alias is not None:
                graph.defined.add(_text(alias))
                graph.add_edge(_text(alias), _text(original))
        elif node.type == "new_expression" and _text(node.child_by_field_name("constructor")) == "Function":
            graph.dynamic = True
        elif node.type == "identifier" and _text(node) == "eval" and node.parent is not None and node.parent.type == "call_expression":
            graph.dynamic = True

        if node.type in _REFERENCES and node.id not in skip:
            text = _text(node)
            graph.add_edge(ctx[-1][0] if ctx else None, text)
            if all(c[1] for c in ctx):
                graph.top.add(text)
        for child in node.children:
            stack.append((child, ctx))
