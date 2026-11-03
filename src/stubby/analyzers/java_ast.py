"""tree-sitter based analysis of a single Java source file.

Java has static types, so a call such as ``yaml.load(x)`` is tied to the class of
``yaml`` through its declaration (local, field, parameter, ``new``). Receivers that
cannot be typed this way are reported by method name only (kind ``maybe``).
Observations use the fully qualified class name as ``package``; the adapter maps
it to the artifact that contains it. Scoping is ignored on purpose, which can only
over-report.
"""

from __future__ import annotations

import re

import tree_sitter_java
from tree_sitter import Language, Node, Parser

from .observations import FileAnalysis, Observation

_PARSER = Parser(Language(tree_sitter_java.language()))
_FQN = re.compile(r"\b((?:[a-z_][\w]*\.){2,}[A-Z][\w$]*)")
_LINE_SKIP = re.compile(r"^\s*(?:import|package)\s")


def analyze_source(source: bytes) -> FileAnalysis:
    root = _PARSER.parse(source).root_node
    analysis = FileAnalysis(has_syntax_errors=root.has_error)
    nodes = list(_walk(root))
    classes: dict[str, str] = {}  # simple name -> fully qualified (imports)
    statics: dict[str, str] = {}  # statically imported member -> class

    for node in nodes:
        if node.type == "import_declaration":
            _handle_import(node, analysis, classes, statics)

    var_types: dict[str, set[str]] = {}
    for node in nodes:
        _collect_declaration(node, var_types)

    for node in nodes:
        if node.type == "type_identifier" and not _in_import(node):
            _handle_type(node, analysis, classes)
        elif node.type == "identifier" and not _in_import(node):
            _handle_identifier(node, analysis, classes)
        elif node.type == "method_invocation":
            _handle_invocation(node, analysis, classes, statics, var_types)

    _fqn_fallback(source.decode("utf-8", errors="replace"), analysis)
    return analysis


def _walk(root: Node):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _in_import(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in ("import_declaration", "package_declaration"):
            return True
        if parent.type in ("class_body", "block"):
            return False
        parent = parent.parent
    return False


def _handle_import(node: Node, analysis: FileAnalysis, classes: dict, statics: dict) -> None:
    ident = next((c for c in node.named_children if c.type in ("scoped_identifier", "identifier")), None)
    if ident is None:
        return
    full = _text(ident)
    is_static = any(c.type == "static" for c in node.children)
    wildcard = any(c.type == "asterisk" for c in node.children)
    line = _line(node)
    if wildcard:
        analysis.observations.append(Observation(full, line, "escape", "*", full + ".*"))
    elif is_static:
        owner, _, member = full.rpartition(".")
        statics[member] = owner
        analysis.observations.append(Observation(owner, line, "import", member, owner))
    else:
        simple = full.rsplit(".", 1)[-1]
        classes[simple] = full
        analysis.observations.append(Observation(full, line, "import", simple, full))


def _type_names(node: Node | None) -> set[str]:
    """Simple (or qualified) class names a declared type refers to, ignoring generics."""
    if node is None:
        return set()
    if node.type == "type_identifier":
        return {_text(node)}
    if node.type == "scoped_type_identifier":
        return {_text(node)}
    if node.type == "generic_type":
        first = next((c for c in node.named_children if c.type in ("type_identifier", "scoped_type_identifier")), None)
        return _type_names(first)
    if node.type == "array_type":
        return _type_names(node.child_by_field_name("element"))
    if node.type == "catch_type":
        return {n for c in node.named_children for n in _type_names(c)}
    return set()


def _collect_declaration(node: Node, var_types: dict[str, set[str]]) -> None:
    kind = node.type
    if kind in ("local_variable_declaration", "field_declaration"):
        type_node = node.child_by_field_name("type")
        for decl in node.named_children:
            if decl.type != "variable_declarator":
                continue
            names = _type_names(type_node)
            value = decl.child_by_field_name("value")
            if names == {"var"} and value is not None and value.type == "object_creation_expression":
                names = _type_names(value.child_by_field_name("type"))
            var_types.setdefault(_text(decl.child_by_field_name("name")), set()).update(names)
    elif kind in ("formal_parameter", "enhanced_for_statement", "resource"):
        name = node.child_by_field_name("name")
        if name is not None:
            var_types.setdefault(_text(name), set()).update(_type_names(node.child_by_field_name("type")))
    elif kind == "catch_formal_parameter":
        name = node.child_by_field_name("name")
        catch_type = next((c for c in node.named_children if c.type == "catch_type"), None)
        if name is not None:
            var_types.setdefault(_text(name), set()).update(_type_names(catch_type))


def _handle_type(node: Node, analysis: FileAnalysis, classes: dict) -> None:
    name = _text(node)
    if name not in classes:
        return
    parent = node.parent
    is_new = parent is not None and parent.type == "object_creation_expression" and (
        parent.child_by_field_name("type") == node
    )
    analysis.observations.append(
        Observation(classes[name], _line(node), "call" if is_new else "ref", name, classes[name])
    )


def _handle_identifier(node: Node, analysis: FileAnalysis, classes: dict) -> None:
    name = _text(node)
    if name not in classes:
        return
    parent = node.parent
    if parent is None:
        return
    uses_class = (
        (parent.type in ("method_invocation", "field_access") and parent.child_by_field_name("object") == node)
        or (parent.type in ("annotation", "marker_annotation") and parent.child_by_field_name("name") == node)
        or parent.type == "method_reference"
    )
    if not uses_class:
        return
    analysis.observations.append(Observation(classes[name], _line(node), "ref", name, classes[name]))
    if parent.type == "field_access":  # constant or nested class: Level.INFO
        member = parent.child_by_field_name("field")
        if member is not None:
            analysis.observations.append(Observation(classes[name], _line(node), "ref", _text(member), classes[name]))


def _resolve(name: str, classes: dict) -> str | None:
    if name in classes:
        return classes[name]
    return name if "." in name else None


def _handle_invocation(node: Node, analysis: FileAnalysis, classes: dict, statics: dict, var_types: dict) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    method = _text(name_node)
    obj = node.child_by_field_name("object")
    line = _line(node)

    def call(fqn: str) -> None:
        analysis.observations.append(Observation(fqn, line, "call", method, fqn))

    def maybe() -> None:
        analysis.observations.append(Observation(None, line, "maybe", method))

    _handle_dynamic(node, method, obj, analysis, line)

    if obj is None:
        if method in statics:
            call(statics[method])
        return
    if obj.type == "this":
        return
    if obj.type == "identifier":
        text = _text(obj)
        if text in classes:
            call(classes[text])
        elif text in var_types:
            for tname in var_types[text]:
                fqn = _resolve(tname, classes)
                if fqn:
                    call(fqn)
            if "var" in var_types[text]:  # inferred from something other than `new`
                maybe()
        else:
            maybe()
        return
    if obj.type == "field_access":
        target = obj.child_by_field_name("object")
        field = obj.child_by_field_name("field")
        if target is not None and target.type == "this" and field is not None and _text(field) in var_types:
            for tname in var_types[_text(field)]:
                fqn = _resolve(tname, classes)
                if fqn:
                    call(fqn)
            return
        maybe()
        return
    if obj.type == "object_creation_expression":
        for tname in _type_names(obj.child_by_field_name("type")):
            fqn = _resolve(tname, classes)
            if fqn:
                call(fqn)
        return
    maybe()


def _handle_dynamic(node: Node, method: str, obj: Node | None, analysis: FileAnalysis, line: int) -> None:
    receiver = _text(obj) if obj is not None and obj.type == "identifier" else ""
    args = node.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    if method == "forName" and receiver == "Class":
        if first is not None and first.type == "string_literal":
            analysis.observations.append(Observation(_text(first)[1:-1], line, "escape", "*", _text(first)[1:-1]))
        else:
            analysis.observations.append(Observation(None, line, "dynamic", "Class.forName"))
    elif method == "loadClass" or (method == "load" and receiver == "ServiceLoader"):
        analysis.observations.append(Observation(None, line, "dynamic", method))


def _fqn_fallback(text: str, analysis: FileAnalysis) -> None:
    """Fully qualified names written inline (code, reflection strings) count as class use."""
    seen = {(o.package, o.line) for o in analysis.observations}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _LINE_SKIP.match(line):
            continue
        for match in _FQN.finditer(line):
            fqn = match.group(1)
            if (fqn, lineno) not in seen:
                analysis.observations.append(Observation(fqn, lineno, "import", fqn.rsplit(".", 1)[-1], fqn))
