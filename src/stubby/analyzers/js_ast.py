"""tree-sitter based analysis of a single JS/TS source file.

Finds which packages a file loads, which of their members it binds, and where
those bindings are called or referenced. Scoping is deliberately ignored: a
shadowed name is still reported, which can only over-report usage.
"""

from __future__ import annotations

from dataclasses import dataclass

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from .observations import FileAnalysis, Observation

_LANGUAGES = {
    "javascript": Language(tree_sitter_javascript.language()),
    "typescript": Language(tree_sitter_typescript.language_typescript()),
    "tsx": Language(tree_sitter_typescript.language_tsx()),
}
_PARSERS: dict[str, Parser] = {}

_SUFFIX_LANGUAGE = {".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx"}

# Parent node types in which an identifier declares or names something rather than uses it.
_NON_REFERENCE_PARENTS = {
    "import_clause",
    "import_specifier",
    "namespace_import",
    "export_specifier",
    "pair_pattern",
}


@dataclass(frozen=True)
class Binding:
    package: str
    module: str
    symbol: str  # "*" whole module, "default", or a named export


def language_for(suffix: str) -> str:
    return _SUFFIX_LANGUAGE.get(suffix, "javascript")


def package_name_from_specifier(spec: str) -> str | None:
    """Map an import specifier to its npm package name (None if not a package)."""
    if not spec or spec.startswith((".", "/", "node:", "#")):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def analyze_source(source: bytes, suffix: str) -> FileAnalysis:
    lang = language_for(suffix)
    parser = _PARSERS.setdefault(lang, Parser(_LANGUAGES[lang]))
    root = parser.parse(source).root_node
    analysis = FileAnalysis(has_syntax_errors=root.has_error)

    bindings: dict[str, Binding] = {}
    declaring: set[int] = set()  # start bytes of identifiers that declare a binding
    nodes = list(_walk(root))

    for node in nodes:
        if node.type in ("import_statement", "export_statement"):
            _handle_esm(node, analysis, bindings, declaring)
        elif node.type == "call_expression":
            _handle_call(node, analysis, bindings, declaring)

    for node in nodes:
        if node.type in ("identifier", "shorthand_property_identifier") and node.start_byte not in declaring:
            _handle_reference(node, analysis, bindings)
        elif node.type == "call_expression":
            _handle_untracked_member_call(node, analysis, bindings)
    return analysis


def _handle_untracked_member_call(node: Node, analysis: FileAnalysis, bindings: dict) -> None:
    """`x.name()` where `x` is not a tracked import: it may still be a package object.

    Values returned by tracked calls flow into untracked variables, so the method
    name is recorded; it only matters if it matches a vulnerable symbol.
    """
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return
    base = func.child_by_field_name("object")
    while base is not None and base.type == "member_expression":
        base = base.child_by_field_name("object")
    if base is not None and base.type == "identifier" and _text(base) in bindings:
        return
    prop = func.child_by_field_name("property")
    if prop is not None:
        analysis.observations.append(Observation(None, _line(node), "maybe", _text(prop)))


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


def _literal(node: Node | None) -> str | None:
    """Return the value of a string (or substitution-free template) literal."""
    if node is None:
        return None
    if node.type == "string" or (
        node.type == "template_string"
        and not any(c.type == "template_substitution" for c in node.children)
    ):
        return _text(node)[1:-1]
    return None


def _is_relative_path(node: Node | None) -> bool:
    """True for `'./x' + y`, `` `./${y}` `` and `path.join(__dirname, ...)`: always files, not packages."""
    while node is not None and node.type == "binary_expression":
        node = node.child_by_field_name("left")
    if node is None:
        return False
    if node.type == "template_string":
        return _text(node)[1:].startswith(("./", "../"))
    if node.type == "string":
        return _text(node)[1:].startswith(("./", "../"))
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        name = _text(func.child_by_field_name("property")) if func is not None and func.type == "member_expression" else (
            _text(func) if func is not None else ""
        )
        return name in ("join", "resolve") and first is not None and _text(first) == "__dirname"
    return False


def _handle_esm(node: Node, analysis: FileAnalysis, bindings: dict, declaring: set) -> None:
    source = node.child_by_field_name("source")
    spec = _literal(source)
    if spec is None:
        return
    package = package_name_from_specifier(spec)
    if package is None:
        return
    line = _line(source)

    if node.type == "export_statement":
        clause = next((c for c in node.children if c.type == "export_clause"), None)
        if clause is None:  # export * from 'pkg'
            analysis.observations.append(Observation(package, line, "escape", "*", spec))
            return
        for spec_node in (c for c in clause.children if c.type == "export_specifier"):
            name = spec_node.child_by_field_name("name")
            analysis.observations.append(Observation(package, line, "import", _text(name), spec))
        return

    clause = next((c for c in node.children if c.type == "import_clause"), None)
    if clause is None:  # import 'pkg'
        analysis.observations.append(Observation(package, line, "import", None, spec))
        return
    if any(c.type == "type" for c in node.children):  # import type ... (erased at runtime)
        return

    for child in clause.children:
        if child.type == "identifier":  # default import
            _bind(child, Binding(package, spec, "default"), analysis, bindings, declaring, line)
        elif child.type == "namespace_import":
            ident = next(c for c in child.children if c.type == "identifier")
            _bind(ident, Binding(package, spec, "*"), analysis, bindings, declaring, line)
        elif child.type == "named_imports":
            for item in (c for c in child.children if c.type == "import_specifier"):
                if any(c.type == "type" for c in item.children):  # import {type X}
                    continue
                name = item.child_by_field_name("name")
                alias = item.child_by_field_name("alias") or name
                binding = Binding(package, spec, _text(name))
                _bind(alias, binding, analysis, bindings, declaring, _line(item))


def _bind(ident: Node, binding: Binding, analysis, bindings, declaring, line: int) -> None:
    bindings[_text(ident)] = binding
    declaring.add(ident.start_byte)
    analysis.observations.append(Observation(binding.package, line, "import", binding.symbol, binding.module))


def _handle_call(node: Node, analysis: FileAnalysis, bindings: dict, declaring: set) -> None:
    func = node.child_by_field_name("function")
    if func is None:
        return
    is_require = func.type == "identifier" and _text(func) == "require"
    is_import = func.type == "import"
    is_eval = func.type == "identifier" and _text(func) == "eval"
    if not (is_require or is_import or is_eval):
        return

    args = node.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    spec = None if is_eval else _literal(first)

    if spec is None and not is_eval and _is_relative_path(first):
        return  # loads a file of the same package, never another package
    if spec is None:
        analysis.observations.append(Observation(None, _line(node), "dynamic", "eval" if is_eval else None))
        return
    package = package_name_from_specifier(spec)
    if package is None:
        return
    line = _line(node)
    if is_import:  # dynamic import() of a literal: whole module, binding not tracked
        analysis.observations.append(Observation(package, line, "escape", "*", spec))
        return

    parent = node.parent
    if parent is not None and parent.type == "variable_declarator" and (
        parent.child_by_field_name("value") == node
    ):
        target = parent.child_by_field_name("name")
        if target is not None and target.type == "identifier":
            _bind(target, Binding(package, spec, "*"), analysis, bindings, declaring, line)
            return
        if target is not None and target.type == "object_pattern":
            for member in target.named_children:
                if member.type == "shorthand_property_identifier_pattern":
                    ident, symbol = member, _text(member)
                elif member.type == "pair_pattern":
                    key, ident = member.child_by_field_name("key"), member.child_by_field_name("value")
                    if ident is None or ident.type != "identifier":
                        analysis.observations.append(Observation(package, line, "escape", "*", spec))
                        continue
                    symbol = _text(key)
                else:  # rest element: any member may be used
                    analysis.observations.append(Observation(package, line, "escape", "*", spec))
                    continue
                _bind(ident, Binding(package, spec, symbol), analysis, bindings, declaring, line)
            return
    if parent is not None and parent.type == "member_expression" and (
        parent.child_by_field_name("object") == node
    ):
        prop = parent.child_by_field_name("property")
        analysis.observations.append(Observation(package, line, "import", _text(prop), spec))
        return
    if parent is not None and parent.type == "expression_statement":  # require('pkg'); side effect only
        analysis.observations.append(Observation(package, line, "import", None, spec))
        return
    # The module value flows somewhere untracked (argument, call result, ...).
    analysis.observations.append(Observation(package, line, "escape", "*", spec))


def _handle_reference(ident: Node, analysis: FileAnalysis, bindings: dict) -> None:
    binding = bindings.get(_text(ident))
    parent = ident.parent
    if binding is None or parent is None or parent.type in _NON_REFERENCE_PARENTS:
        return
    # `{ key: value }` keys and `{ a: b }` pattern keys are property names, not uses.
    if parent.type in ("variable_declarator", "assignment_expression", "function_declaration"):
        field_name = "left" if parent.type == "assignment_expression" else "name"
        if parent.child_by_field_name(field_name) == ident:
            return

    symbol = binding.symbol
    top = ident
    parent_node = ident.parent
    if parent_node.type == "member_expression" and parent_node.child_by_field_name("object") == ident:
        if symbol in ("*", "default"):
            symbol = _text(parent_node.child_by_field_name("property"))
        top = parent_node
        while (
            top.parent is not None
            and top.parent.type == "member_expression"
            and top.parent.child_by_field_name("object") == top
        ):
            top = top.parent

    outer = top.parent
    is_call = outer is not None and (
        (outer.type == "call_expression" and outer.child_by_field_name("function") == top)
        or (outer.type == "new_expression" and outer.child_by_field_name("constructor") == top)
    )
    analysis.observations.append(
        Observation(binding.package, _line(ident), "call" if is_call else "ref", symbol, binding.module)
    )
