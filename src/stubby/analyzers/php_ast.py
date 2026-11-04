"""tree-sitter based analysis of a single PHP source file.

PHP names classes by namespace, so observations carry the fully qualified name
(``Symfony\\Component\\HttpFoundation\\Request``) in ``package``; the adapter maps it
to a Composer package. ``new Foo`` is a ``call`` of ``Foo``, ``Foo::bar()`` a call of
``bar``, and a method call on an untyped value is reported by method name only
(``maybe``). Scoping is ignored on purpose, which can only over-report usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import tree_sitter_php
from tree_sitter import Language, Node, Parser

from .observations import FileAnalysis, Observation

_PARSER = Parser(Language(tree_sitter_php.language_php()))

_NAMES = {"name", "qualified_name"}
_IGNORED_CLASSES = {"self", "static", "parent"}
_DYNAMIC_FUNCTIONS = {
    "eval", "call_user_func", "call_user_func_array", "forward_static_call", "forward_static_call_array",
    "create_function", "unserialize",
}
# Parents in which a bare name is a class reference (type hint, base class, trait, catch, attribute).
_TYPE_PARENTS = {
    "named_type", "base_clause", "class_interface_clause", "use_declaration", "type_list",
    "attribute", "union_type", "intersection_type", "nullable_type", "optional_type",
}
_INCLUDES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}


@dataclass
class PhpAnalysis(FileAnalysis):
    namespaces: set[str] = field(default_factory=set)  # namespaces the file declares


def analyze_source(source: bytes) -> PhpAnalysis:
    root = _PARSER.parse(source).root_node
    analysis = PhpAnalysis(has_syntax_errors=root.has_error)
    state = _State(analysis)
    stack = [root]
    while stack:  # document order, so a `use` is seen before the code that relies on it
        node = stack.pop()
        state.visit(node)
        stack.extend(reversed(node.children))
    return analysis


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _simple(fqn: str) -> str:
    return fqn.rsplit("\\", 1)[-1]


class _State:
    def __init__(self, analysis: PhpAnalysis) -> None:
        self.analysis = analysis
        self.namespace = ""
        self.classes: dict[str, str] = {}  # lowercase alias -> fully qualified name
        self.functions: dict[str, str] = {}
        self.constants: dict[str, str] = {}

    # -- helpers -----------------------------------------------------------

    def emit(self, fqn: str | None, node: Node, kind: str, symbol: str | None) -> None:
        if fqn is None:
            self.analysis.observations.append(Observation(None, _line(node), "dynamic", symbol))
            return
        self.analysis.observations.append(
            Observation(fqn, _line(node), kind, symbol, fqn.replace("\\", "."))
        )

    def maybe(self, node: Node, name: str) -> None:
        self.analysis.observations.append(Observation(None, _line(node), "maybe", name))

    def dynamic(self, node: Node, what: str | None = None) -> None:
        self.analysis.observations.append(Observation(None, _line(node), "dynamic", what))

    def resolve_class(self, name: str) -> str | None:
        """Fully qualified class for a name as written; ``None`` for self/static/parent and globals."""
        if name.startswith("\\"):
            return name.lstrip("\\")
        first, _, rest = name.partition("\\")
        if first.lower() == "namespace" and rest:
            return f"{self.namespace}\\{rest}".lstrip("\\")
        if first.lower() in _IGNORED_CLASSES and not rest:
            return None
        imported = self.classes.get(first.lower())
        if imported is not None:
            return f"{imported}\\{rest}" if rest else imported
        if rest:
            return f"{self.namespace}\\{name}".lstrip("\\")
        return None  # an unqualified class that was not imported is global or in this namespace

    def resolve_function(self, name: str) -> str | None:
        if name.startswith("\\"):
            return name.lstrip("\\")
        if "\\" in name:
            return self.resolve_class(name)
        return self.functions.get(name.lower())

    # -- visitor -----------------------------------------------------------

    def visit(self, node: Node) -> None:
        kind = node.type
        if kind == "namespace_definition":
            name = node.child_by_field_name("name")
            self.namespace = _text(name)
            self.classes, self.functions, self.constants = {}, {}, {}
            if self.namespace:
                self.analysis.namespaces.add(self.namespace)
        elif kind == "namespace_use_declaration":
            self.use_declaration(node)
        elif kind == "object_creation_expression":
            self.creation(node)
        elif kind in ("scoped_call_expression", "class_constant_access_expression", "scoped_property_access_expression"):
            self.scoped(node)
        elif kind == "function_call_expression":
            self.function_call(node)
        elif kind in ("member_call_expression", "nullsafe_member_call_expression"):
            name = node.child_by_field_name("name")
            if name is not None and name.type == "name":
                self.maybe(node, _text(name))
            else:
                self.dynamic(node, "dynamic method name")
        elif kind in _INCLUDES:
            arg = node.named_children[-1] if node.named_children else None
            if arg is None or arg.type not in ("string", "encapsed_string"):
                self.dynamic(node, "include")
        elif kind == "binary_expression":
            if any(c.type == "instanceof" for c in node.children) and node.named_children:
                right = node.named_children[-1]
                if right.type in _NAMES:
                    self.type_reference(right)
        elif kind in _NAMES and node.parent is not None and node.parent.type in _TYPE_PARENTS:
            self.type_reference(node)

    def type_reference(self, node: Node) -> None:
        fqn = self.resolve_class(_text(node))
        if fqn is not None:
            self.emit(fqn, node, "ref", _simple(fqn))

    def use_declaration(self, node: Node) -> None:
        declaration_kind = "class"
        if any(c.type == "function" for c in node.children):
            declaration_kind = "function"
        elif any(c.type == "const" for c in node.children):
            declaration_kind = "const"
        prefix = ""
        group = None
        for child in node.children:
            if child.type in ("namespace_name", "qualified_name") and group is None:
                prefix = _text(child).strip("\\")
            elif child.type == "namespace_use_group":
                group = child
        clauses = [c for c in (group.children if group is not None else node.children) if c.type == "namespace_use_clause"]
        for clause in clauses:
            kind = declaration_kind
            if any(c.type == "function" for c in clause.children):
                kind = "function"
            elif any(c.type == "const" for c in clause.children):
                kind = "const"
            target, alias = None, None
            names = [c for c in clause.children if c.type in _NAMES]
            for index, child in enumerate(clause.children):
                if child.type == "as" and index + 1 < len(clause.children):
                    alias = _text(clause.children[index + 1])
            if names:
                target = _text(names[0]).strip("\\")
            if target is None:
                continue
            fqn = f"{prefix}\\{target}" if prefix else target
            bound = alias or _simple(fqn)
            if kind == "function":
                self.functions[bound.lower()] = fqn
            elif kind == "const":
                self.constants[bound.lower()] = fqn
            else:
                self.classes[bound.lower()] = fqn
            self.emit(fqn, clause, "import", _simple(fqn))

    def creation(self, node: Node) -> None:
        target = next((c for c in node.named_children if c.type not in ("arguments", "attribute_list", "declaration_list")), None)
        if target is None or target.type == "class_declaration":
            return
        if target.type in _NAMES:
            fqn = self.resolve_class(_text(target))
            if fqn is not None:
                self.emit(fqn, node, "call", _simple(fqn))
        elif target.type == "relative_scope":
            return
        else:
            self.dynamic(node, "new with a computed class")

    def scoped(self, node: Node) -> None:
        scope = node.child_by_field_name("scope") or (node.named_children[0] if node.named_children else None)
        name = node.child_by_field_name("name")
        member = _text(name).lstrip("$") if name is not None else None
        if name is not None and name.type not in ("name", "variable_name"):
            self.dynamic(node, "dynamic member")
            return
        if scope is not None and scope.type in _NAMES:
            fqn = self.resolve_class(_text(scope))
            if fqn is not None:
                is_call = node.type == "scoped_call_expression"
                if member and member.lower() == "class":
                    self.emit(fqn, node, "ref", _simple(fqn))
                else:
                    self.emit(fqn, node, "call" if is_call else "ref", member)
                return
            if node.type == "scoped_call_expression" and member and _text(scope).lower() == "parent":
                self.maybe(node, member)  # parent::method() may be a vendor method
        elif scope is not None and scope.type not in ("relative_scope",):
            if member and node.type == "scoped_call_expression":
                self.maybe(node, member)  # $object::method(): class only known at run time

    def function_call(self, node: Node) -> None:
        func = node.child_by_field_name("function") or (node.children[0] if node.children else None)
        if func is None:
            return
        if func.type in _NAMES:
            written = _text(func)
            if written.lstrip("\\").lower() in _DYNAMIC_FUNCTIONS:
                self.dynamic(node, written.lstrip("\\"))
                return
            fqn = self.resolve_function(written)
            if fqn is not None:
                self.emit(fqn, node, "call", _simple(fqn))
        else:
            self.dynamic(node, "dynamic call")
