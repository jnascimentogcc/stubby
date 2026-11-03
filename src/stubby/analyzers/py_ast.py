"""tree-sitter based analysis of a single Python source file.

Reports which top-level modules a file imports, which of their members it binds,
and where those bindings are called or referenced. Scoping is ignored on purpose:
a shadowed name is still reported, which can only over-report usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from .observations import FileAnalysis, Observation

_PARSER = Parser(Language(tree_sitter_python.language()))

_DYNAMIC_CALLS = {"__import__", "import_module", "exec", "eval"}
_DECLARATION_PARENTS = {"parameters", "lambda_parameters", "function_definition", "class_definition"}
_TYPE_CHECKING = {"TYPE_CHECKING", "typing.TYPE_CHECKING"}


@dataclass
class Binding:
    package: str  # top-level module
    module: str  # module the name refers to (full dotted path)
    symbol: str  # "*" for a module, else the imported member
    prefixes: set[tuple[str, ...]] = field(default_factory=set)  # `import a.b.c` also binds a.b.c


def analyze_source(source: bytes) -> FileAnalysis:
    root = _PARSER.parse(source).root_node
    analysis = FileAnalysis(has_syntax_errors=root.has_error)
    bindings: dict[str, Binding] = {}
    nodes = list(_walk(root))

    for node in nodes:
        if node.type == "import_statement":
            _handle_import(node, analysis, bindings)
        elif node.type == "import_from_statement":
            _handle_import_from(node, analysis, bindings)
        elif node.type == "call":
            _handle_dynamic_call(node, analysis)

    if bindings:
        for node in nodes:
            if node.type == "identifier" and node.text.decode() in bindings:
                _handle_reference(node, analysis, bindings)
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


def _in_type_checking_block(node: Node) -> bool:
    """True for imports under ``if TYPE_CHECKING:`` (never executed at runtime)."""
    child, parent = node, node.parent
    while parent is not None:
        if parent.type == "if_statement":
            consequence = parent.child_by_field_name("consequence")
            condition = parent.child_by_field_name("condition")
            if (
                consequence is not None
                and condition is not None
                and _text(condition) in _TYPE_CHECKING
                and consequence.start_byte <= child.start_byte < consequence.end_byte
            ):
                return True
        child, parent = parent, parent.parent
    return False


def _handle_import(node: Node, analysis: FileAnalysis, bindings: dict) -> None:
    if _in_type_checking_block(node):
        return
    line = _line(node)
    for child in node.named_children:
        if child.type == "dotted_name":  # import a.b.c  binds `a`
            full = _text(child)
            top, *rest = full.split(".")
            binding = bindings.setdefault(top, Binding(top, top, "*"))
            binding.prefixes.add(tuple(rest))
            analysis.observations.append(Observation(top, line, "import", "*", full))
        elif child.type == "aliased_import":  # import a.b.c as x  binds x to a.b.c
            full = _text(child.child_by_field_name("name"))
            alias = _text(child.child_by_field_name("alias"))
            top = full.split(".")[0]
            bindings[alias] = Binding(top, full, "*", {()})
            analysis.observations.append(Observation(top, line, "import", "*", full))


def _handle_import_from(node: Node, analysis: FileAnalysis, bindings: dict) -> None:
    module_node = node.child_by_field_name("module_name")
    if module_node is None or module_node.type != "dotted_name":
        return  # relative imports are project-local
    if _in_type_checking_block(node):
        return
    full = _text(module_node)
    top = full.split(".")[0]
    line = _line(node)
    for child in node.named_children:
        if child.id == module_node.id:
            continue
        if child.type == "wildcard_import":
            analysis.observations.append(Observation(top, line, "escape", "*", full))
        elif child.type == "dotted_name":
            name = _text(child)
            bindings[name] = Binding(top, full, name)
            analysis.observations.append(Observation(top, line, "import", name, full))
        elif child.type == "aliased_import":
            name = _text(child.child_by_field_name("name"))
            alias = _text(child.child_by_field_name("alias"))
            bindings[alias] = Binding(top, full, name)
            analysis.observations.append(Observation(top, line, "import", name, full))


def _string_value(node: Node | None) -> str | None:
    """Value of a plain string literal (None for f-strings and non-literals)."""
    if node is None or node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.children):
        return None
    return "".join(_text(c) for c in node.children if c.type == "string_content")


def _handle_dynamic_call(node: Node, analysis: FileAnalysis) -> None:
    func = node.child_by_field_name("function")
    if func is None:
        return
    name = _text(func.child_by_field_name("attribute")) if func.type == "attribute" else (
        _text(func) if func.type == "identifier" else ""
    )
    if name not in _DYNAMIC_CALLS or (func.type == "attribute" and name != "import_module"):
        return
    line = _line(node)
    if name in ("exec", "eval"):
        analysis.observations.append(Observation(None, line, "dynamic", name))
        return
    args = node.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    spec = _string_value(first)
    if spec is None:
        analysis.observations.append(Observation(None, line, "dynamic", None))
    elif not spec.startswith("."):  # relative import_module('.x', package) stays in the package
        top = spec.split(".")[0]
        analysis.observations.append(Observation(top, line, "escape", "*", spec))


def _is_declaration(ident: Node) -> bool:
    """True where the identifier names something instead of using a binding."""
    node = ident.parent
    if node is None:
        return True
    kind = node.type
    if kind == "attribute":
        return node.child_by_field_name("attribute") == ident
    if kind == "keyword_argument":
        return node.child_by_field_name("name") == ident
    if kind in ("function_definition", "class_definition"):
        return node.child_by_field_name("name") == ident
    if kind in ("parameters", "lambda_parameters"):
        return True
    if kind in ("default_parameter", "typed_default_parameter"):
        return node.child_by_field_name("name") == ident
    if kind == "typed_parameter":
        return node.named_children[0] == ident
    # Names inside import statements are handled by the import handlers.
    while node is not None and node.type not in ("module", "block"):
        if node.type in ("import_statement", "import_from_statement"):
            return True
        node = node.parent
    return False


def _handle_reference(ident: Node, analysis: FileAnalysis, bindings: dict) -> None:
    if _is_declaration(ident):
        return
    binding = bindings[_text(ident)]

    tokens: list[str] = []
    top = ident
    while (
        top.parent is not None
        and top.parent.type == "attribute"
        and top.parent.child_by_field_name("object") == top
    ):
        tokens.append(_text(top.parent.child_by_field_name("attribute")))
        top = top.parent
    outer = top.parent
    is_call = outer is not None and outer.type == "call" and outer.child_by_field_name("function") == top
    kind = "call" if is_call else "ref"
    line = _line(ident)

    def emit(symbol: str, module: str | None = None) -> None:
        analysis.observations.append(
            Observation(binding.package, line, kind, symbol, module or binding.module)
        )

    if binding.symbol == "*":  # a module: the member is the first attribute past the import path
        for prefix in sorted(binding.prefixes, key=len, reverse=True):
            if tuple(tokens[: len(prefix)]) == prefix:
                tokens = tokens[len(prefix):]
                break
        emit(tokens[0] if tokens else "*")
        return

    # `from pkg import name`: `name` may be a function, a class or a submodule.
    emit(binding.symbol)
    if tokens:
        emit(tokens[0])
    elif not is_call:
        # Passed around bare. If `name` is a submodule, which member is used is unknown;
        # the module is `pkg.name` so the adapter can drop this when `pkg.name` is not a module.
        emit("*", f"{binding.module}.{binding.symbol}")
