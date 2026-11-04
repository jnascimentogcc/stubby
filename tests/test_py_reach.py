"""Name graph of an installed Python distribution."""

from __future__ import annotations

from pathlib import Path

from stubby.analyzers.py_reach import build_graph
from stubby.models import Evidence
from stubby.scan import _entries


def graph_of(tmp_path: Path, source: str):
    path = tmp_path / "mod.py"
    path.write_text(source)
    return build_graph([path])


def test_function_reaches_what_it_calls(tmp_path):
    g = graph_of(tmp_path, "def a():\n    return b()\n\ndef b():\n    return C()\n\nclass C:\n    pass\n\ndef z():\n    pass\n")
    reached = g.reachable({"a"})
    assert {"b", "C"} <= reached and "z" not in reached


def test_class_methods_are_reached_through_the_class(tmp_path):
    g = graph_of(tmp_path, "class Loader:\n    def construct(self):\n        return Unsafe()\n\nclass Unsafe:\n    pass\n\ndef other():\n    pass\n")
    assert {"construct", "Unsafe"} <= g.reachable({"Loader"}) and "Unsafe" not in g.reachable({"other"})


def test_imports_and_definition_names_are_not_uses(tmp_path):
    g = graph_of(tmp_path, "from .loader import FullLoader\n\ndef safe_load():\n    pass\n")
    assert "FullLoader" not in g.reachable({"safe_load"})


def test_import_alias_reaches_the_original(tmp_path):
    g = graph_of(tmp_path, "from .loader import FullLoader as Loader\n\ndef load():\n    return Loader()\n")
    assert "FullLoader" in g.reachable({"load"})


def test_eval_matters_only_where_it_can_run(tmp_path):
    g = graph_of(tmp_path, "def f(s):\n    return eval(s)\n\ndef g():\n    pass\n")
    assert g.trusted() and g.uses_dynamic_code(g.reachable({"f"})) and not g.uses_dynamic_code(g.reachable({"g"}))
    assert not graph_of(tmp_path, "eval('1')\n").trusted()
    assert not graph_of(tmp_path, "def (:\n").trusted()


def test_load_time_calls_are_always_reached(tmp_path):
    g = graph_of(tmp_path, "setup()\n\ndef setup():\n    return hidden()\n\ndef hidden():\n    pass\n")
    assert "hidden" in g.reachable(set())


def test_plain_module_import_is_not_a_whole_module_use():
    ev = lambda kind, sym: Evidence("a.py", 1, "c", kind, sym, "yaml")  # noqa: E731
    assert _entries([ev("import", "*"), ev("call", "safe_load")]) == {"safe_load"}
    assert _entries([ev("import", "*"), ev("call", "*")]) is None
