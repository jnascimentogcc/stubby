"""Reachability inside an installed package: the name graph and its use in verdicts."""

from __future__ import annotations

from pathlib import Path

from stubby.analyzers.js_reach import build_graph
from stubby.models import Dependency, Evidence, Verdict, Vulnerability
from stubby.reach import NameGraph
from stubby.scan import _assess, _entries, _reach_blockers
from stubby.symbols import VulnerableSymbol, VulnerableSymbols


def package(tmp_path: Path, source: str, name: str = "index.js") -> Path:
    root = tmp_path / "pkg"
    root.mkdir(exist_ok=True)
    (root / name).write_text(source)
    return root


def reach(tmp_path: Path, source: str, entries: set[str] | None) -> tuple[NameGraph, set[str]]:
    graph = build_graph(package(tmp_path, source))
    return graph, graph.reachable(entries)


def test_function_reaches_what_it_calls_through_other_functions(tmp_path):
    src = "function a(){ return b(); }\nfunction b(){ return new C(); }\nclass C {}\nfunction z(){}\nmodule.exports = { a, z };\n"
    _, reached = reach(tmp_path, src, {"a"})
    assert {"b", "C"} <= reached and "z" not in reached


def test_class_methods_and_constructors_are_reached_through_the_class(tmp_path):
    src = "class Unpack { write(x){ return new Link(x); } }\nclass Link {}\nfunction extract(){ return new Unpack(); }\nfunction other(){}\n"
    _, reached = reach(tmp_path, src, {"extract"})
    assert {"Unpack", "write", "Link"} <= reached and "other" not in reached


def test_callbacks_passed_to_load_time_calls_belong_to_the_definition_not_to_load_time(tmp_path):
    src = "const extract = makeCommand((opt) => new Unpack(opt));\nclass Unpack {}\nfunction create(){}\n"
    graph, reached = reach(tmp_path, src, {"create"})
    assert "Unpack" not in reached  # extract is never used
    assert "Unpack" in graph.reachable({"extract"})


def test_load_time_calls_are_always_reached(tmp_path):
    graph, reached = reach(tmp_path, "setup();\nfunction setup(){ return hidden(); }\nfunction hidden(){}\n", set())
    assert "hidden" in reached


def test_listing_a_name_in_an_export_clause_is_not_a_use(tmp_path):
    src = "function Unpack(){}\nfunction x(){}\nexport { Unpack, x as extract };\n"
    graph = build_graph(package(tmp_path, src, "index.mjs"))
    assert "Unpack" not in graph.reachable({"extract"}) and "x" in graph.reachable({"extract"})


def test_default_export_alias_reaches_the_exported_function(tmp_path):
    src = "function expandTop(s){ return expand(s); }\nfunction expand(s){ return s; }\nmodule.exports = expandTop;\n"
    _, reached = reach(tmp_path, src, {"default"})
    assert "expand" in reached


def test_eval_and_unparsable_files_make_the_graph_untrusted(tmp_path):
    assert not build_graph(package(tmp_path, "function f(s){ return eval(s); }")).trusted()
    assert not build_graph(package(tmp_path, "function (")).trusted()
    assert build_graph(package(tmp_path, "function f(){}")).trusted()


def symbols(*names: str) -> VulnerableSymbols:
    return VulnerableSymbols([VulnerableSymbol(n, None, "q") for n in names], "high")


def test_blockers_cover_reach_missing_symbols_missing_source_and_whole_module(tmp_path):
    graph = build_graph(package(tmp_path, "class Link {}\nfunction x(){ return new Link(); }\nfunction c(){}\n"))
    codes = lambda names, entries, graphs: [c for c, _ in _reach_blockers(symbols(*names), entries, graphs)]  # noqa: E731
    assert codes(["Link"], {"x"}, [graph]) == ["internal-reach"]
    assert codes(["Link"], {"c"}, [graph]) == []
    assert codes(["Gone"], {"c"}, [graph]) == ["symbol-not-found"]
    assert codes(["Link"], {"c"}, []) == ["package-not-installed"]
    assert codes(["Link"], None, [graph]) == []  # whole-module use is blocked elsewhere


def test_entries_are_the_member_names_used_or_none_for_whole_module():
    ev = lambda kind, sym: Evidence("a.js", 1, "c", kind, sym, "m")  # noqa: E731
    assert _entries([ev("import", "x"), ev("call", "x")]) == {"x"}
    assert _entries([ev("import", "x"), ev("call", "default")]) is None


def test_verdict_depends_on_what_the_used_member_reaches(tmp_path):
    graph = build_graph(package(tmp_path, "class Link {}\nfunction x(){ return new Link(); }\nfunction c(){}\n"))
    dep, vuln = Dependency("npm", "tar", "7", direct=True), Vulnerability(id="GHSA-1")

    def verdict(member: str):
        used = [Evidence("a.js", 1, "c", "import", member, "tar"), Evidence("a.js", 2, "c", "call", member, "tar")]
        return _assess(dep, vuln, used, [], symbols("Link"), graphs=[graph])

    assert verdict("c").verdict is Verdict.NOT_AFFECTED
    reached = verdict("x")
    assert reached.verdict is Verdict.INCONCLUSIVE and "internal-reach" in reached.reasons
