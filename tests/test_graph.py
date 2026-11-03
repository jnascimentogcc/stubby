import json

from stubby.analyzers.javascript import JavaScriptAdapter
from stubby.lockfiles.npm import parse_package_lock_graph
from stubby.models import Dependency, Evidence, Verdict, Vulnerability
from stubby.scan import DependentUsage, _assess
from stubby.symbols import VulnerableSymbol, VulnerableSymbols

LOCK = {
    "name": "app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"a": "1"}, "devDependencies": {"tool": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1", "c": "2"}},
        "node_modules/a/node_modules/c": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1", "@s/d": "1"}},
        "node_modules/c": {"version": "1.0.0"},
        "node_modules/@s/d": {"version": "1.0.0"},
        "node_modules/tool": {"version": "1.0.0", "dev": True, "dependencies": {"c": "1"}},
        "node_modules/linked": {"link": True},
    },
}


def graph_from(tmp_path, lock=LOCK):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    return parse_package_lock_graph(path)


def test_edges_follow_node_module_resolution(tmp_path):
    g = graph_from(tmp_path)
    assert g.root == ["node_modules/a", "node_modules/tool"]
    # `a` gets its own nested c@2; `b` falls back to the hoisted c@1; scoped names resolve too.
    assert g.edges["node_modules/a"] == ["node_modules/b", "node_modules/a/node_modules/c"]
    assert g.edges["node_modules/b"] == ["node_modules/@s/d", "node_modules/c"]
    assert "node_modules/linked" not in g.nodes


def test_dependents_instances_and_dev_flag(tmp_path):
    g = graph_from(tmp_path)
    assert [n.name for n in g.dependents("node_modules/c")] == ["b", "tool"]
    assert [n.key for n in g.instances("c", "2.0.0")] == ["node_modules/a/node_modules/c"]
    assert g.nodes["node_modules/tool"].dev and not g.nodes["node_modules/a"].dev


def test_shortest_path_from_the_project(tmp_path):
    g = graph_from(tmp_path)
    assert [n.name for n in g.shortest_path("node_modules/@s/d")] == ["a", "b", "@s/d"]
    assert [n.name for n in g.shortest_path("node_modules/a")] == ["a"]
    assert g.shortest_path("node_modules/linked") == []


def test_lockfile_v1_has_no_graph(tmp_path):
    assert graph_from(tmp_path, {"lockfileVersion": 1, "dependencies": {"a": {"version": "1"}}}) is None


def test_package_analysis_reads_dist_and_skips_nested_installs(tmp_path):
    pkg = tmp_path / "node_modules" / "a"
    (pkg / "dist").mkdir(parents=True)
    (pkg / "node_modules" / "inner").mkdir(parents=True)
    (pkg / "dist" / "index.js").write_text("require('lodash').template(x);\n", encoding="utf-8")
    (pkg / "node_modules" / "inner" / "index.js").write_text("require('evil');\n", encoding="utf-8")

    report = JavaScriptAdapter().analyze_package(tmp_path, "node_modules/a")

    assert set(report.by_package) == {"lodash"}
    assert report.by_package["lodash"][0].file == "node_modules/a/dist/index.js"
    assert not report.incomplete


def test_oversized_files_mark_the_report_incomplete(tmp_path, monkeypatch):
    from stubby.analyzers import javascript

    pkg = tmp_path / "node_modules" / "a"
    pkg.mkdir(parents=True)
    (pkg / "index.js").write_text("require('lodash');\n", encoding="utf-8")
    monkeypatch.setattr(javascript, "MAX_FILE_BYTES", 5)

    assert JavaScriptAdapter().analyze_package(tmp_path, "node_modules/a").incomplete


DEP = Dependency("npm", "lodash", "4.17.20", direct=False)
VULN = Vulnerability(id="GHSA-1")
SYMBOLS = VulnerableSymbols([VulnerableSymbol("template", None, "q")], "high")


def dependent(name="some-lib", evidence=(), installed=True, dynamic=(), incomplete=False):
    from stubby.graph import GraphNode

    node = GraphNode(f"node_modules/{name}", name, "1.0.0")
    return DependentUsage(node, installed, list(evidence), list(dynamic), incomplete)


def ev(kind, symbol, line=1):
    return Evidence("node_modules/some-lib/index.js", line, "code", kind, symbol, "lodash")


def assess(dependents, dep=DEP, **kw):
    return _assess(dep, VULN, [], [], SYMBOLS, dependents=dependents, chain=["some-lib", "lodash"], **kw)


def test_transitive_all_dependents_clear_is_not_affected():
    f = assess([dependent(evidence=[ev("import", "debounce"), ev("call", "debounce", 2)])])
    assert f.verdict is Verdict.NOT_AFFECTED
    assert "transitive dependency via some-lib > lodash" in f.notes
    assert {e.line for e in f.evidence} == {1, 2}


def test_transitive_dependent_using_the_symbol_is_inconclusive_with_citation():
    f = assess([dependent(evidence=[ev("import", "template"), ev("call", "template", 4)])])
    assert f.verdict is Verdict.INCONCLUSIVE
    assert "uses a vulnerable symbol (node_modules/some-lib/index.js:4)" in f.notes


def test_uninspectable_or_opaque_dependents_block_not_affected():
    clear = [ev("import", "debounce")]
    assert assess([dependent(installed=False)]).verdict is Verdict.INCONCLUSIVE
    assert assess([dependent(evidence=clear, incomplete=True)]).verdict is Verdict.INCONCLUSIVE
    assert assess([dependent(evidence=clear, dynamic=[ev("dynamic", None)])]).verdict is Verdict.INCONCLUSIVE
    assert assess([dependent(evidence=[ev("ref", "default")])]).verdict is Verdict.INCONCLUSIVE
    assert assess([dependent(evidence=clear), dependent("other", installed=False)]).verdict is Verdict.INCONCLUSIVE


def test_one_bad_dependent_among_clear_ones_blocks():
    f = assess([dependent(evidence=[ev("import", "debounce")]), dependent("bad", evidence=[ev("call", "template")])])
    assert f.verdict is Verdict.INCONCLUSIVE


def test_unknown_dependents_block_not_affected_for_direct_dependencies():
    direct = Dependency("npm", "lodash", "4.17.20", direct=True)
    evidence = [Evidence("a.js", 1, "code", "import", "debounce", "lodash")]
    known = _assess(direct, VULN, evidence, [], SYMBOLS, dependents=[])
    unknown = _assess(direct, VULN, evidence, [], SYMBOLS, dependents=None, dependents_known=False)
    assert known.verdict is Verdict.NOT_AFFECTED
    assert unknown.verdict is Verdict.INCONCLUSIVE and "v1 lockfile" in unknown.notes


def test_dependent_using_the_symbol_blocks_a_direct_not_affected():
    direct = Dependency("npm", "lodash", "4.17.20", direct=True)
    project = [Evidence("a.js", 1, "code", "import", "debounce", "lodash")]
    f = _assess(direct, VULN, project, [], SYMBOLS, dependents=[dependent(evidence=[ev("call", "template")])])
    assert f.verdict is Verdict.INCONCLUSIVE


def test_dev_only_dependencies_are_noted():
    f = assess([dependent(evidence=[ev("import", "debounce")])], dev_only=True)
    assert "only required by devDependencies" in f.notes
