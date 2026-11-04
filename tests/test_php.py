"""PHP: composer.lock, namespace resolution, vendor index and the name graph."""

from __future__ import annotations

import json
from pathlib import Path

from stubby.analyzers.php import PhpAdapter
from stubby.analyzers.php_ast import analyze_source
from stubby.analyzers.php_reach import build_graph
from stubby.lockfiles.php import parse_composer_lock, read_composer_json
from stubby.models import Dependency


def observed(source: str):
    analysis = analyze_source(source.encode())
    return [(o.kind, o.symbol, o.package) for o in analysis.observations]


def test_use_new_static_call_and_type_hint_are_attributed_to_the_class():
    got = observed(
        "<?php\nnamespace App;\nuse Vendor\\Lib\\{Client, Util as U};\n"
        "function f(Client $c) { $x = new Client(); U::run(); \\Other\\Thing::go(); }\n"
    )
    assert ("import", "Client", "Vendor\\Lib\\Client") in got
    assert ("import", "Util", "Vendor\\Lib\\Util") in got
    assert ("call", "Client", "Vendor\\Lib\\Client") in got
    assert ("call", "run", "Vendor\\Lib\\Util") in got
    assert ("call", "go", "Other\\Thing") in got
    assert ("ref", "Client", "Vendor\\Lib\\Client") in got


def test_function_imports_and_method_calls_on_untyped_values():
    got = observed("<?php\nuse function Vendor\\Lib\\helper;\nhelper();\n$obj->parse();\nstrlen('x');\n")
    assert ("call", "helper", "Vendor\\Lib\\helper") in got
    assert ("maybe", "parse", None) in got
    assert not any(symbol == "strlen" for _, symbol, _ in got)  # unimported functions are PHP's own


def test_computed_classes_calls_and_unserialize_are_dynamic():
    got = observed("<?php\n$a = new $cls; $f(); $o->$m(); unserialize($s); eval($c); include $p;\n")
    assert sum(1 for kind, _, _ in got if kind == "dynamic") == 6


def test_parent_class_and_instanceof_count_as_class_references():
    got = observed("<?php\nuse Vendor\\Base;\nuse Vendor\\Other;\nclass A extends Base { function f($x) { return $x instanceof Other; } }\n")
    assert ("ref", "Base", "Vendor\\Base") in got and ("ref", "Other", "Vendor\\Other") in got


def write_project(tmp_path: Path, source: str = "<?php\n") -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/A.php").write_text(source)
    (tmp_path / "composer.json").write_text(json.dumps({
        "name": "acme/app", "require": {"php": ">=8", "vendor/lib": "^1"}, "require-dev": {"vendor/dev": "^1"},
        "autoload": {"psr-4": {"App\\": "src/"}}}))
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [
            {"name": "vendor/lib", "version": "v1.2.3", "require": {"php": ">=8", "vendor/util": "^1"},
             "autoload": {"psr-4": {"Vendor\\Lib\\": "src/"}}},
            {"name": "Vendor/Util", "version": "1.0.0", "autoload": {"psr-4": {"Vendor\\Util\\": ""}}},
        ],
        "packages-dev": [{"name": "vendor/dev", "version": "2.0.0"}]}))
    return tmp_path


def test_lockfile_gives_versions_direct_flags_graph_and_dev_scope(tmp_path):
    write_project(tmp_path)
    lock = parse_composer_lock(tmp_path / "composer.lock", read_composer_json(tmp_path))
    deps = {d.name: d for d in lock.deps}
    assert deps["vendor/lib"] == Dependency("Packagist", "vendor/lib", "1.2.3", direct=True)
    assert not deps["vendor/util"].direct and deps["vendor/dev"].direct
    assert lock.graph.edges["vendor/lib"] == ["vendor/util"]
    assert lock.graph.nodes["vendor/dev"].dev and not lock.graph.nodes["vendor/util"].dev
    assert Dependency("Packagist", "symfony/http-kernel", "5.4.0").purl == "pkg:composer/symfony/http-kernel@5.4.0"


def test_classes_map_to_packages_and_unknown_namespaces_are_unresolved(tmp_path):
    write_project(tmp_path, "<?php\nnamespace App;\nuse Vendor\\Lib\\Client;\nuse Nobody\\Known;\nnew Client(); new Known();\n")
    (tmp_path / "vendor/vendor/lib/src").mkdir(parents=True)
    (tmp_path / "vendor/vendor/lib/src/Client.php").write_text("<?php\nnamespace Vendor\\Lib;\nclass Client {}\n")
    adapter = PhpAdapter()
    assert adapter.detect(tmp_path)
    report = adapter.analyze(tmp_path)
    assert {e.symbol for e in report.by_package["vendor/lib"]} == {"Client"}
    assert any("unresolved class Nobody" in (e.symbol or "") for e in report.dynamic)
    assert adapter.is_installed(tmp_path, "vendor/lib") and not adapter.is_installed(tmp_path, "vendor/util")
    assert any("not in vendor/" in w for w in adapter.warnings(tmp_path))


def test_missing_vendor_directory_is_reported(tmp_path):
    write_project(tmp_path)
    assert any("no vendor/" in w for w in PhpAdapter().warnings(tmp_path))


def graph_of(tmp_path: Path, source: str):
    path = tmp_path / "m.php"
    path.write_text(source)
    return build_graph([path])


def test_classes_reach_their_methods_and_what_those_mention(tmp_path):
    g = graph_of(tmp_path, "<?php\nclass A { function run() { return B::make(); } }\nclass B { static function make() { return new C(); } }\nclass C {}\nclass D {}\n")
    reached = g.reachable({"A"})
    assert {"run", "B", "make", "C"} <= reached and "D" not in reached


def test_use_statements_and_definition_names_are_not_uses(tmp_path):
    g = graph_of(tmp_path, "<?php\nnamespace N;\nuse Other\\Hidden;\nfunction safe() {}\n")
    assert "Hidden" not in g.reachable({"safe"})


def test_dynamic_code_matters_only_where_it_can_run(tmp_path):
    g = graph_of(tmp_path, "<?php\nfunction f($s) { return unserialize($s); }\nfunction g() {}\n")
    assert g.trusted() and g.uses_dynamic_code(g.reachable({"f"})) and not g.uses_dynamic_code(g.reachable({"g"}))
    assert not graph_of(tmp_path, "<?php\neval($x);\n").trusted()
    assert not graph_of(tmp_path, "<?php\nfunction (").trusted()


def test_callable_strings_count_as_mentions(tmp_path):
    g = graph_of(tmp_path, "<?php\nfunction f() { return array_map('Util::clean', []); }\nclass Util { static function clean() {} }\n")
    assert "clean" in g.reachable({"f"})


def test_class_map_written_by_composer_maps_classes_without_psr_prefixes(tmp_path):
    write_project(tmp_path)
    composer = tmp_path / "vendor/composer"
    composer.mkdir(parents=True)
    (composer / "autoload_classmap.php").write_text(
        "<?php\n$vendorDir = dirname(__DIR__);\nreturn array(\n"
        "    'Legacy\\\\Mailer' => $vendorDir . '/vendor/lib/lib/Mailer.php',\n"
        "    'Composer\\\\InstalledVersions' => $vendorDir . '/composer/InstalledVersions.php',\n);\n"
    )
    adapter = PhpAdapter()
    adapter.detect(tmp_path)
    assert adapter._state(tmp_path).vendor.package_of("Legacy\\Mailer") == "vendor/lib"
    assert adapter._state(tmp_path).vendor.package_of("legacy\\mailer") == "vendor/lib"  # PHP class names ignore case
    assert adapter._state(tmp_path).vendor.package_of("Composer\\InstalledVersions") is None
