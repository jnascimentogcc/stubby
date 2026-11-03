import json

from stubby.analyzers.javascript import JavaScriptAdapter
from stubby.lockfiles.npm import parse_package_lock


def test_multiline_imports_are_detected(tmp_path):
    (tmp_path / "a.ts").write_text(
        "import {\n  map,\n  filter,\n} from 'lodash';\n"
        "export {\n  x\n} from \"@scope/pkg/sub\";\n"
        "const m = await import(\n  'dayjs'\n);\n",
        encoding="utf-8",
    )
    imports = JavaScriptAdapter().find_imports(tmp_path)

    assert set(imports) == {"lodash", "@scope/pkg", "dayjs"}
    # Named imports point at the line of each specifier.
    assert [(e.line, e.symbol, e.snippet) for e in imports["lodash"]] == [
        (2, "map", "map,"),
        (3, "filter", "filter,"),
    ]
    assert imports["@scope/pkg"][0].line == 7


def test_each_import_is_reported_once_per_line(tmp_path):
    (tmp_path / "a.js").write_text("import _ from 'lodash';\nrequire('lodash');\n", encoding="utf-8")
    evidence = JavaScriptAdapter().find_imports(tmp_path)["lodash"]
    assert [e.line for e in evidence] == [1, 2]


def test_parse_lockfile_v1_marks_nested_as_transitive(tmp_path):
    lock = {
        "name": "legacy",
        "version": "2.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.15"},
            "express": {
                "version": "4.0.0",
                "dependencies": {
                    "qs": {"version": "1.0.0"},
                    "lodash": {"version": "4.17.15"},
                },
            },
        },
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")

    name, version, deps = parse_package_lock(path)

    assert (name, version) == ("legacy", "2.0.0")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].direct  # also nested under express; direct wins
    assert by_name["express"].direct
    assert not by_name["qs"].direct
    assert len(deps) == 3
