from stubby.analyzers.javascript import JavaScriptAdapter
from stubby.analyzers.js_ast import analyze_source
from stubby.models import Dependency, Evidence, Vulnerability
from stubby.scan import _assess


def obs(code: str, suffix: str = ".ts"):
    analysis = analyze_source(code.encode(), suffix)
    return [(o.package, o.kind, o.symbol, o.line) for o in analysis.observations]


def test_named_import_with_alias_and_call():
    assert obs("import { merge as m } from 'lodash';\nm({}, {});\n") == [
        ("lodash", "import", "merge", 1),
        ("lodash", "call", "merge", 2),
    ]


def test_default_import_member_call_reports_member():
    result = obs("import _ from 'lodash';\n_.template('x');\nconst f = _.get;\n")
    assert ("lodash", "call", "template", 2) in result
    assert ("lodash", "ref", "get", 3) in result


def test_namespace_import_and_new_expression():
    result = obs("import * as ex from 'express';\nconst app = new ex.Router();\n")
    assert ("express", "import", "*", 1) in result
    assert ("express", "call", "Router", 2) in result


def test_require_destructuring_binds_members():
    result = obs("const { merge, set: assign } = require('lodash');\nmerge(a);\nassign(b);\n", ".js")
    assert ("lodash", "import", "merge", 1) in result
    assert ("lodash", "import", "set", 1) in result
    assert ("lodash", "call", "merge", 2) in result
    assert ("lodash", "call", "set", 3) in result


def test_require_member_access_and_whole_module():
    assert obs("const t = require('lodash').template;\n", ".js") == [
        ("lodash", "import", "template", 1)
    ]
    assert obs("require('lodash');\n", ".js") == [("lodash", "import", None, 1)]
    assert obs("run(require('lodash'));\n", ".js") == [("lodash", "escape", "*", 1)]


def test_shorthand_property_counts_as_reference():
    result = obs("import { merge } from 'lodash';\nuse({ merge });\n")
    assert ("lodash", "ref", "merge", 2) in result


def test_export_from_and_side_effect_import():
    result = obs("export { a, b as c } from 'pkg';\nexport * from 'other';\nimport 'polyfill';\n")
    assert ("pkg", "import", "a", 1) in result
    assert ("pkg", "import", "b", 1) in result
    assert ("other", "escape", "*", 2) in result
    assert ("polyfill", "import", None, 3) in result


def test_relative_and_builtin_specifiers_are_ignored():
    assert obs("import a from './a';\nimport fs from 'node:fs';\nrequire('./b');\n") == []


def test_type_only_imports_are_not_runtime_usage():
    assert obs("import type { T } from 'pkg';\nimport { type U } from 'pkg2';\n") == []


def test_dynamic_code_is_reported_without_a_package():
    result = obs("const n = 'x';\nrequire(n);\nimport(`${n}`);\neval('1');\n", ".js")
    assert result == [
        (None, "dynamic", None, 2),
        (None, "dynamic", None, 3),
        (None, "dynamic", "eval", 4),
    ]


def test_dynamic_loading_of_relative_files_is_not_a_package_load():
    code = (
        "require('./locale/' + name);\n"
        "require(`./plugins/${name}`);\n"
        "require(path.join(__dirname, 'x', name));\n"
        "require(name);\n"
    )
    assert obs(code, ".js") == [(None, "dynamic", None, 4)]


def test_template_literal_without_substitution_is_static():
    assert obs("const x = require(`lodash`);\n", ".js") == [("lodash", "import", "*", 1)]


def test_tsx_and_jsx_are_parsed():
    result = obs("import { Button } from 'ui';\nconst a = <Button />;\n", ".tsx")
    assert ("ui", "ref", "Button", 2) in result


def test_syntax_errors_fall_back_to_regex(tmp_path):
    (tmp_path / "broken.js").write_text("import x from 'lodash'\nconst = = ;\n", encoding="utf-8")
    report = JavaScriptAdapter().analyze(tmp_path)
    assert "lodash" in report.by_package


def test_analyze_collects_dynamic_sites_across_files(tmp_path):
    (tmp_path / "a.js").write_text("require(process.env.PLUGIN);\n", encoding="utf-8")
    report = JavaScriptAdapter().analyze(tmp_path)
    assert [(e.file, e.line, e.kind) for e in report.dynamic] == [("a.js", 1, "dynamic")]


def test_assess_notes_describe_members_calls_and_dynamic_code(tmp_path):
    (tmp_path / "a.js").write_text(
        "const { merge } = require('lodash');\nmerge(a);\nrequire(name);\n", encoding="utf-8"
    )
    report = JavaScriptAdapter().analyze(tmp_path)
    dep = Dependency("npm", "lodash", "4.17.15", direct=True)
    finding = _assess(dep, Vulnerability(id="X"), report.by_package["lodash"], report.dynamic)

    assert "imported in 1 file(s)" in finding.notes
    assert "members used: merge" in finding.notes
    assert "1 call site(s)" in finding.notes
    assert "dynamic" in finding.notes
    assert finding.verdict.value == "inconclusive"


def test_dynamic_code_noted_even_when_package_never_imported():
    dep = Dependency("npm", "unused", "1.0.0", direct=True)
    dyn = [Evidence("a.js", 1, "require(x)", "dynamic")]
    finding = _assess(dep, Vulnerability(id="X"), [], dyn)
    assert "never imported" in finding.notes
    assert "not conclusive" in finding.notes
