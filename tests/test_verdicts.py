from pathlib import Path

import pytest

from stubby import cli
from stubby.llm.base import LLMError
from stubby.models import Dependency, Evidence, Verdict, Vulnerability
from stubby.scan import _assess, scan_project
from stubby.symbols import VulnerableSymbol, VulnerableSymbols

DEP = Dependency("npm", "lodash", "4.17.15", direct=True)
VULN = Vulnerability(id="GHSA-1")
FIXTURE = Path(__file__).parent / "fixtures" / "sample-js"


def symbols(confidence="high", name="template", module=None) -> VulnerableSymbols:
    return VulnerableSymbols([VulnerableSymbol(name, module, "q")], confidence)


def ev(kind, symbol, line=1, module="lodash") -> Evidence:
    return Evidence("a.js", line, "code", kind, symbol, module)


def test_vulnerable_symbol_called_is_affected_with_cited_sites():
    evidence = [ev("import", "template"), ev("call", "template", 5), ev("call", "merge", 6)]
    f = _assess(DEP, VULN, evidence, [], symbols())
    assert f.verdict is Verdict.AFFECTED
    assert [(e.line, e.symbol) for e in f.evidence] == [(5, "template")]
    assert "vulnerable symbol used at 1 site(s)" in f.notes


def test_member_of_default_import_is_matched():
    f = _assess(DEP, VULN, [ev("import", "default"), ev("call", "template", 3)], [], symbols())
    assert f.verdict is Verdict.AFFECTED


def test_vulnerable_submodule_import_is_matched():
    evidence = [ev("import", "*", module="lodash/template"), ev("call", "*", 2, "lodash/template")]
    assert _assess(DEP, VULN, evidence, [], symbols()).verdict is Verdict.AFFECTED


def test_other_members_only_and_high_confidence_is_not_affected():
    evidence = [ev("import", "merge"), ev("call", "merge", 4)]
    f = _assess(DEP, VULN, evidence, [], symbols())
    assert f.verdict is Verdict.NOT_AFFECTED
    assert {e.line for e in f.evidence} == {1, 4}  # cites what it relied on


@pytest.mark.parametrize("confidence", ["medium", "low"])
def test_not_affected_needs_high_confidence(confidence):
    evidence = [ev("import", "merge"), ev("call", "merge", 4)]
    f = _assess(DEP, VULN, evidence, [], symbols(confidence))
    assert f.verdict is Verdict.INCONCLUSIVE


def test_opaque_use_of_whole_module_blocks_not_affected():
    evidence = [ev("import", "default"), ev("ref", "default", 3), ev("call", "merge", 4)]
    f = _assess(DEP, VULN, evidence, [], symbols())
    assert f.verdict is Verdict.INCONCLUSIVE
    assert "hide which member" in f.notes


def test_untracked_module_escape_blocks_not_affected():
    f = _assess(DEP, VULN, [ev("escape", "*")], [], symbols())
    assert f.verdict is Verdict.INCONCLUSIVE


def test_dynamic_code_blocks_not_affected():
    dynamic = [Evidence("a.js", 9, "require(x)", "dynamic")]
    f = _assess(DEP, VULN, [ev("import", "merge")], dynamic, symbols())
    assert f.verdict is Verdict.INCONCLUSIVE
    assert "dynamic" in f.notes


def test_dynamic_code_does_not_hide_a_confirmed_hit():
    dynamic = [Evidence("a.js", 9, "require(x)", "dynamic")]
    f = _assess(DEP, VULN, [ev("import", "template"), ev("call", "template", 2)], dynamic, symbols())
    assert f.verdict is Verdict.AFFECTED


def test_imported_vulnerable_symbol_without_call_stays_inconclusive():
    f = _assess(DEP, VULN, [ev("import", "template")], [], symbols())
    assert f.verdict is Verdict.INCONCLUSIVE
    assert "no call found" in f.notes


def test_transitive_and_never_imported_are_never_not_affected():
    transitive = Dependency("npm", "nested", "1.0.0", direct=False)
    assert _assess(transitive, VULN, [ev("import", "merge")], [], symbols()).verdict is Verdict.INCONCLUSIVE
    assert _assess(DEP, VULN, [], [], symbols()).verdict is Verdict.INCONCLUSIVE


def test_no_symbols_or_failed_extraction_stays_inconclusive():
    evidence = [ev("import", "merge")]
    assert _assess(DEP, VULN, evidence, [], None).verdict is Verdict.INCONCLUSIVE
    assert _assess(DEP, VULN, evidence, [], VulnerableSymbols()).verdict is Verdict.INCONCLUSIVE
    failed = _assess(DEP, VULN, evidence, [], None, "HTTP 500")
    assert failed.verdict is Verdict.INCONCLUSIVE and "extraction failed (HTTP 500)" in failed.notes


class FakeOSV:
    def vulnerabilities_for(self, deps):
        return {d: [VULN] for d in deps if d.name in {"lodash", "unused-lib", "nested"}}


class FakeExtractor:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.asked = result, error, []

    def extract(self, vuln):
        self.asked.append(vuln.id)
        if self.error:
            raise self.error
        return self.result


def test_scan_consults_llm_for_imported_direct_and_transitive_dependencies():
    extractor = FakeExtractor(symbols(name="nothing_used"))
    result = scan_project(FIXTURE, osv=FakeOSV(), extractor=extractor)

    # lodash (imported) and nested (transitive); never unused-lib (direct, never imported)
    assert extractor.asked == ["GHSA-1", "GHSA-1"]
    verdicts = {f.dependency.name: f.verdict for f in result.findings}
    assert verdicts["unused-lib"] is Verdict.INCONCLUSIVE
    assert verdicts["nested"] is Verdict.INCONCLUSIVE


def test_scan_survives_llm_failure():
    extractor = FakeExtractor(error=LLMError("OpenAI request failed with HTTP 429"))
    result = scan_project(FIXTURE, osv=FakeOSV(), extractor=extractor)
    lodash = next(f for f in result.findings if f.dependency.name == "lodash")
    assert lodash.verdict is Verdict.INCONCLUSIVE
    assert "extraction failed" in lodash.notes


def test_cli_llm_without_api_key_exits_with_2(monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert cli.main(["scan", ".", "--llm", "openai"]) == 2
    assert "OPENAI_API_KEY" in capsys.readouterr().err


def test_same_name_method_on_untyped_receiver_blocks_not_affected():
    evidence = [ev("import", "merge"), ev("call", "merge", 4)]
    unattributed = {"template": [Evidence("b.js", 9, "p.template(x)", "maybe", "template")]}
    f = _assess(DEP, VULN, evidence, [], symbols(), unattributed=unattributed)
    assert f.verdict is Verdict.INCONCLUSIVE
    assert "template() on a receiver of unknown type (b.js:9)" in f.notes

    unrelated = {"debounce": [Evidence("b.js", 9, "p.debounce(x)", "maybe", "debounce")]}
    assert _assess(DEP, VULN, evidence, [], symbols(), unattributed=unrelated).verdict is Verdict.NOT_AFFECTED


def test_reasons_explain_each_inconclusive_verdict():
    imported = [ev("import", "merge"), ev("call", "merge", 4)]
    transitive = Dependency("npm", "lodash", "4.17.15", direct=False)

    assert _assess(DEP, VULN, imported).reasons == ["symbol-unknown"]
    assert _assess(DEP, VULN, imported, llm_error="boom").reasons == ["llm-error"]
    assert _assess(DEP, VULN, []).reasons == ["not-imported"]
    assert _assess(transitive, VULN, [], dev_only=True).reasons == ["transitive-unanalysed", "dev-only"]
    assert _assess(DEP, VULN, imported, [], symbols(confidence="medium")).reasons == ["low-confidence"]
    assert _assess(DEP, VULN, [ev("import", "template")], [], symbols()).reasons == ["imported-unused"]
    assert _assess(DEP, VULN, [ev("import", "*"), ev("call", "*", 2)], [], symbols()).reasons == ["whole-module-use"]
    assert _assess(DEP, VULN, imported, [ev("dynamic", None)], symbols()).reasons == ["dynamic-code"]


def test_conclusive_verdicts_have_no_reasons():
    assert _assess(DEP, VULN, [ev("import", "merge")], [], symbols()).reasons == []
    assert _assess(DEP, VULN, [ev("import", "template"), ev("call", "template", 5)], [], symbols()).reasons == []
