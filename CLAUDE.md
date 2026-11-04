# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`stubby` (named after Sergeant Stubby, the WWI dog) checks whether project code can actually reach vulnerable dependency code and writes the result as an [OpenVEX](https://openvex.dev) document. Early MVP (v0.1): JS/TS projects with an npm `package-lock.json`, import-level analysis only. See README.md for the roadmap.

## Commands

```bash
pip install -e ".[dev]"                 # install with pytest
pytest                                  # all tests (testpaths = tests)
pytest tests/test_pipeline.py::test_vex_document_shape   # single test
stubby scan path/to/js-project -o vex.json             # needs network (api.osv.dev)
stubby bench                            # benchmark (offline); exit 1 on a false not_affected
stubby report vex.json                  # standalone HTML report from a VEX file (report.py)
stubby scan . --site-packages .venv/lib/python3.12/site-packages   # Python: inspect this environment
stubby scan . --repository ~/.m2/repository                        # Java: where the dependency jars live
```

No linter or formatter is configured. Python >= 3.10, hatchling build, runtime dependencies are `httpx`, tree-sitter and its JS/TS/Python/Java/PHP grammars.

## Documentation

README.md is the public showcase of the open-source project: keep it short and clean. Architecture, design principles and limitations live in `docs/architecture.md`; the product vision is in `docs/`.

## Architecture

Pipeline orchestrated by `scan.scan_project`: lockfile -> dependencies -> OSV.dev lookup -> vulnerabilities -> per-finding assessment against detected imports -> OpenVEX (`vex.build_vex`).

- **Language adapters** (`analyzers/base.py`, `LanguageAdapter` Protocol): one per ecosystem, providing `detect`, `load_dependencies` (name, version, deps) and `analyze` (returns a `UsageReport`: `Evidence` per package plus unattributable `dynamic` sites). `scan.ADAPTERS` is the registry; the first adapter whose `detect` matches wins. Adding a language = implement the protocol and register it there.
- **`analyzers/python.py`** (+ `py_ast.py`, `pyenv.py`, `lockfiles/python.py`) is the Python adapter: modules map to distributions via an installed environment's `RECORD`; unattributable imports count as dynamic code. Details in `docs/architecture.md`. **`analyzers/java.py`** (+ `java_ast.py`, `jars.py`, `lockfiles/java.py`) is the Java adapter: classes map to Maven artifacts through downloaded jars and dependents are read from class-file constant pools. **`analyzers/php.py`** (+ `php_ast.py`, `phpvendor.py`, `lockfiles/php.py`) is the PHP adapter: classes map to Composer packages through PSR-4/PSR-0 prefixes and the class map, and package code is read from `vendor/`. **`analyzers/javascript.py`** walks source files (skipping `node_modules`, `dist`, `build`, etc. and `.d.ts`); **`analyzers/js_ast.py`** does the per-file tree-sitter analysis (imports, bound members, call/ref sites, dynamic `require`/`import()`/`eval`). Files with syntax errors also get a regex fallback so imports are never lost. Scoping is ignored on purpose (over-reports, never hides usage).
- **`models.py`**: shared dataclasses (`Dependency`, `Vulnerability`, `Evidence`, `Finding`) and the `Verdict` enum. `Dependency.purl` builds the package URL used in VEX output.
- **`symbols.py`** (+ `fixes.py`, `llm/`): optional (`--llm openai`) extraction of vulnerable symbols; the LLM only proposes, each symbol needs a verbatim advisory/diff quote or it is dropped. Only advisory data is sent, never project code.

## Behavior to preserve

- `scan._assess` yields `INCONCLUSIVE` unless validated vulnerable symbols exist; `NOT_AFFECTED` additionally needs high confidence, a direct imported dep, no dynamic code and no opaque whole-module use (README design principle: never give false comfort; `not_affected` requires cited evidence). Tests in `tests/test_verdicts.py` cover each blocking condition, and `test_scan_never_concludes_not_affected_in_v01` covers the no-LLM path. Direct-but-never-imported deps are only noted as candidates in `notes`.
- Transitive dependencies (`Dependency.direct = False`) are judged through the installed code of the packages that require them (`graph.py`, `scan._collect_dependents`): never `affected`, `not_affected` only if every dependent is installed, fully analysed and clear. Direct dependencies are held to the same check for their dependents.

- For npm, Python, Java and PHP, `not_affected` also needs the installed code of the vulnerable package and a name graph (`reach.py`, `analyzers/js_reach.py`, `analyzers/py_reach.py`, `analyzers/java_reach.py`, `analyzers/php_reach.py`) showing the members used cannot reach the vulnerable symbols (`scan._reach_blockers`).

## Testing

`benchmarks/cases/` holds real-advisory cases (see `benchmarks/README.md`); `tests/test_benchmark.py` runs them and fails on any false `not_affected` or when a `known_gap` case starts passing. Add a case when changing verdict logic.

`tests/test_pipeline.py` uses a `FakeOSV` class in place of `OSVClient` (pass via `scan_project(..., osv=...)`) so tests need no network. Fixture project lives in `tests/fixtures/sample-js/` (including an ignored `node_modules` dir used to verify skipping).
