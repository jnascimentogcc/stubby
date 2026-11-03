# Architecture

## Pipeline

```
lockfile ──► dependencies ──► OSV.dev ──► vulnerabilities
                                              │
                    (--llm) LLM: advisory + fix diff ──► vulnerable symbols
                                              │
 source code ──► tree-sitter ──► imports / call sites ─┤
                                              ▼
                              verdict + evidence ──► OpenVEX
```

What exists today: lockfile parsing, OSV lookup, tree-sitter analysis of JS/TS
(imports, bound members, call sites, dynamic code), optional LLM extraction of
vulnerable symbols, OpenVEX output. Without validated vulnerable symbols every
verdict stays `inconclusive`.

## Vulnerable symbols (`--llm`)

`symbols.SymbolExtractor` sends only the advisory text and the public fix diff
(`fixes.py`, GitHub commits/PRs only, truncated) to an `LLMProvider`; project
source is never sent, and it is only called for direct dependencies the project
imports. The model only proposes: each symbol must carry a verbatim quote from
the advisory or diff that contains the symbol as a whole word, otherwise it is
dropped, and any dropped proposal caps confidence at `medium`. Results are
cached on disk (`--cache-dir`) by advisory, model and prompt version.

`scan._assess` then decides:

- `affected`: a call or reference to a vulnerable symbol (or its sub-module).
- `not_affected`: only with *high* confidence, a direct imported dependency, no
  dynamic code, no use of the whole module that hides the member (`ref` or
  `escape` evidence), and no vulnerable symbol used. The evidence cited is the
  package's imports and calls.
- `inconclusive`: everything else, including transitive or never-imported
  dependencies and LLM failures.

Known gap: an advisory names the vulnerable function, but the package may reach
it through other public members. `not_affected` is therefore a draft to review.

## Transitive dependencies

`graph.py` models who requires whom from the lockfile (v2/v3, using Node's
resolution: nested `node_modules` first, then the parents'). For a vulnerable
package, `scan._collect_dependents` analyses the installed code
(`node_modules/<pkg>`, including `dist/`) of every package that directly
requires it, with the same tree-sitter analysis used for the project. Dependents
are inspected for direct dependencies too, since the project and a library can
share one copy of the vulnerable package.

- A dependent that uses a vulnerable symbol, uses the module opaquely, loads
  modules dynamically, is not installed, or could not be fully analysed keeps
  the finding `inconclusive` (the first case cites file and line).
- If every dependent is clear (and confidence is high), a transitive dependency
  becomes `not_affected`. It never becomes `affected`: the project reaching the
  dependent's code path is not known.
- Notes show the shortest chain from the project (`via a > b`) and flag
  packages required only by `devDependencies`.

## Python

`PythonAdapter` reads `poetry.lock` (with `pyproject.toml` to tell direct
dependencies from transitive ones) or a pinned `requirements.txt` (`-r`
includes, pip-compile `# via` annotations; unpinned lines are skipped with a
warning). Imports name modules, not distributions, so modules are mapped to
distributions through the `RECORD` files of an installed environment (`.venv`,
`venv` or `env` in the project, or `--site-packages`). That environment is also
the source of the dependency graph for requirements files (`Requires-Dist`) and
of the installed code of dependents, so the rules of the section above apply
unchanged.

Without an installed environment Stubby falls back to name guesses and an alias
table (`yaml` -> `pyyaml`). Any import it cannot attribute to a distribution is
reported as unresolved (like dynamic code), and dependents cannot be inspected,
so nothing is ruled out and a warning says so. Python specifics:

- `from pkg import name` may bind a function, a class or a submodule. Both `name`
  and the first attribute used (`name.member`) are reported. A bare reference to
  `name` counts as whole-module use only when `pkg.name` is a module in the
  environment, so passing a class around does not block `not_affected`.
- Imports under `if TYPE_CHECKING:` and relative imports are ignored.
- `__import__`, `importlib.import_module` with a variable, `exec` and `eval`
  count as dynamic code.
- Not covered: `*.egg-info` environments (no `RECORD`), `Pipfile.lock`, wildcard
  re-exports and reflection beyond `getattr` on a tracked name.

## Benchmark

`bench.py` runs the cases in `benchmarks/cases/` through the real `scan_project`
with a static OSV and a replayed LLM answer, then reports precision and recall
per verdict. A false `not_affected` fails the run and the test suite. See
`benchmarks/README.md` for the case format.

## Evidence

Each `Evidence` has a `kind`: `import`, `call`, `ref` (binding used without a
call) or `dynamic` (`require(name)`, `import(expr)`, `eval`, which cannot be
tied to a package). Dynamic sites weaken any "not used" conclusion. Type-only
imports are ignored (erased at runtime); scoping is ignored on purpose, so
shadowed names over-report rather than hide usage. Files with syntax errors
also get a regex scan so an import is never lost.

## Layout

```
src/stubby/
  models.py          dataclasses: Dependency, Vulnerability, Finding, Evidence
  lockfiles/npm.py   package-lock.json (v1/v2/v3) parser
  lockfiles/python.py poetry.lock, requirements.txt, pyproject.toml readers
  osv.py             OSV.dev client
  pyenv.py           installed Python environment index (RECORD, METADATA)
  analyzers/
    base.py          LanguageAdapter protocol (one adapter per language)
    javascript.py    JS/TS/Node adapter (file walk, regex fallback)
    js_ast.py        tree-sitter analysis of one JS/TS file
    python.py        Python adapter (module -> distribution mapping)
    py_ast.py        tree-sitter analysis of one Python file
    observations.py  what a file analysis reports (shared)
  llm/base.py        LLM provider protocol; llm/openai.py is the OpenAI provider
  symbols.py         vulnerable-symbol extraction, validation and cache
  graph.py           dependency graph (who requires whom)
  fixes.py           fix-commit diff fetching
  bench.py           benchmark runner and metrics
  scan.py            orchestration
  vex.py             OpenVEX writer
  cli.py             command line
```

Adding a language means implementing `LanguageAdapter` (lockfile parsing and
`analyze`, which returns a `UsageReport`) and registering it in `scan.ADAPTERS`.

## Design principles

1. **Deterministic first, LLM second.** The LLM extracts the vulnerable symbol
   from advisory text; static analysis decides whether your code reaches it.
   The LLM only sees minimal snippets, and only for ambiguous cases.
2. **Never give false comfort.** Three verdicts: `affected`,
   `not_affected` (only with cited evidence) and `inconclusive`. Dynamic code
   (`eval`, dynamic `import()`, reflection, `getattr`) lowers confidence.
3. **Evidence or it didn't happen.** Every verdict cites file and line.
4. **Output is a draft for human review**, not a security guarantee.
5. **Provider-agnostic LLM layer** (OpenAI first, local models later), and
   privacy-minded: never upload the whole repository.

## Limitations

- Transitive reachability stops at the package that directly requires the
  vulnerable one: if it uses a vulnerable symbol the finding stays
  `inconclusive`, because reaching it from the project needs a call graph.
- Transpiled interop wrappers (`_interopRequireDefault(require('x'))`) look like
  whole-module use, and any non-relative dynamic `require` in a dependent blocks
  `not_affected`; both err on the cautious side.
- Lockfile v1 has no install locations, so dependents are unknown there.
- A scan covers one ecosystem: npm wins when both `package-lock.json` and a Python lockfile exist.
- Symbol extraction depends on advisory quality; many advisories name no symbol.
- Dynamic features defeat static analysis and must yield `inconclusive`.
- OSV data quality varies; some advisories name no affected symbol.
