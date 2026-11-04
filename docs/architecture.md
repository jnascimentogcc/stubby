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

## Java

`JavaAdapter` reads `pom.xml` (direct dependencies; properties and
`dependencyManagement` are interpolated, unresolved versions are warned about,
`test` scope counts as dev) and, when present, the output of
`mvn dependency:tree -DoutputFile=dependency-tree.txt`, which supplies the
transitive dependencies and the graph. `gradle.lockfile` gives the resolved
versions but no graph, so dependents stay unknown there. Source files import
classes, not artifacts, so classes are mapped to artifacts through the jars
Maven or Gradle downloaded (`~/.m2`, the Gradle cache, `.m2/repository` in the
project, or `--repository`); a jar also supplies the bytecode of dependents,
read from the constant pool of its `.class` files (methods called, classes
referenced, reflection entry points). Java specifics:

- Receivers are typed from their declarations (locals, fields, parameters,
  `new X()`), so `yaml.load(..)` is attributed to the class of `yaml`. Receivers
  that cannot be typed (`var x = f()`, chained calls) are recorded by method name
  and block `not_affected` when the name matches a vulnerable symbol.
- Wildcard imports, `Class.forName`, `loadClass` and `ServiceLoader.load` are
  opaque. A fully qualified name written inline counts as use.
- A dependency whose jar is missing makes the project analysis incomplete, so
  nothing is ruled out until the jars are available.
- Not covered: Kotlin and other JVM languages (a warning is issued), Gradle
  version catalogs and dynamic versions, shaded or repackaged classes.

## PHP

`PhpAdapter` reads `composer.lock` (versions, `packages-dev` as development
scope) and `composer.json` (which packages are direct; platform requirements such
as `php` and `ext-*` are ignored). The lockfile has no requirement graph, but
each locked package lists what it requires, which gives the graph. Code names
classes by namespace, not package, so a class is mapped to its package through
the PSR-4/PSR-0 prefixes of the lockfile and the class map Composer writes to
`vendor/composer/autoload_classmap.php`; the code of every package is read from
`vendor/` (`composer install`). PHP specifics:

- `new Foo` is a call of `Foo`, `Foo::bar()` a call of `bar`, and type hints,
  `extends`, `implements`, traits and `instanceof` are references. `use`
  statements (including group, aliased and `use function`) resolve names; an
  unqualified class that was not imported is PHP's own or local.
- A method call on an untyped value (`$x->parse()`) is recorded by method name and
  blocks `not_affected` when the name matches a vulnerable symbol.
- `new $class`, `$callable()`, `$object->$method()`, `eval`, `unserialize`,
  `call_user_func*` and non-literal `include`/`require` are dynamic code. A
  namespaced class that no package provides and the project does not define is
  unresolved code, which also blocks `not_affected`.
- The package graph treats strings that look like class or method names as
  mentions, because PHP passes callables as strings (`'Foo::bar'`).
- Not covered: Composer plugins and custom installers (packages are read from
  `vendor/<name>`), autoloaded global functions without a namespace, and
  frameworks that wire classes through a container or annotations: the code runs
  without a visible `new`, so those findings tend to stay `inconclusive`.

## Benchmark

`bench.py` runs the cases in `benchmarks/cases/` through the real `scan_project`
with a static OSV and a replayed LLM answer, then reports precision and recall
per verdict. A false `not_affected` fails the run and the test suite. See
`benchmarks/README.md` for the case format.

## Reachability inside a package (npm, Python, Java and PHP)

A project that calls `tar.x()` never names `Unpack`, yet `x` creates one. Matching
the vulnerable symbol only against names the code uses would call that
`not_affected`. For npm, Python, Java and PHP, `not_affected` therefore also needs the installed code of
the vulnerable package: it is reduced to a *name graph* (`reach.py`,
`analyzers/js_reach.py`, `analyzers/py_reach.py`, `analyzers/java_reach.py`, `analyzers/php_reach.py`) where `a -> b` means the definition `a` mentions `b`. The
members the project (and each dependent) uses must not reach a vulnerable symbol
through it. Names are global to the package and unscoped, so the graph can only
over-report reach, never hide it. Code that runs when a module loads is always
reached; callbacks and functions are reached only through their name.

Consequences, each with its own reason code:
- `internal-reach`: the members used may reach a vulnerable symbol internally.
- `symbol-not-found`: the symbol is not in the installed code (for example it only
  exists in the fixed version), so absence of use proves nothing.
- `package-not-installed`: no installed code to check.
- `package-unanalysable`: the package uses `eval` or has files that do not parse.

Whole-module use (`import * as x`, a callable `require`) is still a blocker of its
own. The graph is coarse: minified bundles merge names and some findings that are
really safe stay inconclusive. Python's graph does not model `getattr`, metaclasses or other
attribute-name dispatch. Java's graph is read from the jar's class files and is
class granular: a class and each method it declares reach everything its constant
pool mentions (superclass, classes, methods), and method names are not tied to a
single class. Without the jar (`package-not-installed`) nothing is ruled out.

## Why a finding is inconclusive

Every inconclusive finding carries machine-readable reason codes (`Finding.reasons`,
listed with their meaning in `scan.REASONS`), for example `symbol-unknown`,
`whole-module-use`, `dynamic-code`, `dependent-not-installed` or
`dependent-uses-symbol`. They are written to each VEX statement as the extension
field `x-stubby-reasons`, and `stubby report` shows them as labels with a filter.
Findings reachable only through development dependencies are flagged with the
extension field `x-stubby-scope: development` and keep their verdict: a
vulnerable build tool can still matter, but it is not part of the shipped runtime.

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
  lockfiles/java.py  pom.xml, mvn dependency:tree output, gradle.lockfile readers
  lockfiles/php.py   composer.lock and composer.json readers
  phpvendor.py       Composer vendor/ index (class -> package)
  jars.py            jar locator and class-file constant pool reader
  osv.py             OSV.dev client
  pyenv.py           installed Python environment index (RECORD, METADATA)
  analyzers/
    base.py          LanguageAdapter protocol (one adapter per language)
    javascript.py    JS/TS/Node adapter (file walk, regex fallback)
    js_ast.py        tree-sitter analysis of one JS/TS file
    js_reach.py      name graph of an installed npm package
    py_reach.py      name graph of an installed Python distribution
    java_reach.py    name graph of a dependency jar (from class files)
    python.py        Python adapter (module -> distribution mapping)
    py_ast.py        tree-sitter analysis of one Python file
    java.py          Java adapter (class -> artifact mapping through jars)
    java_ast.py      tree-sitter analysis of one Java file
    php.py           PHP adapter (class -> package through PSR-4 and the class map)
    php_ast.py       tree-sitter analysis of one PHP file
    php_reach.py     name graph of an installed Composer package
    observations.py  what a file analysis reports (shared)
  llm/base.py        LLM provider protocol; llm/openai.py is the OpenAI provider
  symbols.py         vulnerable-symbol extraction, validation and cache
  graph.py           dependency graph (who requires whom)
  reach.py           name graph of one installed package (reachability inside it)
  fixes.py           fix-commit diff fetching
  bench.py           benchmark runner and metrics
  scan.py            orchestration
  vex.py             OpenVEX writer (statements carry the advisory @id link and title)
  report.py          standalone HTML report rendered from a VEX document
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
- A scan covers one ecosystem: npm wins over Python, which wins over Java, which wins over PHP, when several are present (a Laravel project with a `package-lock.json` is scanned as npm).
- Method calls on receivers whose type cannot be determined are matched by name only, so a same-named method on an unrelated object blocks `not_affected` (two benchmark cases document this cost).
- Symbol extraction depends on advisory quality; many advisories name no symbol.
- Dynamic features defeat static analysis and must yield `inconclusive`.
- OSV data quality varies; some advisories name no affected symbol.
