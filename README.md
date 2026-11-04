# stubby

Most vulnerability scanners tell you *"dependency X has CVE-Y"*. Few tell you
whether **your code can actually reach the vulnerable code**. Stubby answers
that question and records the answer as an [OpenVEX](https://openvex.dev)
document you can review, version and share.

> **Early MVP (v0.9).** JS/TS projects (npm `package-lock.json`), Python projects
> (`poetry.lock`, pinned `requirements.txt` or `==` pins in `pyproject.toml`) and
> Java projects (Maven `pom.xml` or Gradle `gradle.lockfile`) and PHP projects
> (`composer.lock`). Verdicts are drafts for human review. Without `--llm`, findings are reported as `under_investigation`.

## Quick start

```bash
pip install stubby-vex

stubby scan path/to/js-project -o vex.json
stubby report vex.json            # optional: a standalone HTML page to browse the findings
```

Requires network access to `api.osv.dev`. Install your dependencies first (`npm install`, a `.venv` for Python, `mvn dependency:tree` and `mvn dependency:resolve` for Java, or `composer install` for PHP) so Stubby can also inspect the packages that depend on a vulnerable one. To also identify which function of
each package is vulnerable, add `--llm openai` (reads `OPENAI_API_KEY`). Only
public advisory text and fix diffs are sent, never your code. Example output:

```
lodash@4.17.15  CVE-2020-8203  inconclusive  imported in 3 file(s); members used: merge, template; 4 call site(s); vulnerable symbol not identified
```

## Command line

`stubby <command> --help` prints the full help of each command.

**`stubby scan [PATH]`** scans a project (default: the current directory) and prints the findings.

| Option | Meaning |
|---|---|
| `-o, --output FILE` | also write the OpenVEX JSON to `FILE` |
| `--author NAME` | author field of the VEX document (default `stubby`) |
| `-q, --quiet` | no progress on stderr (findings and errors are still printed) |
| `--llm PROVIDER` | identify the vulnerable functions with an LLM (`openai`, reads `OPENAI_API_KEY`) |
| `--llm-model MODEL` | model for `--llm` (default `$STUBBY_LLM_MODEL`, else `gpt-4o-mini`) |
| `--no-fix-diff` | do not download fix-commit diffs from GitHub; use the advisory text only |
| `--cache-dir DIR` | where extracted symbols are cached (default `~/.cache/stubby/symbols`) |
| `--site-packages DIR` | Python: site-packages to inspect (default `.venv`, `venv` or `env` in the project) |
| `--repository DIR` | Java: Maven repository or Gradle cache with the jars (default `.m2/repository`, `~/.m2/repository`, `~/.gradle`) |

**`stubby report VEX [-o FILE]`** renders an OpenVEX file written by `scan` as a standalone
HTML page (default: the input name with `.html`). It can be filtered by verdict, reason or text.

**`stubby bench [PATH] [--live PROVIDER] [--llm-model MODEL] [--strict]`** replays the benchmark
cases offline and reports precision and recall per verdict. `--live` asks a real LLM instead
of replaying the recorded answers; `--strict` also fails on cases that miss their expected verdict.

Exit status: `scan` and `report` return `0` on success and `2` on invalid input (unsupported
project, unreadable file, LLM error); `scan` returns `3` when OSV.dev cannot be reached.
`bench` returns `0` when no case is a false `not_affected`, `1` otherwise (or with `--strict`
when a case misses), `2` when no cases are found or the LLM fails, and `3` on network failure.

## Why

- Scanners produce hundreds of alerts, most of them irrelevant to how a project
  uses a library.
- Regulation (e.g. the EU Cyber Resilience Act) increasingly asks for VEX
  statements, and almost nobody generates them automatically.
- Advisories rarely say *which function* is dangerous in a structured way.

## How it works

Stubby reads your lockfile, looks up known vulnerabilities on
[OSV.dev](https://osv.dev), and checks how your code uses each affected
package. Every verdict (`affected`, `not_affected` or `inconclusive`) cites file
and line, and the output is a draft for human review, never a guarantee. When
Stubby cannot rule a package out it says why (for example the advisory names no
function, or the whole module is used), in the VEX and in the HTML report, which
also links each finding to its advisory. See
[docs/architecture.md](docs/architecture.md) for details.

## Roadmap

- [x] v0.1 – npm lockfile, OSV lookup, import-level detection, OpenVEX output
- [x] v0.2 – tree-sitter based JS/TS analysis (named imports, call sites)
- [x] v0.3 – LLM symbol extraction from advisory text and fix-commit diff
- [x] v0.4 – benchmark suite (known CVEs, expected verdicts)
- [x] v0.5 – transitive dependencies
- [x] v0.6 – Python adapter
- [x] v0.7 – Java adapter
- [x] v0.8 – HTML report, advisory links, reasons for inconclusive findings
- [x] v0.9 – reachability inside the package (npm, Python, Java)

## Why "Stubby"?

Named after [Sergeant Stubby](https://pt.wikipedia.org/wiki/Stubby), the dog who
served with the US 102nd Infantry Regiment in World War I. He is remembered for
sensing danger, such as incoming gas attacks, before the soldiers did. The tool
aims to do the same for your dependencies: raise the alarm only for the
vulnerabilities that can actually reach your code.

## Contributing

Benchmark cases (a real CVE, a small project, the expected verdict) are the
most valuable contribution; see [benchmarks/](benchmarks/README.md). Open an issue to discuss before large changes.

## License

Apache-2.0
