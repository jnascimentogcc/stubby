# stubby

Most vulnerability scanners tell you *"dependency X has CVE-Y"*. Few tell you
whether **your code can actually reach the vulnerable code**. Stubby answers
that question and records the answer as an [OpenVEX](https://openvex.dev)
document you can review, version and share.

> **Early MVP (v0.7).** JS/TS projects (npm `package-lock.json`), Python projects
> (`poetry.lock` or pinned `requirements.txt`) and Java projects (Maven `pom.xml`
> or Gradle `gradle.lockfile`). Verdicts
> are drafts for human review. Without `--llm`, findings are reported as
> `under_investigation`.

## Quick start

```bash
pip install stubby-vex

stubby scan path/to/js-project -o vex.json
stubby report vex.json            # optional: a standalone HTML page, with links to each advisory
```

Requires network access to `api.osv.dev`. Install your dependencies first (`npm install`, a `.venv` for Python, or `mvn dependency:tree` and `mvn dependency:resolve` for Java) so Stubby can also inspect the packages that depend on a vulnerable one. To also identify which function of
each package is vulnerable, add `--llm openai` (reads `OPENAI_API_KEY`). Only
public advisory text and fix diffs are sent, never your code. Example output:

```
lodash@4.17.15  CVE-2020-8203  inconclusive  imported in 3 file(s); members used: merge, template; 4 call site(s); vulnerable symbol not identified yet
```

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
and line, and the output is a draft for human review, never a guarantee. See
[docs/architecture.md](docs/architecture.md) for details.

## Roadmap

- [x] v0.1 – npm lockfile, OSV lookup, import-level detection, OpenVEX output
- [x] v0.2 – tree-sitter based JS/TS analysis (named imports, call sites)
- [x] v0.3 – LLM symbol extraction from advisory text and fix-commit diff
- [x] v0.4 – benchmark suite (known CVEs, expected verdicts)
- [x] v0.5 – transitive dependencies
- [x] v0.6 – Python adapter
- [x] v0.7 – Java adapter

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
