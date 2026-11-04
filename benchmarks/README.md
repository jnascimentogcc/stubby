# Benchmark

Real advisories, tiny projects and the verdict a careful human would give. The
suite measures whether Stubby's verdicts can be trusted; its one hard rule is
**zero false `not_affected`**, which fails the run (exit code 1).

```bash
stubby bench                      # replay recorded LLM answers, fully offline
stubby bench --strict             # also fail on any missed verdict
stubby bench --live openai        # ask a real model (needs OPENAI_API_KEY)
```

The report lists each case, the number of matches, and precision and recall per
verdict. Cases marked `gap` are known limitations: the tool is cautious
(`inconclusive`) where a human could be definite. They are kept on purpose and
shown with the reason.

## Adding a case

Create `cases/<id>/` with:

```
case.json
project/
  package-lock.json                     npm, or poetry.lock / requirements.txt for Python
  src/...                               the code under test
  node_modules/ or .venv/...            installed dependencies, when dependents matter
  pom.xml + dependency-tree.txt         Maven, or gradle.lockfile for Gradle
  .m2/repository/...                    fake jars (zip files with minimal class files) for Java
  composer.json + composer.lock         PHP, with the packages' code under vendor/<vendor>/<name>/
```

A Python case needs a (fake) environment at `project/.venv/lib/python3.12/site-packages`
with a `<name>-<version>.dist-info/{METADATA,RECORD}` per package; without one the
tool correctly refuses to rule anything out.

`case.json`:

| Field | Meaning |
| --- | --- |
| `description` | What the case demonstrates |
| `package` | Affected package name in the lockfile |
| `expected` | `affected`, `not_affected` or `inconclusive`: the correct answer for a human, not what the tool says today |
| `vulnerability` | The OSV record (`id`, `aliases`, `summary`, `details`, `references`), copied from `https://api.osv.dev/v1/vulns/<id>` |
| `llm_response` | The model answer to replay: `confidence` and `symbols` (`name`, `module`, `quote`); every `quote` must appear verbatim in the advisory |
| `known_gap` | Optional. Why the tool cannot reach `expected` yet. The test suite fails once the gap is fixed, as a cue to remove it |

Use a real advisory, keep the project minimal, and prefer cases that stress a
single behaviour (a call, a dynamic import, a re-export, ...).
