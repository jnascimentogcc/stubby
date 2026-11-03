"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

from . import __version__
from .bench import compute_metrics, format_report, load_cases, run_cases
from .llm.base import LLMError
from .llm.openai import OpenAIProvider
from .report import render_report
from .scan import scan_project
from .symbols import SymbolExtractor
from .vex import build_vex


_DESCRIPTION = """Reachability analysis for vulnerable dependencies, with OpenVEX output.

Stubby reads a project's lockfile, looks up known vulnerabilities on OSV.dev and
checks whether the project's code (and the packages that depend on the
vulnerable one) can reach the vulnerable code. Each finding becomes an OpenVEX
statement: affected, not_affected or under_investigation (inconclusive).
The output is a draft for human review, never a guarantee."""

_EPILOG = """supported projects (the first match wins, in this order):
  npm      package-lock.json
  Python   poetry.lock, a pinned requirements.txt, or `==` pins in pyproject.toml
  Java     pom.xml (+ dependency-tree.txt from `mvn dependency:tree`) or gradle.lockfile

examples:
  stubby scan .                                   report findings on the terminal
  stubby scan . -o vex.json                       also write an OpenVEX file
  stubby scan . --llm openai -o vex.json          identify the vulnerable functions with an LLM
  stubby report vex.json                          turn the VEX file into vex.html
  stubby bench                                    run the offline benchmark

run `stubby <command> --help` for the options of a command."""

_SCAN_EPILOG = """how verdicts are decided:
  affected       the project calls a vulnerable function (needs --llm to know which)
  not_affected   a vulnerable function is named, with high confidence, and neither the
                 project nor any package that requires the dependency uses it
  inconclusive   anything else; the reason is printed and written to the VEX file
                 (x-stubby-reasons) so you can see what is missing

for best results install the project's dependencies first (npm install, a .venv for
Python, downloaded jars for Java): their code is inspected, too.

environment:
  OPENAI_API_KEY     API key read by --llm openai
  STUBBY_LLM_MODEL   model used by --llm when --llm-model is not given

exit status:
  0  scan finished (whatever the verdicts)
  2  invalid input: unsupported project, unreadable file, or LLM error (e.g. no API key)
  3  network failure while reaching OSV.dev"""

_BENCH_EPILOG = """exit status:
  0  no false not_affected (a not_affected on a case that is really affected or inconclusive)
  1  at least one false not_affected, or --strict and some case misses its expected verdict
  2  no cases found, or LLM error
  3  network failure (with --live)"""

_REPORT_EPILOG = """The page is standalone (no network, no external files): it lists every finding with
its verdict, advisory link and title, and the reasons it is inconclusive, and can be
filtered by verdict, reason or text.

exit status:
  0  report written
  2  the file cannot be read or is not an OpenVEX document"""


def build_parser() -> argparse.ArgumentParser:
    fmt = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(
        prog="stubby", description=_DESCRIPTION, epilog=_EPILOG, formatter_class=fmt
    )
    parser.add_argument("--version", action="version", version=f"stubby {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>", title="commands")

    scan = sub.add_parser(
        "scan",
        help="scan a project and emit an OpenVEX document",
        description="Scan a project for vulnerable dependencies and judge whether its code can reach them.",
        epilog=_SCAN_EPILOG,
        formatter_class=fmt,
    )
    scan.add_argument(
        "path", type=Path, nargs="?", default=Path("."), metavar="PATH",
        help="project directory (default: the current directory)",
    )
    out = scan.add_argument_group("output")
    out.add_argument(
        "-o", "--output", type=Path, metavar="FILE",
        help="write the OpenVEX JSON to FILE (without it, findings are only printed)",
    )
    out.add_argument(
        "--author", default="stubby", metavar="NAME",
        help="author field of the VEX document (default: %(default)s)",
    )
    out.add_argument(
        "-q", "--quiet", action="store_true",
        help="do not print progress to stderr (findings and errors are still printed)",
    )
    llm = scan.add_argument_group(
        "vulnerable-symbol identification",
        "Without --llm the tool cannot tell which function is vulnerable, so findings stay inconclusive.",
    )
    llm.add_argument(
        "--llm", choices=["openai"], metavar="PROVIDER",
        help="identify the vulnerable functions from the advisory text and fix diff with this "
        "provider (choices: openai; reads OPENAI_API_KEY). Only public advisory data is "
        "sent, never your code. Each symbol must be backed by a verbatim quote or it is dropped",
    )
    llm.add_argument(
        "--llm-model", metavar="MODEL",
        help="model for --llm (default: $STUBBY_LLM_MODEL, else gpt-4o-mini)",
    )
    llm.add_argument(
        "--no-fix-diff", action="store_true",
        help="do not download fix-commit diffs from GitHub; use the advisory text only",
    )
    llm.add_argument(
        "--cache-dir", type=Path, default=Path.home() / ".cache" / "stubby" / "symbols", metavar="DIR",
        help="where extracted symbols are cached (default: %(default)s)",
    )
    env = scan.add_argument_group("installed dependencies")
    env.add_argument(
        "--site-packages", type=Path, metavar="DIR",
        help="Python: site-packages of the environment to inspect "
        "(default: .venv, venv or env inside the project)",
    )
    env.add_argument(
        "--repository", type=Path, metavar="DIR",
        help="Java: Maven repository or Gradle cache holding the dependency jars "
        "(default: .m2/repository in the project, ~/.m2/repository and ~/.gradle)",
    )

    report = sub.add_parser(
        "report",
        help="turn an OpenVEX file written by `scan` into an HTML page",
        description="Render an OpenVEX file written by `stubby scan` as a standalone HTML page.",
        epilog=_REPORT_EPILOG,
        formatter_class=fmt,
    )
    report.add_argument("vex", type=Path, metavar="VEX", help="OpenVEX JSON file")
    report.add_argument(
        "-o", "--output", type=Path, metavar="FILE",
        help="HTML file to write (default: the input name with an .html extension)",
    )

    bench = sub.add_parser(
        "bench",
        help="run the benchmark cases and report precision/recall",
        description="Replay the benchmark cases (real advisories, small projects, expected verdicts) "
        "and report precision and recall per verdict.",
        epilog=_BENCH_EPILOG,
        formatter_class=fmt,
    )
    bench.add_argument(
        "path", type=Path, nargs="?", default=Path("benchmarks/cases"), metavar="PATH",
        help="directory of cases (default: %(default)s)",
    )
    bench.add_argument(
        "--live", choices=["openai"], metavar="PROVIDER",
        help="ask a real LLM (choices: openai) instead of replaying the recorded answers",
    )
    bench.add_argument("--llm-model", metavar="MODEL", help="model for --live")
    bench.add_argument(
        "--strict", action="store_true",
        help="also fail when a case misses its expected verdict (known gaps included)",
    )
    return parser


def _run_bench(args: argparse.Namespace) -> int:
    cases = load_cases(args.path)
    if not cases:
        print(f"error: no cases found in {args.path}", file=sys.stderr)
        return 2
    provider = OpenAIProvider(model=args.llm_model) if args.live else None
    results = run_cases(cases, provider)
    print(format_report(results))
    metrics = compute_metrics(results)
    if metrics.unsafe:
        return 1
    return 1 if args.strict and metrics.correct != metrics.total else 0


def _build_extractor(args: argparse.Namespace) -> SymbolExtractor | None:
    if args.llm is None:
        return None
    provider = OpenAIProvider(model=args.llm_model)
    print(
        f"note: sending advisory text and public fix diffs to {provider.name}; "
        "your source code is not sent.",
        file=sys.stderr,
    )
    return SymbolExtractor(provider, use_fix_diff=not args.no_fix_diff, cache_dir=args.cache_dir)


def _progress(quiet: bool):
    """Progress on stderr: stages as lines, per-item updates rewrite one line on a terminal."""
    if quiet:
        return None
    tty = sys.stderr.isatty()
    state = {"transient": False}

    def report(message: str, transient: bool = False) -> None:
        if transient:
            if tty:
                print(f"\r\x1b[K  {message[:100]}", end="", file=sys.stderr, flush=True)
                state["transient"] = True
            return
        if state["transient"]:
            print("\r\x1b[K", end="", file=sys.stderr)
            state["transient"] = False
        print(f"... {message}", file=sys.stderr, flush=True)

    return report


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "bench":
        try:
            return _run_bench(args)
        except LLMError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except httpx.HTTPError as exc:
            print(f"error: network failure: {exc}", file=sys.stderr)
            return 3

    if args.command == "report":
        try:
            vex = json.loads(args.vex.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {args.vex}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(vex, dict) or "statements" not in vex:
            print(f"error: {args.vex} is not an OpenVEX document", file=sys.stderr)
            return 2
        output = args.output or args.vex.with_suffix(".html")
        output.write_text(render_report(vex), encoding="utf-8")
        print(f"Report written to {output}", file=sys.stderr)
        return 0

    if args.command == "scan":
        try:
            extractor = _build_extractor(args)
            result = scan_project(
                args.path, extractor=extractor, site_packages=args.site_packages, repository=args.repository,
                progress=_progress(args.quiet),
            )
        except LLMError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except httpx.HTTPError as exc:
            print(f"error: could not reach OSV.dev: {exc}", file=sys.stderr)
            return 3

        for f in result.findings:
            print(
                f"{f.dependency.name}@{f.dependency.version}  "
                f"{f.vulnerability.display_id}  {f.verdict.value}  {f.notes}"
            )
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        dev = sum(1 for f in result.findings if f.dev_only)
        suffix = f", {dev} only in development dependencies." if dev else "."
        print(f"\n{len(result.findings)} finding(s){suffix}", file=sys.stderr)

        vex = build_vex(result, author=args.author)
        if args.output:
            args.output.write_text(json.dumps(vex, indent=2) + "\n", encoding="utf-8")
            print(f"OpenVEX written to {args.output}", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
