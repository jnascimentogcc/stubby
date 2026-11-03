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
from .scan import scan_project
from .symbols import SymbolExtractor
from .vex import build_vex


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stubby",
        description="Reachability analysis for vulnerable dependencies, with OpenVEX output.",
    )
    parser.add_argument("--version", action="version", version=f"stubby {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a project and emit an OpenVEX document")
    scan.add_argument("path", type=Path, nargs="?", default=Path("."), help="project directory")
    scan.add_argument("-o", "--output", type=Path, help="write OpenVEX JSON to this file")
    scan.add_argument("--author", default="stubby", help="author field of the VEX document")
    scan.add_argument(
        "--llm",
        choices=["openai"],
        help="identify vulnerable symbols from advisory text and fix diffs with this provider "
        "(sends public advisory data only, never your code; OpenAI reads OPENAI_API_KEY)",
    )
    scan.add_argument("--llm-model", help="model name for --llm (default: provider's default)")
    scan.add_argument(
        "--repository",
        type=Path,
        help="Maven repository or Gradle cache holding the dependency jars of a Java project "
        "(default: ~/.m2, ~/.gradle and .m2/repository in the project)",
    )
    scan.add_argument(
        "--site-packages",
        type=Path,
        help="site-packages of the Python environment to inspect "
        "(default: .venv, venv or env inside the project)",
    )
    scan.add_argument(
        "--no-fix-diff", action="store_true", help="do not fetch fix-commit diffs from GitHub"
    )
    scan.add_argument(
        "--cache-dir",
        type=Path,
        default=Path.home() / ".cache" / "stubby" / "symbols",
        help="where extracted symbols are cached (default: %(default)s)",
    )

    bench = sub.add_parser("bench", help="run the benchmark cases and report precision/recall")
    bench.add_argument(
        "path", type=Path, nargs="?", default=Path("benchmarks/cases"), help="directory of cases"
    )
    bench.add_argument(
        "--live",
        choices=["openai"],
        help="ask a real LLM instead of replaying the recorded answers",
    )
    bench.add_argument("--llm-model", help="model name for --live")
    bench.add_argument(
        "--strict",
        action="store_true",
        help="also fail on cases that miss their expected verdict (known gaps included)",
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

    if args.command == "scan":
        try:
            extractor = _build_extractor(args)
            result = scan_project(
                args.path, extractor=extractor, site_packages=args.site_packages, repository=args.repository
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
        print(f"\n{len(result.findings)} finding(s).", file=sys.stderr)

        vex = build_vex(result, author=args.author)
        if args.output:
            args.output.write_text(json.dumps(vex, indent=2) + "\n", encoding="utf-8")
            print(f"OpenVEX written to {args.output}", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
