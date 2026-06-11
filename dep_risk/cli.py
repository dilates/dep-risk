from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress

from dep_risk.cache import get_default_cache
from dep_risk.config import load_config
from dep_risk.report.html import HtmlReporter
from dep_risk.report.terminal import TerminalReporter
from dep_risk.scanner import Scanner, detect_ecosystems

VERSION = "1.0.0"
GITHUB_URL = "https://github.com/dilates"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-risk",
        description="Supply chain risk scorer for npm, pip, and cargo dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        metavar="PATH",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--ecosystem",
        choices=["npm", "pip", "cargo", "auto"],
        default="auto",
        help="Ecosystems to scan (default: auto-detect)",
    )
    parser.add_argument(
        "--min-risk",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Only show packages at or above this risk level",
    )
    parser.add_argument(
        "--include-dev",
        action="store_true",
        default=False,
        help="Include dev dependencies (default: false)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Export HTML report to file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output machine-readable JSON to stdout",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit code 1 if any packages above threshold",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="CI failure threshold (default: high)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass cache, fetch fresh data",
    )
    parser.add_argument(
        "--github-token",
        metavar="TOKEN",
        default=None,
        help="GitHub API token (or set GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Config file path (default: .dep-risk.toml)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Parallel fetch workers (default: 10)",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version info and GitHub link",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show individual scorer breakdowns per package",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"dep-risk v{VERSION}")
        print("Supply chain risk scorer for npm, pip, and cargo dependencies")
        print("Scores maintainer churn, install scripts, typosquatting, and more")
        print(GITHUB_URL)
        return 0

    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    if args.include_dev:
        config.include_dev = True
    if args.no_cache:
        config.no_cache = True
    if args.github_token:
        config.github_token = args.github_token
    if args.workers is not None:
        config.workers = args.workers
    if args.fail_on:
        config.fail_on = args.fail_on

    directory = Path(args.path).resolve()
    if not directory.exists():
        print(f"dep-risk: directory not found: {directory}", file=sys.stderr)
        return 2

    if args.ecosystem == "auto":
        ecosystems = detect_ecosystems(directory)
        if not ecosystems:
            print(
                "dep-risk: no supported dependency files found in directory.",
                file=sys.stderr,
            )
            return 2
    else:
        ecosystems = [args.ecosystem]

    console = Console(stderr=True) if args.json_output else Console()
    reporter = TerminalReporter(console=console)

    cache = None if config.no_cache else get_default_cache()
    scanner = Scanner(config=config, cache=cache)

    start = time.monotonic()
    completed_count = 0
    fresh_count = 0

    if not args.json_output and not args.ci:
        console.print(f"[dim]Detecting ecosystems in {directory}: {', '.join(ecosystems)}[/dim]")

    with reporter.make_progress() as progress:
        task_id = progress.add_task(
            f"{len(ecosystems)} ecosystem(s)",
            total=None,
            status="starting...",
        )

        def on_progress(done: int, total: int, name: str) -> None:
            nonlocal completed_count
            completed_count = done
            progress.update(
                task_id,
                total=total,
                completed=done,
                status=f"[dim]{name}[/dim]",
            )

        results = asyncio.run(
            scanner.scan(directory, ecosystems, progress_callback=on_progress)
        )

    duration = time.monotonic() - start

    if args.json_output:
        json.dump([r.to_dict() for r in results], sys.stdout, indent=2)
        print()
        return 0

    min_risk = args.min_risk or config.min_risk or "low"

    if args.ci:
        return reporter.print_ci_output(results, fail_on=config.fail_on)

    reporter.print_summary(
        results=results,
        directory=directory,
        duration=duration,
        cached_count=0,
        fresh_count=len(results),
    )
    reporter.print_findings_table(
        results=results,
        min_level=min_risk,
        verbose=args.verbose,
    )

    if args.output:
        html_reporter = HtmlReporter()
        output_path = Path(args.output)
        html_reporter.write(output_path, results, directory, duration)
        console.print(f"\n[green]HTML report written to:[/green] {output_path.resolve()}")

    critical_count = sum(1 for r in results if r.risk_level == "critical")
    high_count = sum(1 for r in results if r.risk_level == "high")
    if critical_count or high_count:
        return 0
    return 0
