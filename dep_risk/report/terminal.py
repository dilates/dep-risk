from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dep_risk.scorers.base import LEVEL_ORDER, PackageResult, score_to_level

RISK_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

RISK_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class TerminalReporter:
    def __init__(self, console: Optional[Console] = None) -> None:
        self._console = console or Console()

    def print_summary(
        self,
        results: list[PackageResult],
        directory: Path,
        duration: float,
        cached_count: int,
        fresh_count: int,
    ) -> None:
        total = len(results)
        by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1

        header_text = (
            f"[bold]dep-risk scan[/bold] — {directory}\n"
            f"{total} packages scanned\n"
            f"Completed in {duration:.1f}s "
            f"(cached: {cached_count}, fresh: {fresh_count})"
        )
        self._console.print(Panel(header_text, expand=False, border_style="blue"))

        self._print_risk_bar(by_level, total)

    def _print_risk_bar(self, by_level: dict[str, int], total: int) -> None:
        self._console.print()
        max_count = max(by_level.values()) if by_level.values() else 1
        bar_width = 30
        for level in ("critical", "high", "medium", "low"):
            count = by_level.get(level, 0)
            if count == 0:
                continue
            bar_len = max(1, int(count / max(max_count, 1) * bar_width))
            bar = "█" * bar_len
            color = RISK_COLORS[level]
            label = f"{RISK_LABELS[level]:<10}"
            self._console.print(
                f"  [{color}]{label}[/{color}]  {count:>4}  [{color}]{bar}[/{color}]"
            )
        self._console.print()

    def print_findings_table(
        self,
        results: list[PackageResult],
        min_level: str = "low",
        verbose: bool = False,
    ) -> None:
        min_order = LEVEL_ORDER.get(min_level, 0)
        visible = [r for r in results if LEVEL_ORDER.get(r.risk_level, 0) >= min_order]

        if not visible:
            self._console.print("[green]No packages above the minimum risk threshold.[/green]")
            return

        table = Table(
            show_header=True,
            header_style="bold white",
            box=box.SIMPLE,
            padding=(0, 1),
        )
        table.add_column("Package", style="bold", no_wrap=True)
        table.add_column("Version", no_wrap=True)
        table.add_column("Ecosystem", no_wrap=True)
        table.add_column("Score", justify="right", no_wrap=True)
        table.add_column("Risk", no_wrap=True)
        table.add_column("Top Finding")

        for r in visible:
            color = RISK_COLORS.get(r.risk_level, "white")
            score_bar = _score_bar(r.total_score)
            top_finding = r.flags[0] if r.flags else "—"
            table.add_row(
                r.name,
                r.version or "—",
                r.ecosystem,
                f"[{color}]{r.total_score:.0f}[/{color}]",
                f"[{color}]{RISK_LABELS.get(r.risk_level, r.risk_level)}[/{color}]",
                top_finding,
            )

        self._console.print(table)

        if verbose or any(r.risk_level in ("critical", "high") for r in visible):
            for r in visible:
                if r.risk_level in ("critical", "high") or verbose:
                    self._print_detail_block(r)

    def _print_detail_block(self, result: PackageResult) -> None:
        color = RISK_COLORS.get(result.risk_level, "white")
        title = (
            f"[bold]{result.name}@{result.version}[/bold] ({result.ecosystem}) "
            f"— [{color}]{RISK_LABELS.get(result.risk_level)} {result.total_score:.0f}/100[/{color}]"
        )

        scorer_order = ["maintainer", "install_script", "activity", "typosquat", "version", "github", "entropy"]
        rows: list[str] = []
        for scorer_name in scorer_order:
            rs = result.scores.get(scorer_name)
            if rs is None:
                continue
            bar_filled = int(rs.score / 100 * 20)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            sc = RISK_COLORS.get(score_to_level(rs.score), "white")
            rows.append(
                f"  [{sc}]{scorer_name:<14} {bar}[/{sc}]  [bold]{rs.score:>4.0f}pts[/bold]  {rs.finding}"
            )

        body = "\n".join(rows)
        if result.registry_url:
            body += f"\n\n  [dim]Registry:[/dim] {result.registry_url}"
        if result.github_url:
            body += f"\n  [dim]GitHub:[/dim]   {result.github_url}"
        if result.fetch_errors:
            body += f"\n  [dim]Errors:[/dim]   {'; '.join(result.fetch_errors[:2])}"

        self._console.print(Panel(body, title=title, expand=False, border_style=color))

    def print_ci_output(
        self, results: list[PackageResult], fail_on: str = "high"
    ) -> int:
        fail_order = LEVEL_ORDER.get(fail_on, 2)
        failing = [r for r in results if LEVEL_ORDER.get(r.risk_level, 0) >= fail_order]

        for r in failing:
            color = RISK_COLORS.get(r.risk_level, "white")
            top = r.flags[0] if r.flags else "No details"
            self._console.print(
                f"[{color}][{RISK_LABELS.get(r.risk_level)}][/{color}] "
                f"{r.name}@{r.version} — score {r.total_score:.0f} — {top}"
            )

        counts = {lvl: sum(1 for r in failing if r.risk_level == lvl) for lvl in LEVEL_ORDER}
        parts = [f"{counts[lvl]} {RISK_LABELS[lvl]}" for lvl in ("critical", "high", "medium") if counts.get(lvl, 0) > 0]

        if failing:
            self._console.print(f"\n[bold red]dep-risk: {', '.join(parts)} packages found. Failing CI.[/bold red]")
            return 1
        else:
            self._console.print("[bold green]dep-risk: No packages above failure threshold. CI passed.[/bold green]")
            return 0

    def make_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning {task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("{task.fields[status]}"),
            console=self._console,
            transient=True,
        )


def _score_bar(score: float, width: int = 10) -> str:
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)
