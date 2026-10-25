"""MetaScan CLI entry point."""

from __future__ import annotations

import asyncio
import sys
import webbrowser
from pathlib import Path

# Reconfigure stdout/stderr to UTF-8 on Windows to prevent UnicodeEncodeErrors
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
import typer.rich_utils as _rich_utils
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table

from metascan import __version__
from metascan.core.orchestrator import Orchestrator
from metascan.core.registry import ResultRegistry
from metascan.core.validator import AsyncValidator
from metascan.exporters.html_exporter import HtmlExporter
from metascan.models import ProfileEntry

_rich_utils.STYLE_OPTIONS_PANEL_BORDER = "green"
_rich_utils.STYLE_COMMANDS_PANEL_BORDER = "green"
_rich_utils.STYLE_USAGE = "bold green"
_rich_utils.STYLE_USAGE_COMMAND = "bold"
_rich_utils.STYLE_OPTION = "bold green"
_rich_utils.STYLE_SWITCH = "bold green"
_rich_utils.STYLE_NEGATIVE_OPTION = "bold red"
_rich_utils.STYLE_NEGATIVE_SWITCH = "bold red"
_rich_utils.STYLE_TYPES = "white"
_rich_utils.STYLE_TYPES_SEPARATOR = "dim"
_rich_utils.STYLE_HELPTEXT_FIRST_LINE = ""
_rich_utils.STYLE_HELPTEXT = "dim"
_rich_utils.STYLE_OPTION_HELP = ""
_rich_utils.STYLE_OPTION_DEFAULT = "dim"
_rich_utils.STYLE_OPTION_ENVVAR = "dim"
_rich_utils.STYLE_REQUIRED_SHORT = "red"
_rich_utils.STYLE_REQUIRED_LONG = "dim red"
_rich_utils.STYLE_COMMANDS_TABLE_FIRST_COLUMN = "bold green"
_rich_utils.STYLE_ERRORS_PANEL_BORDER = "red"
_rich_utils.STYLE_ERRORS_SUGGESTION = "dim"
_rich_utils.STYLE_ABORTED = "red"
_rich_utils.RICH_HELP = "Try [green]'{command_path} {help_option}'[/green] for help."

console = Console(highlight=False)

BANNER = r"""    __  __________________   _____ _________    _   __
   /  |/  / ____/_  __/   | / ___// ____/   |  / | / /
  / /|_/ / __/   / / / /| | \__ \/ /   / /| | /  |/ /
 / /  / / /___  / / / ___ |___/ / /___/ ___ |/ /|  /
/_/  /_/_____/ /_/ /_/  |_/____/\____/_/  |_/_/ |_/   """


def _print_banner(username: str) -> None:
    """Print tactical terminal banner with target username.

    Args:
        username: Target username being investigated.
    """
    banner_text = (
        f"[green]{BANNER}[/green]\n\n"
        f"Version: {__version__}\n"
        f"Target: {username}"
    )
    console.print(Panel(banner_text, border_style="green", padding=(0, 2)))


async def _run_pipeline(
    username: str,
    output: Path,
    timeout: int,
    concurrency: int,
    no_open: bool,
) -> None:
    """Execute complete scan, validation, summary display, and export pipeline.

    Args:
        username: Target username.
        output: Destination HTML file path.
        timeout: Subprocess timeout in seconds.
        concurrency: Max concurrent validation requests.
        no_open: When True, prevents opening report in browser.
    """
    orchestrator = Orchestrator(runner_timeout=timeout)
    registry = ResultRegistry(
        target=username,
        scanners=[r.name for r in orchestrator._runners],
    )

    dots = [".", "..", "..."]
    scan_task = asyncio.create_task(orchestrator.run(username, registry))

    async def _animate_scanning() -> None:
        idx = 0
        with Live(console=console, refresh_per_second=4, transient=True) as live:
            while not scan_task.done():
                live.update(f"Scanning platforms{dots[idx % len(dots)]}")
                idx += 1
                try:
                    await asyncio.sleep(0.3)
                except asyncio.CancelledError:
                    break

    anim_task = asyncio.create_task(_animate_scanning())
    try:
        await scan_task
    finally:
        anim_task.cancel()
        try:
            await anim_task
        except asyncio.CancelledError:
            pass

    total_found = len(registry.all_entries())
    console.print(f"Scan complete - {total_found} raw profile(s) discovered.")

    if total_found == 0:
        console.print("No profiles found.")
        raise typer.Exit(code=0)

    validator = AsyncValidator(concurrency=concurrency)
    entries = registry.all_entries()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Validating URLs...", total=len(entries))

        def _on_progress(entry: ProfileEntry) -> None:
            progress.advance(task)

        await validator.validate_all(registry, progress_callback=_on_progress)

    valid = registry.get_valid_results()
    errors = registry.get_filtered_results()
    console.print(
        f"Validation complete - "
        f"[green]{len(valid)} confirmed[/green], "
        f"[red]{len(errors)} filtered[/red]."
    )

    table = Table(
        show_header=True,
        header_style="bold green",
        border_style="green",
        expand=False,
        highlight=False,
    )
    table.add_column("Service", style="bold", no_wrap=True)
    table.add_column("URL", overflow="fold", ratio=2)
    table.add_column("Tools", style="dim")
    table.add_column("Status", justify="left", width=12)

    for entry in valid:
        table.add_row(
            entry.service,
            entry.url,
            entry.tools_str,
            "[green]FOUND[/green]",
        )

    if errors:
        table.add_section()
        for entry in errors:
            table.add_row(
                f"[dim]{entry.service}[/dim]",
                f"[dim]{entry.url}[/dim]",
                f"[dim]{entry.tools_str}[/dim]",
                f"[dim red]ERROR ({entry.reason or '?'})[/dim red]",
            )

    console.print(table)

    exporter = HtmlExporter()
    saved_path = exporter.export(registry, output)
    console.print(f"\nReport saved - {saved_path}")

    if not no_open:
        webbrowser.open(saved_path.as_uri())


def _version_callback(value: bool) -> None:
    """Display CLI version and exit."""
    if value:
        console.print(f"MetaScan v{__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="mns",
    help="MetaScan - Aggregate, Verify, and Visualize Digital Identities.",
    add_completion=False,
    no_args_is_help=True,
)


@app.command()
def scan(
    username: str = typer.Argument(..., help="Target username to investigate."),
    output: Path | None = typer.Option(
        None,
        "--output", "-o",
        help="Output path for the HTML report (default: reports/metascan_<username>.html).",
    ),
    timeout: int = typer.Option(
        120,
        "--timeout", "-t",
        help="Runner subprocess timeout in seconds.",
    ),
    concurrency: int = typer.Option(
        20,
        "--concurrency", "-c",
        help="Maximum parallel HTTP validation requests.",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Do not open the HTML report in the browser automatically.",
    ),
    version: bool = typer.Option(
        False,
        "--version", "-v",
        callback=_version_callback,
        is_eager=True,
        help="Show MetaScan version and exit.",
    ),
) -> None:
    """Scan USERNAME across Sherlock, Maigret, and Blackbird."""
    if output is None:
        output = Path(f"reports/metascan_{username}.html")

    _print_banner(username)

    asyncio.run(
        _run_pipeline(
            username=username,
            output=output,
            timeout=timeout,
            concurrency=concurrency,
            no_open=no_open,
        )
    )


if __name__ == "__main__":
    app()
