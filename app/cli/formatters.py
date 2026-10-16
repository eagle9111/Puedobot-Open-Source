"""Rich formatting utilities, severities, badges, and notifications for the CLI."""
from __future__ import annotations

from rich.console import Console
from rich.prompt import Confirm

console = Console()


def format_severity(severity: str) -> str:
    """Return color-coded Rich markup for vulnerability severity."""
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif sev == "HIGH":
        return "[bold red]HIGH[/bold red]"
    elif sev == "MEDIUM":
        return "[bold yellow]MEDIUM[/bold yellow]"
    elif sev == "LOW":
        return "[bold cyan]LOW[/bold cyan]"
    return f"[dim]{sev}[/dim]"


def format_confidence(confidence: int | None) -> str:
    """Color-coded confidence percentage (green = strong evidence, red = shaky)."""
    if confidence is None:
        return "[dim]n/a[/dim]"
    if confidence >= 85:
        return f"[bold green]{confidence}%[/bold green]"
    if confidence >= 70:
        return f"[green]{confidence}%[/green]"
    if confidence >= 60:
        return f"[yellow]{confidence}%[/yellow]"
    return f"[red]{confidence}%[/red]"


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_scan_started(repo_id: int) -> None:
    """Print confirmation of a detached background scan."""
    console.print(f"[bold green]✓[/bold green] Scan running in background. (Repo ID: {repo_id})")


def prompt_approval(question: str = "Do you want to approve this finding?") -> bool:
    """Ask user for yes/no confirmation."""
    return Confirm.ask(question)


def print_github_unlinked_error(file_path: str, finding_id: int) -> None:
    """Print error when trying to publish a local file without a GitHub remote."""
    print_error(f"Cannot push to GitHub: File '{file_path}' is not part of a GitHub repository (no remote origin found).")
    console.print(f"[dim yellow]💡 Tip: Use [bold cyan]puedobot review {finding_id}[/bold cyan] to approve or reject this finding locally in your database.[/dim yellow]\n")


def print_low_confidence_warning(confidence: int, threshold: int) -> None:
    """Warn the reviewer that this finding is below the bot's own publish-confidence bar."""
    console.print(
        f"[bold yellow]⚠ Confidence is {confidence}% (publish threshold is {threshold}%).[/bold yellow] "
        "[dim yellow]Re-read the code proof yourself before posting this publicly.[/dim yellow]\n"
    )


def print_missing_github_token_error(finding_id: int) -> None:
    """Print error when GITHUB_BOT_TOKEN is missing."""
    print_error("Cannot push to GitHub: GITHUB_BOT_TOKEN is not configured in .env.")
    console.print(f"[dim yellow]💡 Tip: Add your GitHub Personal Access Token to .env (GITHUB_BOT_TOKEN=...) or use [bold cyan]puedobot review {finding_id}[/bold cyan] for local database review.[/dim yellow]\n")
