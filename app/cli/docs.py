"""Command guide, help text, and terminal visualizers for PuedoBot Core."""
from rich.console import Console
from rich.table import Table

console = Console()

CLI_HEADER = """
================================================================================
PUEDOBOT CORE // LOCAL CODEBASE SECURITY AUDITOR
================================================================================
  scan <target_path>            Audit a local codebase or directory
  show-errors                   Display table of detected security findings
  show <id>                     Inspect finding dossier and code proof
  review <id> <approve|reject>  Confirm or dismiss finding in local database
  repos                         List all audited repositories and vulnerability counts
================================================================================
"""

SCAN_HELP = "Audit target directory for security flaws and leaked secrets."
SHOW_ERRORS_HELP = "Display table of security findings in database."
SHOW_ERROR_HELP = "Inspect full dossier, code proof, and remediation for one finding."
SHOW_HELP = "Inspect detailed vulnerability dossier with syntax-highlighted code proof."
REVIEW_HELP = "Review and confirm or dismiss a finding (approve/reject)."
REPOS_HELP = "List all audited local repositories."
ACTIVITY_HELP = "Display active repository scans and status."


def render_cli_help() -> None:
    """Print the formatted command reference table."""
    table = Table(
        title="🤖 PuedoBot Core — Command Reference",
        title_style="bold green",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Command", style="bold white", width=30)
    table.add_column("Description", style="white")

    table.add_row("puedobot scan <path>", "Audit a local codebase or directory")
    table.add_row("puedobot show-errors", "List all findings across audited codebases")
    table.add_row("puedobot show <id>", "Display complete vulnerability dossier & code snippet")
    table.add_row("puedobot review <id> <verdict>", "Mark finding as verified ('approve') or false positive ('reject')")
    table.add_row("puedobot repos", "List all tracked codebases and finding tallies")

    console.print()
    console.print(table)
    console.print()
