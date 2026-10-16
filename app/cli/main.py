import typer
from app.core.config import settings
from app.cli.client import PuedoBotClient, PuedoBotClientError
from app.cli import ui
from app.cli import docs

app = typer.Typer(
    add_completion=False,
    help="🤖 PuedoBot Security Auditor — Autonomous & Interactive SAST Security Suite.",
)
client = PuedoBotClient()


def help_callback(value: bool):
    if value:
        docs.render_cli_help()
        raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    help: bool = typer.Option(
        None,
        "--help",
        "-h",
        is_eager=True,
        callback=help_callback,
        help="Show PuedoBot command guide and flags table.",
    ),
):
    """PuedoBot Client CLI - AI-Powered SAST Security Auditor."""
    if ctx.invoked_subcommand is None:
        docs.render_cli_help()
        raise typer.Exit(code=0)


@app.command("scan", help=docs.SCAN_HELP)
def scan_path(
    target_path: str = typer.Argument(..., help="Local path, GitHub URL, or owner/repo to audit"),
    detach: bool = typer.Option(False, "--detach", "-d", help="Run audit in background on server"),
    history: bool = typer.Option(False, "--history", "-H", help="Also search past commits for deleted secrets"),
    smart: bool = typer.Option(True, "--smart/--all", "--agent/--no-agent", help="Use AI Agent Scout to dynamically choose high-risk attack surface files"),
    keep: bool = typer.Option(False, "--keep", "-k", help="Preserve cloned remote repositories in cache after audit"),
):
    """Audit a codebase for vulnerabilities and leaked secrets."""
    try:
        if detach:
            ui.print_scan_started(client.trigger_scan(target_path, scan_history=history, smart_scan=smart, keep=keep))
        else:
            ui.render_scan_stream(client.stream_scan(target_path, scan_history=history, smart_scan=smart, keep=keep))
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)



@app.command("show-errors", help=docs.SHOW_ERRORS_HELP)
def show_errors(
    finding_id: int | None = typer.Argument(None, help="Optional Finding ID to inspect directly"),
    status: str = typer.Option("pending", "--status", "-s", help="Filter: pending, approved, rejected, all"),
    detail: bool = typer.Option(False, "--detail", "-d", help="Expand findings with full code proofs"),
):
    """Display security findings table or inspect a specific finding by ID."""
    if finding_id is not None:
        return show_error(finding_id)
    try:
        findings = client.get_errors(status=status)
        title = f"{status.capitalize()} Security Findings" if status.lower() != "all" else "All Security Findings"
        ui.render_findings(findings, title=title, show_details=detail, show_status=(status.lower() == "all"))
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show-error", help=docs.SHOW_ERROR_HELP)
def show_error(
    finding_id: int = typer.Argument(..., help="Database ID of the finding to inspect")
):
    """Inspect a single finding's code proof, taint context, and remediation."""
    try:
        finding = client.get_error(finding_id)
        if not finding:
            ui.print_error(f"Finding ID #{finding_id} not found.")
            raise typer.Exit(code=1)
        ui.render_error_detail(finding)
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)


@app.command("review", help=docs.REVIEW_HELP)
def review_error(
    finding_id: int = typer.Argument(..., help="Database ID of the finding to review")
):
    """Review and confirm/reject a finding in your local PostgreSQL database."""
    try:
        finding = client.get_error(finding_id)
        if not finding:
            ui.print_error(f"Finding ID #{finding_id} not found.")
            raise typer.Exit(code=1)

        ui.render_error_detail(finding)
        approved = ui.prompt_approval(f"Confirm finding #{finding_id} as a valid vulnerability in local database?")
        res = client.submit_review(finding_id, approved=approved, publish_to_github=False)

        if approved:
            ui.print_success(f"✓ Approved! {res.get('message', 'Saved in local database.')}")
        else:
            ui.print_error(f"✗ Rejected. {res.get('message', 'Marked as false positive.')}")
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)


@app.command("activity", help=docs.ACTIVITY_HELP)
def show_activity():
    """Display active repository scans and published GitHub advisory reports with direct links."""
    try:
        activity = client.get_activity()
        ui.render_activity(activity)
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show", help="Inspect a single finding's code proof, taint context, and remediation (alias for show-error)")
def show_finding_alias(
    finding_id: int = typer.Argument(..., help="Database ID of the finding to inspect")
):
    """Inspect finding dossier and code proof by ID."""
    return show_error(finding_id)


@app.command("repos", help="List all audited repositories recorded in the database")
def list_repos_cmd(
    limit: int = typer.Option(50, "--limit", "-l", help="Number of repositories to display (default: 50)"),
):
    """List all audited repositories recorded in the database."""
    try:
        repos = client.get_repositories(limit=limit)
        ui.render_repositories_table(repos)
    except PuedoBotClientError as e:
        ui.print_error(str(e))
        raise typer.Exit(code=1)


