"""Rich table displays and dossier visualizers for findings, candidates, and activity."""
from __future__ import annotations

from typing import Any

from rich import box
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from app.cli.formatters import console, format_confidence, format_severity


def render_findings(
    findings: list[dict[str, Any]],
    title: str = "Security Findings",
    show_details: bool = False,
    show_status: bool = False,
) -> None:
    """Render table of findings, optionally expanding each with full code proof."""
    if not findings:
        console.print(f"[green]No findings found ({title.lower()})! ✨[/green]")
        return

    table = Table(title=title, title_style="bold yellow")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("File & Line", style="magenta")
    table.add_column("Vulnerability Type", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("Conf.", justify="center")
    if show_status:
        table.add_column("Status", justify="center")
    table.add_column("Repository & Remote URL", style="dim cyan")

    for f in findings:
        repo_name = f.get("repo_name") or f.get("github_repo")
        repo_url = f.get("repo_url") or (f"https://github.com/{f['github_repo']}" if (f.get("github_repo") and "/" in f["github_repo"]) else None)

        if repo_name and repo_url:
            repo_cell = f"[bold white]{repo_name}[/bold white]\n[dim cyan]{repo_url}[/dim cyan]"
        elif repo_name:
            repo_cell = f"[bold white]{repo_name}[/bold white]"
        elif repo_url:
            repo_cell = f"[dim cyan]{repo_url}[/dim cyan]"
        else:
            repo_cell = "[dim]Local only[/dim]"

        status_val = f.get("status", "PENDING_REVIEW")
        if status_val == "APPROVED":
            status_badge = "[bold green]APPROVED[/bold green]"
        elif status_val == "REJECTED":
            status_badge = "[dim red]REJECTED[/dim red]"
        elif status_val == "PUBLISHED":
            status_badge = (
                f"[bold blue]PUBLISHED[/bold blue]\n[dim cyan]{f['github_issue_url']}[/dim cyan]"
                if f.get("github_issue_url")
                else "[bold blue]PUBLISHED[/bold blue]"
            )
        else:
            status_badge = "[bold yellow]PENDING[/bold yellow]"

        row = [
            str(f["id"]),
            f"{f['file_path']}:{f['line_number']}",
            f["vulnerability_type"],
            format_severity(f["severity"]),
            format_confidence(f.get("confidence")),
        ]
        if show_status:
            row.append(status_badge)
        row.append(repo_cell)

        table.add_row(*row)

    console.print(table)

    if show_details:
        console.print("\n[bold yellow]═══ Detailed Code Proofs ═══[/bold yellow]")
        for f in findings:
            render_error_detail(f)
    else:
        console.print("[dim]💡 Tip: Inspect code proof for any finding with: [bold cyan]puedobot show-error <ID>[/bold cyan] or [bold cyan]puedobot show-errors -d[/bold cyan][/dim]\n")


def render_pending_errors(findings: list[dict[str, Any]], show_details: bool = False) -> None:
    """Backwards-compatible alias for render_findings."""
    render_findings(findings, title="Pending Security Findings", show_details=show_details, show_status=False)


def render_error_detail(finding: dict[str, Any]) -> None:
    """Render detailed review card for a single finding with a table on top and syntax-highlighted code proof."""
    table = Table(
        title=f"🚨 Security Finding #{finding['id']} Dossier",
        title_style="bold red",
        header_style="bold cyan",
        show_header=True,
    )
    table.add_column("Property", style="bold cyan", width=18)
    table.add_column("Security Details", style="white")

    repo_name = finding.get("repo_name") or finding.get("github_repo") or "Local repository"
    repo_url = finding.get("repo_url") or (f"https://github.com/{finding['github_repo']}" if (finding.get("github_repo") and "/" in finding["github_repo"]) else None)

    status_val = finding.get("status", "PENDING_REVIEW")
    if status_val == "APPROVED":
        status_badge = "[bold green]APPROVED[/bold green]"
    elif status_val == "REJECTED":
        status_badge = "[dim red]REJECTED[/dim red]"
    elif status_val == "PUBLISHED":
        status_badge = "[bold blue]PUBLISHED[/bold blue]"
    else:
        status_badge = "[bold yellow]PENDING_REVIEW[/bold yellow]"

    table.add_row("Vulnerability", f"{finding['vulnerability_type']} ({format_severity(finding['severity'])})")
    table.add_row("File & Line", f"{finding['file_path']}:{finding['line_number']}")
    table.add_row("Target Repo", f"[bold white]{repo_name}[/bold white]")
    if repo_url:
        table.add_row("Repo URL", f"[bold cyan underline]{repo_url}[/bold cyan underline]")
    table.add_row("Status", status_badge)
    if finding.get("github_issue_url"):
        table.add_row("GitHub Issue", f"[bold green]{finding['github_issue_url']}[/bold green]")
    if finding.get("confidence") is not None:
        table.add_row("Confidence", format_confidence(finding["confidence"]))
    if finding.get("source"):
        table.add_row("Detected By", f"[bold magenta]{finding['source']}[/bold magenta] engine")
    if finding.get("verification_note"):
        table.add_row("Verification", f"[dim]{finding['verification_note']}[/dim]")
    table.add_row("Technical Analysis", finding.get("description", ""))
    if finding.get("remediation"):
        table.add_row("Remediation", f"[bold green]{finding['remediation']}[/bold green]")

    console.print()
    console.print(table)

    if finding.get("code_snippet"):
        fpath = finding.get("file_path", "")
        lexer = "python"
        if fpath.endswith(".env") or ".env" in fpath:
            lexer = "bash"
        elif fpath.endswith(".yaml") or fpath.endswith(".yml"):
            lexer = "yaml"
        elif fpath.endswith(".json"):
            lexer = "json"
        elif fpath.endswith(".sql"):
            lexer = "sql"
        elif "Dockerfile" in fpath:
            lexer = "dockerfile"

        line_num = finding.get("line_number", 1)
        # Determine start line based on lines in snippet
        snippet_lines = finding["code_snippet"].count("\n") + 1
        calc_start = max(1, line_num - 3) if snippet_lines > 1 else line_num

        syntax = Syntax(
            finding["code_snippet"],
            lexer,
            theme="monokai",
            line_numbers=True,
            start_line=calc_start,
            highlight_lines={line_num},
        )
        console.print()
        console.print(Panel(syntax, title=f"[bold cyan]🔍 Code Proof / Taint Context (Line {line_num})[/bold cyan]", border_style="cyan"))
        console.print()


def render_auto_candidates_table(candidates: list[dict[str, Any]], cooldown_days: int) -> None:
    """Render discovered candidate repositories with cooldown eligibility."""
    table = Table(
        title=f"🔎 Discovered Candidate Repositories (Cooldown: {cooldown_days} days)",
        title_style="bold cyan",
        border_style="cyan",
        box=box.ROUNDED,
    )
    table.add_column("Repository", style="bold white", no_wrap=True)
    table.add_column("Size", justify="right", style="cyan")
    table.add_column("Stars", justify="right", style="yellow")
    table.add_column("Eligibility & Cooldown", style="bold")

    for c in candidates:
        full_name = c["full_name"]
        size_str = f"{c.get('size_kb', 0):,} KB"
        stars_str = f"★ {c.get('stars', 0)}"

        if c.get("is_eligible", True):
            status_text = "[bold green]✓ Ready to Audit[/bold green]"
        else:
            reason = c.get("cooldown_reason", "Cooldown active")
            status_text = f"[yellow]⏳ Skipped: {reason}[/yellow]"

        table.add_row(full_name, size_str, stars_str, status_text)

    console.print()
    console.print(table)
    console.print()


def render_activity(data: dict[str, Any]) -> None:
    """Render active scans and sent GitHub advisory reports."""
    running = data.get("running", [])
    reports = data.get("reports", [])

    # 1. Active Scans Table
    active_table = Table(title="🔄 Active Repository Audits", title_style="bold cyan")
    active_table.add_column("Run ID", style="cyan", justify="right")
    active_table.add_column("Target / Repo", style="bold white")
    active_table.add_column("Stage", style="bold yellow")
    active_table.add_column("Current File", style="dim")
    active_table.add_column("Mode", justify="center")

    if running:
        for r in running:
            active_table.add_row(
                str(r.get("id")),
                str(r.get("current_repo") or r.get("target") or "Unknown"),
                str(r.get("stage") or "Scanning"),
                str(r.get("current_file") or "—"),
                str(r.get("mode") or "MANUAL"),
            )
        console.print(active_table)
    else:
        console.print("[dim]No active repository audits currently running.[/dim]\n")

    console.print()

    # 2. Sent GitHub Advisory Reports Table
    reports_table = Table(title="📢 Sent GitHub Issue Advisories (Auto & Manual)", title_style="bold green")
    reports_table.add_column("Repository", style="bold white")
    reports_table.add_column("Findings", justify="center", style="bold red")
    reports_table.add_column("Scan Mode", justify="center", style="dim")
    reports_table.add_column("Direct GitHub Issue URL", style="bold cyan")

    if reports:
        for rep in reports:
            reports_table.add_row(
                str(rep.get("repo_name")),
                str(rep.get("findings_count")),
                str(rep.get("scan_mode")),
                str(rep.get("url")),
            )
        console.print(reports_table)
    else:
        console.print("[dim]No published GitHub issue reports recorded yet.[/dim]\n")


def render_repositories_table(repos: list[dict[str, Any]]) -> None:
    """Render table of all audited repositories recorded in the database."""
    if not repos:
        console.print("[yellow]No repositories found in the database. Run 'puedobot scan <target>' to audit one.[/yellow]\n")
        return

    table = Table(title="📦 Audited Repositories", title_style="bold cyan")
    table.add_column("ID", style="bold cyan", justify="right")
    table.add_column("Repository Name", style="bold white")
    table.add_column("Findings", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Mode", justify="center", style="dim")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Last Scanned", style="dim")

    for r in repos:
        findings_cnt = r.get("findings_count", 0)
        f_badge = f"[bold red]{findings_cnt}[/bold red]" if findings_cnt > 0 else "[dim green]0[/dim green]"
        status_raw = str(r.get("status", "completed")).lower()
        if status_raw == "completed":
            status_badge = "[green]✓ completed[/green]"
        elif status_raw in ("running", "scanning"):
            status_badge = "[bold yellow]⏳ running[/bold yellow]"
        elif status_raw == "partial":
            status_badge = "[yellow]⚠️ partial[/yellow]"
        else:
            status_badge = f"[dim]{status_raw}[/dim]"

        scanned_at_str = r.get("scanned_at") or "—"
        if "T" in scanned_at_str:
            scanned_at_str = scanned_at_str.replace("T", " ")[:19]

        size_kb = r.get("size_kb")
        size_str = f"{size_kb:,} KB" if size_kb else "—"

        table.add_row(
            str(r["id"]),
            str(r.get("repo_name") or "Local Repo"),
            f_badge,
            status_badge,
            str(r.get("scan_mode") or "MANUAL"),
            size_str,
            scanned_at_str,
        )

    console.print()
    console.print(table)
    console.print("[dim]💡 Tip: Inspect repo findings with: [bold cyan]puedobot show-errors[/bold cyan] or bundle advisory with: [bold green]puedobot push-repo <ID>[/bold green][/dim]\n")
