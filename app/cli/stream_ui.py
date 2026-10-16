"""Live terminal streaming renderers for manual and autonomous scans."""
from __future__ import annotations

import threading
from typing import Any, Generator

from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from app.cli.formatters import console, format_confidence, format_severity
from app.cli.shortcuts import terminal_shortcut_listener


def render_scan_stream(events: Generator[dict[str, Any], None, None]) -> None:
    """Render deep, file-by-file visual progress with Shift+D early exit support."""
    scanned_files: list[dict[str, Any]] = []
    confirmed_findings: list[dict[str, Any]] = []
    dismissed_findings: list[dict[str, Any]] = []
    low_conf_findings: list[dict[str, Any]] = []
    triage_errors: list[dict[str, Any]] = []
    interrupted_early = False
    partial_scan = False
    last_event: dict[str, Any] = {}
    stop_event = threading.Event()
    repo_name = ""
    repo_id: int | None = None

    console.print("[dim]💡 Tip: Press [bold cyan]Shift + D[/bold cyan] (or [bold]Ctrl + C[/bold]) at any time to end scan early and keep all findings.[/dim]\n")

    with terminal_shortcut_listener(stop_event):
        try:
            with console.status("[bold cyan]Connecting to PuedoBot scanner...[/bold cyan]") as status:
                for event in events:
                    if stop_event.is_set():
                        interrupted_early = True
                        break

                    last_event = event
                    event_type = event.get("type")
                    partial_scan |= bool(event.get("partial"))

                    if event.get("repo_name"):
                        repo_name = event["repo_name"]
                    if event.get("repo_id"):
                        repo_id = event["repo_id"]

                    if event_type == "start":
                        target_display = repo_name or event.get("target_path") or "Target"
                        repo_tag = f" [cyan](Repo #{repo_id})[/cyan]" if repo_id else ""
                        console.print(f"📦 [bold cyan]Target Repository:[/bold cyan] [bold white]{target_display}[/bold white]{repo_tag}")
                        if event.get("target_path"):
                            console.print(f"   [dim]Location: {event.get('target_path')}[/dim]\n")
                        status.update(f"[bold cyan]Auditing {target_display}...[/bold cyan]")

                    elif event_type == "scout_started":
                        target_display = repo_name or "repository"
                        status.update(f"[bold cyan]🤖 AI Agent Scout analyzing {target_display} attack surfaces...[/bold cyan]")

                    elif event_type == "scout_completed":
                        target_display = repo_name or "Repository"
                        rationale = event.get("rationale", "")
                        surfaces = event.get("attack_surfaces", [])
                        skipped = event.get("skipped_areas", [])
                        console.print(
                            f"\n  [bold cyan]🧠 AI Agent Scout Selected {event['selected_count']} Target Files for {target_display}:[/bold cyan] "
                            f"[dim]{rationale}[/dim]"
                        )
                        if surfaces:
                            console.print(f"  [bold green]• Attack Surfaces:[/bold green] [dim]{', '.join(surfaces)}[/dim]")
                        if skipped:
                            console.print(f"  [dim yellow]• Deliberately Skipped:[/dim yellow] [dim]{', '.join(skipped)}[/dim]\n")
                        status.update(f"Scanning {event['selected_count']} selected attack surface files...")

                    elif event_type == "file_scanned":
                        scanned_files.append({"file": event["file"], "hotspots": event["hotspots"]})
                        if event["hotspots"] > 0:
                            console.print(
                                f"  [bold yellow]⚡ Flagged in {event['file']}:[/bold yellow] "
                                f"[yellow]{event['hotspots']} suspicious item(s) found[/yellow]"
                            )
                        else:
                            status.update(f"Inspecting [dim]{event['file']}[/dim]...")

                    elif event_type == "engine_progress":
                        status.update(f"[bold cyan]{event['message']}[/bold cyan]")

                    elif event_type == "engine_notice":
                        console.print(f"  [dim yellow]ℹ {event['message']}[/dim yellow]")

                    elif event_type == "scan_complete":
                        target_display = repo_name or "Repository"
                        console.print(
                            f"\n[bold green]✓ Discovery Complete for {target_display}:[/bold green] "
                            f"Audited [bold]{event['total_files']}[/bold] files, "
                            f"found [bold yellow]{event['total_hotspots']}[/bold yellow] suspicious item(s)."
                        )
                        if event["total_hotspots"] > 0:
                            console.print("[dim]Consulting AI Security Engine for deep taint & secret analysis...[/dim]\n")

                    elif event_type == "triage_progress":
                        status.update(
                            f"[bold magenta]AI Triaging ({event['index']}/{event['total']}):[/bold magenta] "
                            f"[yellow]{event['function']}[/yellow] in {event['file']}:{event['line']}..."
                        )

                    elif event_type == "hotspot_confirmed":
                        confirmed_findings.append(event)
                        finding_tag = f" [bold magenta][Finding #{event['id']}][/bold magenta]" if event.get("id") else ""
                        console.print(
                            f"  [bold red]✗ Threat Confirmed:[/bold red] "
                            f"[bold]{event['vulnerability_type']}[/bold] ({format_severity(event['severity'])}) "
                            f"at [cyan]{event['file']}:{event['line']}[/cyan] "
                            f"{format_confidence(event.get('confidence'))}{finding_tag} [dim]via {event.get('source', '?')}[/dim]"
                        )

                    elif event_type == "hotspot_low_confidence":
                        low_conf_findings.append(event)
                        console.print(
                            f"  [bold yellow]? Uncertain (discarded):[/bold yellow] "
                            f"{event['function']} in [dim]{event['file']}:{event['line']}[/dim] "
                            f"[dim](confidence {event['confidence']}% < threshold)[/dim]"
                        )

                    elif event_type == "hotspot_rejected":
                        dismissed_findings.append(event)
                        console.print(
                            f"  [bold green]✓ AI Dismissed (Safe):[/bold green] "
                            f"{event['function']} in [dim]{event['file']}:{event['line']}[/dim] (false alarm filtered)"
                        )

                    elif event_type == "triage_error":
                        triage_errors.append(event)
                        console.print(
                            f"  [bold red]⚠ Triage Warning:[/bold red] {event['file']}:{event['line']} - {event['error']}"
                        )

                    elif event_type == "complete":
                        status.stop()
        except KeyboardInterrupt:
            interrupted_early = True

    if interrupted_early or stop_event.is_set():
        console.print("\n[bold yellow]⏹ Session ended early by user (Shift + D / Ctrl + C).[/bold yellow]")
        console.print("[dim]All findings analyzed up to this moment were securely saved to the database.[/dim]\n")

    # --- Render Audit Breakdown Report ---
    console.print()

    repo_title_parts = []
    if repo_id:
        repo_title_parts.append(f"Repo #{repo_id}")
    if repo_name:
        repo_title_parts.append(repo_name)
    repo_label = f" ({' — '.join(repo_title_parts)})" if repo_title_parts else ""

    # 1. Actionable Vulnerabilities Table (if any confirmed)
    if confirmed_findings:
        vuln_table = Table(
            title=f"🚨 Confirmed Vulnerabilities{repo_label}",
            title_style="bold red",
            border_style="red"
        )
        vuln_table.add_column("ID", style="bold cyan", justify="right")
        vuln_table.add_column("File & Line", style="cyan", no_wrap=True)
        vuln_table.add_column("Vulnerability", style="bold white")
        vuln_table.add_column("Severity", justify="center")
        vuln_table.add_column("Conf.", justify="center")
        vuln_table.add_column("Technical Analysis", style="dim")

        for f in confirmed_findings:
            desc = f.get('description', '')
            short_desc = desc[:120] + "..." if len(desc) > 120 else desc
            finding_id_str = f"#{f['id']}" if f.get("id") else "—"
            vuln_table.add_row(
                finding_id_str,
                f"{f['file']}:{f['line']}",
                f['vulnerability_type'],
                format_severity(f['severity']),
                format_confidence(f.get('confidence')),
                short_desc
            )
        console.print(vuln_table)
        console.print()

    # 2. Files Audited Breakdown Table
    if scanned_files:
        files_table = Table(
            title=f"📁 Files Audited & Status Breakdown{repo_label}",
            title_style="bold cyan",
            border_style="dim"
        )
        files_table.add_column("File Path", style="dim cyan")
        files_table.add_column("Hotspots Found", justify="center")
        files_table.add_column("Status", justify="right")

        vuln_files = {f["file"]: f for f in confirmed_findings}
        error_files = {e["file"] for e in triage_errors if e.get("file")}

        for item in scanned_files:
            fpath = item["file"]
            hcount = item["hotspots"]
            if fpath in vuln_files:
                v = vuln_files[fpath]
                status_badge = f"[bold red]VULNERABLE ({v['severity']})[/bold red]"
            elif fpath in error_files:
                status_badge = "[bold yellow]⚠ Triage Error (Uninspected)[/bold yellow]"
            elif partial_scan:
                status_badge = "[yellow]Incomplete audit[/yellow]"
            elif hcount > 0:
                status_badge = "[green]✓ Filtered (Safe)[/green]"
            else:
                status_badge = "[dim green]✓ Clean[/dim green]"

            files_table.add_row(
                fpath,
                str(hcount) if hcount > 0 else "[dim]0[/dim]",
                status_badge
            )

        console.print(files_table)

    # 3. Final Summary Panel
    summary_lines = []
    if repo_name or repo_id:
        target_info = f"[bold white]{repo_name or 'Repository'}[/bold white]"
        if repo_id:
            target_info += f" [dim](Repo #{repo_id})[/dim]"
        summary_lines.append(f"• [bold]Target Repository:[/bold] {target_info}")

    summary_lines.extend([
        f"• [bold]Files Audited:[/bold] {len(scanned_files)}",
        f"• [bold]Suspicious Sinks Flagged:[/bold] {last_event.get('total_hotspots', len(confirmed_findings) + len(dismissed_findings))}",
        f"• [bold]False Alarms Discarded by AI:[/bold] {len(dismissed_findings)}",
        f"• [bold]Uncertain Findings Discarded (low confidence):[/bold] {len(low_conf_findings)}",
    ])
    if triage_errors:
        summary_lines.append(f"• [bold red]Triage Failures (AI Offline/Error):[/bold red] [bold red]{len(triage_errors)}[/bold red]")
    summary_lines.append(f"• [bold]Confirmed Vulnerabilities Saved to DB:[/bold] [bold red]{len(confirmed_findings)}[/bold red]")

    if confirmed_findings:
        f_ids = [str(f["id"]) for f in confirmed_findings if f.get("id")]
        if f_ids:
            summary_lines.append(f"• [bold]Saved Finding IDs:[/bold] [bold cyan]{', '.join(f'#{x}' for x in f_ids)}[/bold cyan]")

    if interrupted_early or stop_event.is_set():
        summary_lines.append("\n[bold yellow]⚠️ Scan was stopped early. Partial audit results have been preserved.[/bold yellow]")

    if partial_scan:
        summary_lines.append(f"Partial scan: {last_event.get('reason', 'resource limit')}. Review saved findings; coverage is incomplete.")
        panel_title = "[yellow]Audit Summary - Partial[/yellow]"
        border = "yellow"
    elif confirmed_findings:
        first_id = confirmed_findings[0].get("id")
        summary_lines.append("\n👉 Run [bold cyan]puedobot show-errors[/bold cyan] to review findings in detail.")
        if first_id:
            summary_lines.append(f"👉 Inspect code proof: [bold cyan]puedobot show-error {first_id}[/bold cyan]")
            summary_lines.append(f"👉 Submit 1 private Security Advisory (PVR): [bold green]puedobot push-error {first_id}[/bold green]")
        if repo_id:
            summary_lines.append(f"👉 Or bundle repo into 1 advisory (PVR): [bold green]puedobot push-repo {repo_id}[/bold green]")
        panel_title = "[bold red]Audit Summary - Action Required[/bold red]"
        border = "red"
    else:
        summary_lines.append("\n✨ [bold green]No exploitable flaws detected in the scanned files.[/bold green]")
        panel_title = "[bold green]Audit Summary - Clean Codebase[/bold green]"
        border = "green"

    console.print()
    console.print(Panel("\n".join(summary_lines), title=panel_title, border_style=border))
    console.print()


def render_auto_scan_stream(event_generator: Generator[dict[str, Any], None, None]) -> None:
    """Stream events for an autonomous multi-repository audit."""
    scanned_count = 0
    current_repo = ""
    confirmed_findings_by_repo: dict[str, list[dict]] = {}
    warning_repos: set[str] = set()

    console.print(
        Panel(
            "[bold white]Autonomous Audit Engine Started[/bold white]\n"
            "[dim]Searching new & small GitHub repos • Enforcing 180-day spam cooldown • Feature-focused analysis[/dim]",
            title="[bold green]🤖 PuedoBot Auto-Mode[/bold green]",
            border_style="green",
        )
    )

    with Live(console=console, refresh_per_second=8, transient=False) as live:
        for event in event_generator:
            etype = event.get("type")
            if event.get("partial"):
                warning_repos.add(current_repo)
                live.console.print(f"[yellow]Partial audit: {event.get('reason', 'resource limit')}[/yellow]")

            if etype == "auto_discovery_start":
                live.console.print(
                    f"\n[cyan]🔍 Discovered [bold]{event.get('found_candidates', 0)}[/bold] candidate repositories on GitHub. "
                    f"([bold green]{event.get('eligible_candidates', 0)} eligible[/bold green] after spam cooldown check)[/cyan]\n"
                )

            elif etype == "auto_discovery_empty":
                live.console.print(f"[bold yellow]ℹ {event.get('message')}[/bold yellow]\n")

            elif etype == "repo_started":
                current_repo = event.get("repo_name", "")
                confirmed_findings_by_repo[current_repo] = []
                size_kb = event.get("size_kb", 0)
                stars = event.get("stars", 0)
                live.console.print(
                    f"[bold cyan]▶ Auditing Repository:[/bold cyan] [bold white]{current_repo}[/bold white] "
                    f"[dim]({size_kb} KB, ★ {stars})[/dim]"
                )

            elif etype == "engine_notice":
                live.console.print(f"  [dim yellow]⚡ {event.get('message')}[/dim yellow]")

            elif etype == "triage_error":
                warning_repos.add(current_repo)
                live.console.print(f"  [bold yellow]Triage warning:[/bold yellow] {event.get('error')}")

            elif etype == "scout_started":
                live.console.print("  [cyan]🤖 AI Agent Scout mapping repository tree & attack surfaces...[/cyan]")

            elif etype == "scout_completed":
                rationale = event.get("rationale", "")
                surfaces = event.get("attack_surfaces", [])
                live.console.print(
                    f"  [bold cyan]🧠 Agent Scout Selected {event.get('selected_count')} files:[/bold cyan] [dim]{rationale}[/dim]"
                )
                if surfaces:
                    live.console.print(f"  [dim green]• Attack Surfaces: {', '.join(surfaces)}[/dim green]")

            elif etype == "file_scanned":
                hcount = event.get("hotspots", 0)
                if hcount > 0:
                    live.console.print(
                        f"  [dim]• Scanned {event.get('file')}[/dim] → [bold yellow]{hcount} hotspots[/bold yellow]"
                    )

            elif etype == "triage_progress":
                live.update(
                    f"  [cyan]Triaging hotspot {event.get('index')}/{event.get('total')}:[/cyan] "
                    f"[bold white]{event.get('function')}[/bold white] in [dim]{event.get('file')}:{event.get('line')}[/dim]"
                )

            elif etype == "hotspot_confirmed":
                if current_repo:
                    confirmed_findings_by_repo[current_repo].append(event)
                sev = event.get("severity", "MEDIUM")
                conf = event.get("confidence", 0)
                finding_tag = f" [bold magenta][Finding #{event['id']}][/bold magenta]" if event.get("id") else ""
                live.console.print(
                    f"  [bold red]🚨 Confirmed {sev} Flaw ({conf}% confidence):[/bold red] "
                    f"[bold white]{event.get('vulnerability_type')}[/bold white]{finding_tag} in [cyan]{event.get('file')}:{event.get('line')}[/cyan]"
                )

            elif etype in ("repo_advisory_reported", "repo_advisory_published"):
                mode = event.get("mode", "local")
                if mode == "issue":
                    live.console.print(f"  [bold green]Published consolidated security issue:[/bold green] {event.get('issue_url')}\n")
                elif mode == "pvr" and event.get("issue_url"):
                    live.console.print(
                        f"  [bold green]🔒 Privately Submitted Security Advisory to Maintainers ({event.get('count')} findings):[/bold green]\n"
                        f"     [bold cyan]🔗 {event.get('issue_url')}[/bold cyan]\n"
                        f"     [dim]Local copy: {event.get('local_report')}[/dim]\n"
                    )
                else:
                    live.console.print(
                        f"  [bold green]📁 Saved Confidential Security Advisory Report ({event.get('count')} findings):[/bold green]\n"
                        f"     [bold cyan]📄 {event.get('local_report')}[/bold cyan]\n"
                    )

            elif etype == "repo_completed":
                scanned_count += 1
                c_list = confirmed_findings_by_repo.get(current_repo, [])
                if current_repo in warning_repos:
                    live.console.print(
                        f"  [bold yellow]Finished {current_repo} with warnings:[/bold yellow] "
                        f"{len(c_list)} confirmed vulnerabilities saved. Review warnings and pending findings.\n"
                    )
                elif c_list:
                    live.console.print(
                        f"  [bold green]✓ Finished {current_repo}:[/bold green] "
                        f"[bold red]{len(c_list)} confirmed vulnerabilities saved to DB.[/bold red]\n"
                    )
                else:
                    live.console.print(
                        f"  [bold green]✓ Finished {current_repo}:[/bold green] [dim green]Clean (no high-confidence flaws found).[/dim green]\n"
                    )

            elif etype == "daemon_cycle_start":
                live.console.print(
                    f"\n[bold magenta]🔄 [DAEMON CYCLE #{event.get('cycle', 1)}][/bold magenta] "
                    f"[dim]{event.get('message', 'Starting autonomous cycle...')}[/dim]\n"
                )

            elif etype == "daemon_sleeping":
                live.console.print(
                    f"\n[bold yellow]💤 [CYCLE #{event.get('cycle', 1)} COMPLETE][/bold yellow] "
                    f"{event.get('message', '')}\n"
                    f"   [dim cyan]Next discovery cycle at {event.get('next_cycle_at')} (press Ctrl+C to detach or stop)[/dim cyan]\n"
                )

            elif etype == "daemon_stopped":
                live.console.print(
                    f"\n[bold yellow]⏹ [DAEMON STOPPED][/bold yellow] {event.get('message', '')}\n"
                )

            elif etype == "auto_scan_finished":
                live.console.print(
                    Panel(
                        f"[bold green]Autonomous Audit Completed Successfully![/bold green]\n"
                        f"Total repositories processed: [bold white]{event.get('total_repos_scanned', scanned_count)}[/bold white]\n"
                        f"Use [bold cyan]puedobot show-errors[/bold cyan] to inspect all new findings in your database.",
                        border_style="green",
                    )
                )
