"""Rich CLI UI Façade.

Consolidates formatters, shortcuts, stream renderers, and tables
so existing callers remain 100% backward-compatible.
"""
from __future__ import annotations

from app.cli.formatters import (
    console,
    format_confidence,
    format_severity,
    print_error,
    print_github_unlinked_error,
    print_low_confidence_warning,
    print_missing_github_token_error,
    print_scan_started,
    print_success,
    prompt_approval,
)
from app.cli.shortcuts import terminal_shortcut_listener
from app.cli.stream_ui import render_auto_scan_stream, render_scan_stream
from app.cli.tables import (
    render_activity,
    render_auto_candidates_table,
    render_error_detail,
    render_findings,
    render_pending_errors,
    render_repositories_table,
)

__all__ = [
    "console",
    "terminal_shortcut_listener",
    "format_severity",
    "format_confidence",
    "print_error",
    "print_success",
    "print_scan_started",
    "prompt_approval",
    "print_github_unlinked_error",
    "print_low_confidence_warning",
    "print_missing_github_token_error",
    "render_scan_stream",
    "render_auto_scan_stream",
    "render_findings",
    "render_pending_errors",
    "render_error_detail",
    "render_auto_candidates_table",
    "render_activity",
    "render_repositories_table",
]
