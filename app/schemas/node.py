"""Core data models and schemas for detected code hotspots and AST nodes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.schemas.finding import SecurityTriageResult


@dataclass
class SuspiciousNode:
    """Represents a suspicious code sink or vulnerability candidate detected by any engine."""
    file_path: str
    line_number: int
    function_name: str
    code_context: str
    # Which engine raised it: ast | bandit | secret | semgrep | dependency | history
    source: str = "ast"
    # Wider context (enclosing function, callers, entry-point hints) filled in before AI triage
    extended_context: str = ""
    # Deterministic findings (e.g. a known CVE for a pinned package) carry their own verdict
    # and skip the LLM entirely, so the model can never hallucinate them.
    prebuilt_result: SecurityTriageResult | None = None
