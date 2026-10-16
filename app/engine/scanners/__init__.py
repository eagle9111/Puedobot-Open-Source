"""Deterministic SAST and dependency scanners."""
from app.engine.scanners.ast_visitor import DANGEROUS_SINKS, SecurityASTVisitor, scan_file_for_hotspots
from app.engine.scanners.bandit import scan_file_with_bandit
from app.engine.scanners.dependencies import scan_dependencies
from app.engine.scanners.discovery import Discovery, run_discovery
from app.engine.scanners.git_history import scan_git_history
from app.engine.scanners.secrets import detect_secret_in_line, redact_secrets, scan_file_for_secrets
from app.engine.scanners.semgrep import scan_with_semgrep

__all__ = [
    "DANGEROUS_SINKS",
    "SecurityASTVisitor",
    "scan_file_for_hotspots",
    "scan_file_with_bandit",
    "scan_dependencies",
    "Discovery",
    "run_discovery",
    "scan_git_history",
    "detect_secret_in_line",
    "redact_secrets",
    "scan_file_for_secrets",
    "scan_with_semgrep",
]
