"""Git history secret scanner."""
from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

from app.core.scan_budget import HotspotList
from app.core.scan_process import run_process
from app.core.config import settings
from app.core.constants import IGNORED_DIRS, IGNORED_FILES
from app.core.paths import checked_path
from app.engine.scanners.secrets import detect_secret_in_line
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)

SKIP_EXTENSIONS = {
    ".md", ".rst", ".txt", ".lock", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf", ".min.js", ".map", ".csv",
}
MAX_LINE_LENGTH = 500
MAX_CANDIDATES = 200
HEAD_CHECK_TIMEOUT_SECONDS = 120
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _git(repo: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return run_process(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout)


def _skip_file(path: str) -> bool:
    parts = path.split("/")
    if any(part in IGNORED_DIRS for part in parts[:-1]):
        return True
    name = parts[-1]
    if name in IGNORED_FILES:
        return True
    return any(name.endswith(ext) for ext in SKIP_EXTENSIONS)


def scan_git_history(target_path: str) -> tuple[list[SuspiciousNode], list[str]]:
    """Return (hotspots, notices) for secrets that exist only in past commits."""
    probe = target_path if os.path.isdir(target_path) else os.path.dirname(os.path.abspath(target_path))
    top = _git(probe, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return [], ["History scan skipped: target is not inside a git repository."]
    repo = top.stdout.strip()

    notices: list[str] = []
    if _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        notices.append("Repository is a shallow clone: only the fetched part of the history was searched.")

    try:
        log = _git(
            repo, "log", "--all", "-p", "-U0", "--no-color", "--no-renames",
            f"--max-count={settings.HISTORY_MAX_COMMITS}",
            "--pretty=format:@@COMMIT\t%H\t%an\t%ad", "--date=short",
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return [], ["History scan timed out; results skipped."]
    if log.returncode != 0:
        return [], [f"History scan failed: {log.stderr.strip()[:160]}"]

    candidates: dict[tuple[str, str], dict] = {}
    commit = author = date = ""
    current_file: str | None = None
    new_line = 0

    for raw in log.stdout.splitlines():
        if raw.startswith("@@COMMIT\t"):
            _, commit, author, date = raw.split("\t", 3)
            current_file = None
            continue
        if raw.startswith("+++ "):
            current_file = raw[6:] if raw.startswith("+++ b/") else None
            if current_file and _skip_file(current_file):
                current_file = None
            continue
        if raw.startswith("@@"):
            match = _HUNK.match(raw)
            new_line = int(match.group(1)) if match else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++") and current_file:
            text = raw[1:]
            line_no = new_line
            new_line += 1
            if len(text) > MAX_LINE_LENGTH or text.strip().startswith(("#", "//")):
                continue
            hit = detect_secret_in_line(text)
            if not hit:
                continue
            label, value = hit
            key = (current_file, value)
            if key not in candidates and len(candidates) < MAX_CANDIDATES:
                candidates[key] = {
                    "label": label, "value": value, "line": line_no, "text": text.strip(),
                    "commit": commit, "author": author, "date": date,
                }

    nodes: list[SuspiciousNode] = HotspotList()
    target = Path(target_path).absolute()
    boundary = target if target.is_dir() else target.parent
    for (file, value), info in candidates.items():
        try:
            candidate_path = checked_path(boundary, Path(repo) / file)
        except (OSError, ValueError, RuntimeError):
            continue
        if target.is_file() and candidate_path != target:
            continue
        # Still present at HEAD? Then the regular scan already reports it; skip to avoid duplicates.
        try:
            presence = _git(repo, "grep", "-qF", "-e", value, "HEAD", "--", timeout=HEAD_CHECK_TIMEOUT_SECONDS)
        except (subprocess.SubprocessError, OSError):
            # Exception text/commands can contain the credential being checked.
            notices.append("History HEAD check failed; remaining candidates skipped because absence could not be established.")
            break
        if presence.returncode == 0:
            continue
        if presence.returncode != 1:
            notices.append("History HEAD check failed; remaining candidates skipped because absence could not be established.")
            break
        sha = info["commit"][:8]
        context = (
            f"Commit {sha} by {info['author']} on {info['date']}\n"
            f"File: {file} (line {info['line']} in that commit)\n"
            f"Added line:\n{info['text']}\n\n"
            "NOTE: this value is NOT present at the current HEAD, but it remains readable in git history "
            "(`git log -p`). Deleting a leaked secret does not revoke it; it must be rotated."
        )
        nodes.append(SuspiciousNode(
            file_path=str(candidate_path),
            line_number=info["line"],
            function_name=f"Historical Secret Leak ({info['label']}) in commit {sha}",
            code_context=context,
            source="history",
        ))

    if len(candidates) >= MAX_CANDIDATES:
        notices.append(f"History scan capped at {MAX_CANDIDATES} candidate secrets.")
    return nodes, notices
