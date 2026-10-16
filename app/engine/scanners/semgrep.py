"""Semgrep adapter: multi-language SAST with taint-aware community rules."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.core.scan_budget import HotspotList
from app.core.scan_process import run_process
from app.core.scan_budget import bounded_walk, CURRENT_BUDGET
from app.core.config import settings
from app.core.constants import IGNORED_DIRS
from app.core.paths import is_safe_file, open_text_under
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)

TOOLS_VENV_BIN = os.path.expanduser("~/.cache/puedobot/tools/semgrep-venv/bin/semgrep")
MAX_RESULTS = 150
CONTEXT_RADIUS = 6


def find_semgrep() -> str | None:
    """Locate the semgrep executable: explicit setting, PATH, then PuedoBot's tools venv."""
    candidates = [settings.SEMGREP_BIN, shutil.which("semgrep"), TOOLS_VENV_BIN]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _read_context(path: str, line: int, root: str | None = None) -> str:
    try:
        with open_text_under(root or Path(path).absolute().parent, Path(path).absolute()) as handle:
            lines = handle.read().splitlines()
    except (OSError, ValueError):
        return ""
    start = max(0, line - 1 - CONTEXT_RADIUS)
    end = min(len(lines), line + CONTEXT_RADIUS)
    return "\n".join(lines[start:end])


def scan_with_semgrep(target_path: str, timeout: int = 300) -> tuple[list[SuspiciousNode], list[str]]:
    """Return (hotspots, notices). Never raises; problems become notices."""
    if not settings.ENABLE_SEMGREP:
        return [], []

    root = Path(target_path).absolute()
    if any(path.is_symlink() for path in (root, *root.parents)):
        return [], ["Semgrep skipped: symlink targets are not permitted."]
    single_file = root.is_file()
    boundary = root.parent if single_file else root
    binary = find_semgrep()
    if not binary:
        return [], [
            "Semgrep not installed: multi-language scanning is off. "
            "Install with: python3 -m venv ~/.cache/puedobot/tools/semgrep-venv && "
            "~/.cache/puedobot/tools/semgrep-venv/bin/pip install semgrep"
        ]

    for current, dirs, files in bounded_walk(root):
        if any(Path(current, name).is_symlink() for name in (*dirs, *files)):
            return [], ["Semgrep skipped: repository contains symlinks; native scanning continues."]
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

    cmd = [binary, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
           "--timeout", "20", "--max-target-bytes", "1000000"]
    for config in [c.strip() for c in settings.SEMGREP_CONFIGS.split(",") if c.strip()]:
        cmd += ["--config", config]
    for ignored in sorted(IGNORED_DIRS):
        cmd += ["--exclude", ignored]
    snapshot_root = None
    budget = CURRENT_BUDGET.get()
    if budget:
        # Semgrep opens its own paths. Feed a private, bounded snapshot so it
        # cannot read files outside the shared input ledger or growing originals.
        from app.engine.scanner import walk_scannable_files
        snapshot_root = Path(tempfile.mkdtemp(prefix="puedobot-semgrep-"))
        for original in walk_scannable_files(target_path):
            relative = Path(original).relative_to(boundary)
            destination = snapshot_root / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with open_text_under(boundary, Path(original).absolute()) as source:
                data = source.read()
            with open_text_under(snapshot_root, destination, mode="w") as output:
                output.write(data)
        cmd.append(str(snapshot_root))
    else:
        cmd.append(target_path)

    try:
        proc = run_process(cmd, capture_output=True, text=True, timeout=timeout)
        data = json.loads(proc.stdout or "{}")
    except subprocess.TimeoutExpired:
        return [], [f"Semgrep timed out after {timeout}s; results skipped."]
    except (ValueError, OSError) as exc:
        return [], [f"Semgrep failed to run: {exc}"]

    notices: list[str] = []
    if not data.get("results") and data.get("errors"):
        first = data["errors"][0].get("message", "unknown error")
        notices.append(f"Semgrep reported an error: {str(first)[:160]}")

    nodes: list[SuspiciousNode] = HotspotList()
    seen: set[tuple[str, int]] = set()
    for item in data.get("results", []):
        extra = item.get("extra", {})
        if str(extra.get("severity", "")).upper() == "INFO":
            continue
        path = item.get("path", "")
        if not os.path.isabs(path):
            path = os.path.abspath(os.path.join(os.getcwd(), path))
        if snapshot_root is not None:
            try:
                path = str(boundary / Path(path).relative_to(snapshot_root))
            except ValueError:
                continue
        if not is_safe_file(boundary, Path(path)) or (single_file and Path(path) != root):
            continue
        line = int(item.get("start", {}).get("line", 1))
        if (path, line) in seen:
            continue
        seen.add((path, line))

        rule_id = str(item.get("check_id", "rule")).split(".")[-1]
        message = str(extra.get("message", "")).strip()
        context = _read_context(path, line, str(boundary))
        nodes.append(SuspiciousNode(
            file_path=path,
            line_number=line,
            function_name=f"semgrep: {rule_id}",
            code_context=f"{context}\n\n# Semgrep rule message: {message}".strip(),
            source="semgrep",
        ))
        if len(nodes) >= MAX_RESULTS:
            notices.append(f"Semgrep returned more than {MAX_RESULTS} hits; only the first {MAX_RESULTS} are triaged.")
            break

    return nodes, notices
