"""Regex, entropy, and git-aware secrets scanner."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from app.core.scan_budget import HotspotList
from app.core.paths import is_safe_file, open_text_under
from app.schemas.node import SuspiciousNode
from app.services.git_service import GitFileStatus, GitService

logger = logging.getLogger(__name__)

_PRIVATE_KEY_BEGIN = re.compile(
    r"(?i)-{0,5}BEGIN[ \t]+(?:[A-Z0-9]+[ \t-]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t-]*"
)
_PRIVATE_KEY_MARKER = re.compile(
    r"(?i)-{0,5}(?P<action>BEGIN|END)[ \t]+"
    r"(?P<label>(?:[A-Z0-9]+[ \t-]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?)[ \t-]*"
)

# Regular expressions for high-confidence security secrets & tokens
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private Key", _PRIVATE_KEY_BEGIN),
    ("GitHub Personal Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b")),
    ("Stripe API Key", re.compile(r"\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
    ("Database Credentials URI", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+\b")),
    (
        "Hardcoded Password/Secret",
        re.compile(r"(?i)\b(?:password|passwd|secret|jwt_secret|jwt_secret_key|api_secret|auth_token)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?")
    ),
]

IGNORE_PLACEHOLDERS = {
    "changeme", "your_password", "placeholder", "secret", "password",
    "xxxxxx", "123456", "example", "none", "null", "false", "true",
    "akiaiosfodnn7example",
}


def detect_secret_in_line(line: str) -> tuple[str, str] | None:
    """Return (label, matched_value) if the line contains a likely secret, else None."""
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(line)
        if match:
            matched_value = match.group(1) if match.groups() else match.group(0)
            val_lower = matched_value.lower()
            if (
                val_lower in IGNORE_PLACEHOLDERS
                or val_lower.endswith("example")
                or "placeholder" in val_lower
                or "changeme" in val_lower
            ):
                continue
            return label, matched_value
    return None


def _redact_private_keys(text: str) -> str:
    """Mask whole blocks; malformed/truncated boundaries deliberately over-redact."""
    spans: list[tuple[int, int]] = []
    labels: list[str] = []
    start = 0
    for marker in _PRIVATE_KEY_MARKER.finditer(text):
        label = re.sub(r"[ \t-]+", " ", marker["label"]).upper()
        if marker["action"].upper() == "BEGIN":
            if not labels:
                start = marker.start()
            labels.append(label)
        elif labels:
            if label == labels[-1]:
                labels.pop()
                if not labels:
                    spans.append((start, marker.end()))
        else:
            spans = [(0, marker.end())]
    if labels:
        spans.append((start, len(text)))
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.extend((text[cursor:start], "[REDACTED PRIVATE KEY]"))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact_secrets(text: str) -> str:
    """Mask recognized credentials, removing complete private-key material."""
    def _mask(value: str) -> str:
        return value[:4] + "*" * 8 if len(value) > 4 else "*" * 8

    redacted = _redact_private_keys(text)
    for _label, pattern in SECRET_PATTERNS:
        def _sub(match: re.Match) -> str:
            if match.groups():
                secret = match.group(1)
                return match.group(0).replace(secret, _mask(secret))
            return _mask(match.group(0))
        redacted = pattern.sub(_sub, redacted)
    return redacted


def scan_file_for_secrets(file_path: str) -> list[SuspiciousNode]:
    """Scan any configuration, environment, or code file for leaked secrets with Git-Awareness."""
    if not is_safe_file(Path(file_path).absolute().parent, Path(file_path).absolute()):
        return []
    filename = os.path.basename(file_path)
    findings: list[SuspiciousNode] = HotspotList()

    # 1. Git-Aware check for .env files
    if filename.startswith(".env"):
        git_status = GitService.get_git_status(file_path)

        if git_status == GitFileStatus.GITIGNORED:
            logger.info(f"Skipping {file_path}: properly ignored by .gitignore (safe local env).")
            return []

        if git_status == GitFileStatus.UNTRACKED_UNPROTECTED:
            return [
                SuspiciousNode(
                    file_path=file_path,
                    line_number=1,
                    function_name="Unprotected .env File (Missing from .gitignore)",
                    code_context=f"Warning: {filename} contains secrets and is NOT added to .gitignore. Add '{filename}' to .gitignore to prevent accidental GitHub leaks.",
                    source="secret",
                )
            ]

        if git_status == GitFileStatus.TRACKED:
            findings.append(
                SuspiciousNode(
                    file_path=file_path,
                    line_number=1,
                    function_name="Committed .env File (Git Leak)",
                    code_context=f"Critical: {filename} is tracked and committed to Git version control. Anyone cloning this repository has access to these credentials.",
                    source="secret",
                )
            )

    # 2. Pattern-based secret scanning on contents
    try:
        with open_text_under(Path(file_path).absolute().parent, Path(file_path).absolute()) as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            hit = detect_secret_in_line(line)
            if hit:
                label, _value = hit
                start = max(0, idx - 2)
                end = min(len(lines), idx + 2)
                context = "".join(lines[start:end])

                findings.append(
                    SuspiciousNode(
                        file_path=file_path,
                        line_number=idx,
                        function_name=f"Secret Leak ({label})",
                        code_context=context.strip(),
                        source="secret",
                    )
                )

    except Exception as e:
        logger.error(f"Error reading file {file_path} for secrets: {e}")

    return findings
