"""Bandit AST security rules scanner for Python source files."""
from __future__ import annotations

import io
import logging
import tokenize
from pathlib import Path

from bandit.core import config, manager

from app.core.scan_budget import HotspotList
from app.core.paths import open_text_under
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)


def scan_file_with_bandit(file_path: str) -> list[SuspiciousNode]:
    """Runs Bandit security rules over a Python file and returns discovered hotspots as SuspiciousNodes.

    Covers 40+ CWE vulnerability classes including:
    - B101-B108: assert, exec, chmod, hardcoded passwords, bind to all interfaces
    - B201: Flask debug mode
    - B301-B325: pickle deserialization, weak hashing (MD5/SHA1), tempfile, mktemp
    - B501-B507: disabled SSL verification (verify=False), unsafe YAML loader
    - B601-B609: shell injections (os.system, subprocess, popen)
    - B608: hardcoded SQL with dynamic string interpolation
    - B701-B703: Jinja2 autoescape disabled, XML vulnerabilities
    """
    try:
        b_conf = config.BanditConfig()
        b_mgr = manager.BanditManager(b_conf, "file")
        with open_text_under(Path(file_path).absolute().parent, Path(file_path).absolute()) as handle:
            data = handle.buffer.read()
            b_mgr._parse_file(file_path, io.BytesIO(data), [file_path])
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        source_lines = data.decode(encoding).splitlines()

        nodes: list[SuspiciousNode] = HotspotList()
        for issue in b_mgr.get_issue_list():
            # Skip pure module import warnings (B401-B414) to avoid noise on plain 'import pickle'
            if issue.test_id.startswith("B4"):
                continue

            node = SuspiciousNode(
                file_path=issue.fname,
                line_number=issue.lineno,
                function_name=f"{issue.test_id}: {issue.test}",
                code_context="".join(
                    f"{line} {source_lines[line - 1]}\n"
                    for line in range(
                        max(1, issue.lineno - 1),
                        min(len(source_lines) + 1, max(1, issue.lineno - 1) + len(issue.linerange) + 2),
                    )
                ),
                source="bandit",
            )

            nodes.append(node)

        return nodes
    except Exception as e:
        logger.warning(f"Bandit scan failed for {file_path}: {e}")
        return []
