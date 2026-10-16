"""Discovery stage: run every detection engine and merge their hotspots."""
from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from app.core.config import settings
from app.core.scan_budget import HotspotList
from app.core.paths import is_safe_file
from app.engine.scanners.dependencies import scan_dependencies
from app.engine.scanners.git_history import scan_git_history
from app.engine.scanners.semgrep import scan_with_semgrep
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)


@dataclass
class Discovery:
    """Mutable result holder filled in while the event generator runs."""
    hotspots: list[SuspiciousNode] = field(default_factory=HotspotList)
    total_files: int = 0


def _rel(path: str, root: str) -> str:
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return path


def run_discovery(
    target_path: str,
    sink: Discovery,
    scan_history: bool = False,
    feature_only: bool = False,
    max_files: int | None = None,
    selected_files: list[str] | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Yield progress events while filling ``sink`` with every hotspot found."""
    from app.engine.scanner import scan_file, walk_scannable_files

    seen: set[tuple[str, int]] = set()

    # 1. Determine scannable file targets (either agent-selected or walked)
    if selected_files is not None:
        target_files = [
            f if os.path.isabs(f) else os.path.join(target_path, f)
            for f in selected_files
        ]
        file_iterator = (f for f in target_files if is_safe_file(Path(target_path).absolute(), Path(f)))
    else:
        file_iterator = walk_scannable_files(target_path, feature_only=feature_only, max_files=max_files)

    # 2. Python AST + Bandit + secret scanning, file by file
    for full_path in file_iterator:
        sink.total_files += 1
        hotspots = scan_file(full_path)
        for node in hotspots:
            seen.add((node.file_path, node.line_number))
        sink.hotspots.extend(hotspots)
        yield {"type": "file_scanned", "file": _rel(full_path, target_path), "hotspots": len(hotspots)}

    # 3. Semgrep (multi-language)
    if settings.ENABLE_SEMGREP:
        yield {"type": "engine_progress", "message": "Running Semgrep multi-language rules (first run downloads rules)..."}
        nodes, notices = scan_with_semgrep(target_path)
        new_nodes = [n for n in nodes if (n.file_path, n.line_number) not in seen]
        if selected_files is not None:
            selected_full_set = {
                os.path.abspath(os.path.join(target_path, f)) if not os.path.isabs(f) else os.path.abspath(f)
                for f in selected_files
            }
            new_nodes = [n for n in new_nodes if os.path.abspath(n.file_path) in selected_full_set]

        for node in new_nodes:
            seen.add((node.file_path, node.line_number))
        sink.hotspots.extend(new_nodes)
        per_file = Counter(n.file_path for n in new_nodes)
        for path, count in per_file.items():
            sink.total_files += 1
            yield {"type": "file_scanned", "file": _rel(path, target_path), "hotspots": count}
        for notice in notices:
            yield {"type": "engine_notice", "message": notice}

    # 3. Dependency CVEs
    if settings.ENABLE_DEPENDENCY_SCAN:
        yield {"type": "engine_progress", "message": "Checking dependencies against OSV.dev..."}
        dep_nodes, notices = scan_dependencies(target_path)
        sink.hotspots.extend(dep_nodes)
        per_file = Counter(n.file_path for n in dep_nodes)
        for path, count in per_file.items():
            sink.total_files += 1
            yield {"type": "file_scanned", "file": _rel(path, target_path), "hotspots": count}
        for notice in notices:
            yield {"type": "engine_notice", "message": notice}

    # 4. Git history (opt-in: slower, and needs a repo with history)
    if scan_history:
        yield {"type": "engine_progress", "message": "Searching git history for deleted secrets..."}
        hist_nodes, notices = scan_git_history(target_path)
        sink.hotspots.extend(hist_nodes)
        for node in hist_nodes:
            yield {"type": "file_scanned", "file": f"{_rel(node.file_path, target_path)} (history)", "hotspots": 1}
        for notice in notices:
            yield {"type": "engine_notice", "message": notice}

    yield {
        "type": "scan_complete",
        "total_files": sink.total_files,
        "total_hotspots": len(sink.hotspots),
    }
