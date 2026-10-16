from pathlib import Path
from app.core.scan_budget import HotspotList
from app.core.scan_budget import bounded_walk
from app.core.paths import is_safe_file
import os
import logging
from typing import Generator
from app.engine.ast_parser import SuspiciousNode, scan_file_for_hotspots
from app.engine.bandit_scanner import scan_file_with_bandit
from app.engine.secret_scanner import scan_file_for_secrets


logger = logging.getLogger(__name__)

from app.core.constants import (
    CONFIG_EXACT_NAMES,
    CONFIG_EXTENSIONS,
    FEATURE_DIR_KEYWORDS,
    IGNORED_DIRS,
    IGNORED_FILES,
    NON_FEATURE_DIRS,
    is_scannable_file,
)


FEATURE_FILE_KEYWORDS = {
    "app.py", "main.py", "server.py", "views.py", "routes.py",
    "urls.py", "api.py", "auth.py", "models.py", "handlers.py", "tasks.py",
    "security.py", "crypto.py", "db.py", "database.py"
}


def is_feature_path(full_path: str) -> bool:
    """Identify if a file belongs to core business/application features.
    
    Used on large repositories to avoid scanning thousands of test/doc files
    and focus directly on high-risk feature surfaces (routes, API, controllers).
    """
    normalized = full_path.replace("\\", "/").lower()
    parts = normalized.split("/")
    filename = parts[-1]

    # Reject non-feature directories (tests, benchmarks, docs, examples)
    if any(non_feat in parts for non_feat in NON_FEATURE_DIRS):
        return False

    # Accept if inside a feature directory (e.g. app/, src/, routes/, api/, services/)
    if any(feat in parts for feat in FEATURE_DIR_KEYWORDS):
        return True

    # Accept if filename indicates core entrypoint or feature
    if filename in FEATURE_FILE_KEYWORDS:
        return True

    return False


def walk_scannable_files(
    target_path: str,
    feature_only: bool = False,
    max_files: int | None = None,
) -> Generator[str, None, None]:
    """Walk directory while pruning virtual environments, caches, tests, and non-target files.
    
    Args:
        target_path: Target root directory or direct file path.
        feature_only: When True (or on large repos), filters for core features (routes, API, models).
        max_files: Optional cap on files returned to keep scans responsive.
    """
    # If the user passed a direct file path, yield it directly
    if os.path.isfile(target_path):
        if is_scannable_file(os.path.basename(target_path)) and is_safe_file(Path(target_path).absolute().parent, Path(target_path).absolute()):
            yield target_path
        return

    yielded_count = 0
    for root, dirs, files in bounded_walk(target_path, topdown=True):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS
            and not (d.startswith(".") and d != ".env")
            and not d.endswith(".egg-info")
            and not Path(root, d).is_symlink()
            and (not feature_only or d.lower() not in NON_FEATURE_DIRS)
        ]
        for file in sorted(files):
            if not is_scannable_file(file):
                continue
            full_path = os.path.join(root, file)
            if not is_safe_file(Path(target_path).absolute(), Path(full_path).absolute()):
                continue
            if feature_only and not is_feature_path(full_path):
                continue
            yield full_path
            yielded_count += 1
            if max_files and yielded_count >= max_files:
                return


def scan_file(file_path: str) -> list[SuspiciousNode]:
    """Scan a single file using AST sink detection, Bandit security rules, and Secret detection."""
    if not is_safe_file(Path(file_path).absolute().parent, Path(file_path).absolute()):
        return []
    hotspots: list[SuspiciousNode] = HotspotList()
    seen_lines: set[int] = set()

    # 1. Python AST parsing for dangerous code sinks (eval, os.system, raw SQL)
    if file_path.endswith(".py"):
        for node in scan_file_for_hotspots(file_path):
            seen_lines.add(node.line_number)
            hotspots.append(node)

        # 2. Bandit rules for 40+ CWE classes (pickle, weak crypto, disabled SSL, permissions, etc.)
        for node in scan_file_with_bandit(file_path):
            if node.line_number not in seen_lines:
                seen_lines.add(node.line_number)
                hotspots.append(node)

    # 3. Secret & credential scanning on all code, env, and config files
    for secret_node in scan_file_for_secrets(file_path):
        if secret_node.line_number not in seen_lines:
            seen_lines.add(secret_node.line_number)
            hotspots.append(secret_node)

    return hotspots



def scan_directory(target_path: str) -> tuple[int, list[SuspiciousNode]]:
    """Scan all relevant files in target directory and return (total_files_scanned, hotspots)."""
    total_files = 0
    all_hotspots: list[SuspiciousNode] = HotspotList()

    for full_path in walk_scannable_files(target_path):
        total_files += 1
        hotspots = scan_file(full_path)
        all_hotspots.extend(hotspots)

    return total_files, all_hotspots
