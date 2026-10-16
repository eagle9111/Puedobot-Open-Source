"""Filesystem boundaries for untrusted repository paths (POSIX, like scan leases)."""
from __future__ import annotations

import io
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO
from app.core.scan_budget import CURRENT_BUDGET, BudgetedRaw, ScanLimitExceeded


def repository_parts(reference: str) -> tuple[str, str]:
    """Validate a plain owner/repository reference without rewriting path segments."""
    parts = reference.split("/")
    if len(parts) != 2 or any(
        part in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
        for part in parts
    ):
        raise ValueError("Invalid GitHub repository reference; expected owner/repository.")
    return parts[0], parts[1]


def relative_parts(root: Path, path: Path) -> tuple[str, ...]:
    """Check lexical containment before following any filesystem links."""
    if not path.is_absolute():
        path = root / path
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise ValueError("Path is outside its permitted directory.") from None
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError("Path must be a child without traversal segments.")
    return parts


def checked_path(root: Path, path: Path) -> Path:
    """Reject traversal and existing symlink components, including dangling links."""
    root = root.absolute()
    parts = relative_parts(root, path)
    if any(parent.is_symlink() for parent in (root, *root.parents)):
        raise ValueError("Symlink directories are not permitted.")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlink paths are not permitted.")
    if not current.resolve().is_relative_to(root.resolve()):
        raise ValueError("Path is outside its permitted directory.")
    return current


def is_safe_file(root: str | Path, path: str | Path) -> bool:
    """Cheap discovery filter; open_text_under performs the authoritative check."""
    try:
        return checked_path(Path(root).absolute(), Path(path)).is_file()
    except (OSError, ValueError, RuntimeError):
        return False


@contextmanager
def open_text_under(
    root: str | Path,
    path: str | Path,
    *,
    mode: str = "r",
    errors: str = "ignore",
    create_parents: bool = False,
) -> Iterator[TextIO]:
    """Open only regular files, refusing symlinks at every directory/file component.

    Directory descriptors anchor each step, so swapping a checked directory for a
    symlink cannot redirect a later open. Write mode truncates only after fstat.
    """
    if mode not in {"r", "w"}:
        raise ValueError("Only text read/write modes are supported.")
    root_path = Path(os.path.abspath(root))
    parts = relative_parts(root_path, Path(path))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    file_fd: int | None = None
    try:
        directories = (*root_path.parts[1:], *parts[:-1])
        for part in directories:
            if create_parents:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=directory)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        flags = os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= os.O_RDONLY if mode == "r" else os.O_WRONLY | os.O_CREAT
        file_fd = os.open(parts[-1], flags, 0o600, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise ValueError("Only regular files are permitted.")
        if mode == "w":
            os.ftruncate(file_fd, 0)
        budget = CURRENT_BUDGET.get() if mode == "r" else None
        if budget:
            budget.input_file(os.fspath(root_path.joinpath(*parts)))
            if os.fstat(file_fd).st_size > budget.limits.file_bytes:
                raise ScanLimitExceeded("file_bytes")
            raw = io.FileIO(file_fd, "r", closefd=True)
            file_fd = None
            handle = io.TextIOWrapper(io.BufferedReader(BudgetedRaw(raw, budget)), encoding="utf-8", errors=errors)
        else:
            handle = os.fdopen(file_fd, mode, encoding="utf-8", errors=errors)
        file_fd = None  # fdopen owns the descriptor from here onward.
        with handle:
            yield handle
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)
