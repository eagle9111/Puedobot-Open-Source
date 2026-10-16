"""Nonblocking repository leases shared by server threads and processes on this host."""
from __future__ import annotations

import fcntl
import hashlib
from pathlib import Path
from typing import IO


class RepositoryBusyError(ValueError):
    """Another scan owns this repository's cached checkout."""


class RepositoryLease:
    def __init__(self, key: str, directory: Path | None = None) -> None:
        directory = directory or Path.home() / ".cache" / "puedobot" / "scan-locks"
        directory.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(key.casefold().encode()).hexdigest()
        self._file: IO[str] = (directory / f"{digest}.lock").open("a+")
        try:
            fcntl.flock(self._file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._file.close()
            raise RepositoryBusyError(f"Repository {key} is already running.") from None

    def release(self) -> None:
        # Keep the lock file: unlinking it would allow two different inodes to be locked.
        if not self._file.closed:
            fcntl.flock(self._file, fcntl.LOCK_UN)
            self._file.close()

    def __enter__(self) -> RepositoryLease:
        return self

    def __exit__(self, *args: object) -> None:
        self.release()
