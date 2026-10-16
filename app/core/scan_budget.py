"""Shared scan ledger and bounded I/O. Limits propagate through scanner adapters."""
from __future__ import annotations

import io
import os
import time
from threading import Lock
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class ScanLimitExceeded(BaseException):
    """Must cross scanner/provider exception fallbacks without becoming 'clean'."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ScanLimits:
    seconds: float = 900
    entries: int = 30000
    files: int = 3000
    file_bytes: int = 1048576
    read_bytes: int = 67108864
    hotspots: int = 1000
    triage: int = 100
    requests: int = 250
    model_bytes: int = 2097152
    output_tokens: int = 2048
    osv_workers: int = 4

    @classmethod
    def configured(cls):
        from app.core.config import settings
        return cls(**{name: getattr(settings, f'SCAN_{name.upper()}') for name in cls.__dataclass_fields__})


@dataclass
class ScanBudget:
    limits: ScanLimits = field(default_factory=ScanLimits)
    started: float = field(default_factory=time.monotonic)
    counts: dict[str, int] = field(default_factory=dict)
    lock: object = field(default_factory=Lock, repr=False)
    visited: set[str] = field(default_factory=set)
    scanned: set[str] = field(default_factory=set)

    def check(self):
        if time.monotonic() - self.started >= self.limits.seconds:
            raise ScanLimitExceeded('deadline')

    def consume(self, name: str, amount: int = 1):
        self.check()
        with self.lock:
            value = self.counts.get(name, 0) + amount
            if value > getattr(self.limits, name):
                raise ScanLimitExceeded(name)
            self.counts[name] = value

    def input_file(self, path: str):
        self.check()
        if path not in self.scanned:
            self.consume('files')
            self.scanned.add(path)

    def remaining(self, maximum: float) -> float:
        self.check()
        return max(0.001, min(maximum, self.limits.seconds - (time.monotonic() - self.started)))


CURRENT_BUDGET: ContextVar[ScanBudget | None] = ContextVar('scan_budget', default=None)
FINDING_SINK: ContextVar[object | None] = ContextVar('finding_sink', default=None)


@contextmanager
def budget_scope(budget: ScanBudget):
    token = CURRENT_BUDGET.set(budget)
    try:
        yield budget
    finally:
        CURRENT_BUDGET.reset(token)


class BudgetedRaw(io.RawIOBase):
    def __init__(self, raw, budget):
        self.raw = raw
        self.budget = budget

    def readable(self): return True
    def seekable(self): return self.raw.seekable()
    def seek(self, *args): return self.raw.seek(*args)
    def tell(self): return self.raw.tell()
    def fileno(self): return self.raw.fileno()

    def readinto(self, buffer):
        self.budget.check()
        remaining = self.budget.limits.file_bytes - self.raw.tell()
        total_left = self.budget.limits.read_bytes - self.budget.counts.get('read_bytes', 0)
        amount = min(len(buffer), max(1, remaining + 1), max(1, total_left + 1))
        data = self.raw.read(amount)
        if len(data) > remaining:
            raise ScanLimitExceeded('file_bytes')
        self.budget.consume('read_bytes', len(data))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        if not self.closed:
            self.raw.close()
        super().close()


def bounded_walk(root: str, topdown: bool = True) -> Iterator:
    """Preserve mutable dirs pruning while bounding directory enumeration itself."""
    budget = CURRENT_BUDGET.get()
    if budget is None:
        for cur, dirs, files in os.walk(root, topdown=topdown):
            dirs.sort()
            files.sort()
            yield cur, dirs, files
        return
    pending = [os.fspath(root)]
    while pending:
        current = pending.pop()
        budget.check()
        dirs, files = [], []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.check()
                    if entry.path not in budget.visited:
                        budget.consume('entries')
                        budget.visited.add(entry.path)
                    (dirs if entry.is_dir(follow_symlinks=False) else files).append(entry.name)
        except OSError:
            continue
        dirs.sort()
        files.sort()
        yield current, dirs, files
        pending.extend(os.path.join(current, name) for name in reversed(dirs)
                       if not os.path.islink(os.path.join(current, name)))


class HotspotList(list):
    """Bound each engine's temporary output as well as the merged result."""
    def append(self, item):
        budget = CURRENT_BUDGET.get()
        if budget:
            budget.check()
            if len(self) >= budget.limits.hotspots:
                raise ScanLimitExceeded('hotspots')
        super().append(item)

    def extend(self, items):
        for item in items:
            self.append(item)
