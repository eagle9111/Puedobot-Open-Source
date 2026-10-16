"""Run audits independently of the HTTP connection showing their progress."""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from threading import Condition, Lock, Thread

logger = logging.getLogger(__name__)


def _gap_notice() -> str:
    return json.dumps({
        "type": "engine_notice",
        "message": "Some live progress messages were skipped. The audit continues and findings are saved to the database.",
    }) + "\n"


@dataclass(eq=False)
class _Subscriber:
    events: deque[str] = field(default_factory=lambda: deque(maxlen=512))
    omitted: bool = False

    def append(self, event: str) -> None:
        if len(self.events) == self.events.maxlen:
            self.omitted = True
        self.events.append(event)


class ScanStreamBroadcaster:
    """Buffers recent events and fans out live stream progress to multiple/reconnecting readers."""

    def __init__(self, name: str, run_id: int | None = None, history_maxlen: int = 500) -> None:
        self.name = name
        self.run_id = run_id
        self.history: deque[str] = deque(maxlen=history_maxlen)
        self.condition = Condition()
        self.finished = False
        self.finished_at: float | None = None
        self.subscribers: list[_Subscriber] = []

    def publish(self, event: str) -> None:
        with self.condition:
            self.history.append(event)
            for sub in list(self.subscribers):
                sub.append(event)
            self.condition.notify_all()

    def finish(self, error_event: str | None = None) -> None:
        with self.condition:
            if error_event:
                self.history.append(error_event)
                for sub in list(self.subscribers):
                    sub.append(error_event)
            self.finished = True
            self.finished_at = time.monotonic()
            self.condition.notify_all()
        ScanStreamHub.prune()

    def subscribe(self, replay_history: bool = True) -> Iterator[str]:
        subscriber = _Subscriber()
        q = subscriber.events
        with self.condition:
            initial = list(self.history) if replay_history else []
            from app.core.config import settings
            if len(self.subscribers) >= settings.SCAN_SUBSCRIBERS:
                raise RuntimeError("Scan subscriber limit reached")
            self.subscribers.append(subscriber)

        try:
            for evt in initial:
                yield evt
            while True:
                with self.condition:
                    self.condition.wait_for(lambda: bool(q) or self.finished)
                    if not q and self.finished:
                        return
                    evt = q.popleft()
                    skipped = subscriber.omitted
                    subscriber.omitted = False
                if skipped:
                    yield _gap_notice()
                yield evt
        finally:
            with self.condition:
                self.subscribers.remove(subscriber)


class ScanStreamHub:
    """Process-wide registry for active and recent scan streams to support client reattachment."""

    _lock = Lock()
    _active: ScanStreamBroadcaster | None = None
    _by_run_id: dict[int, ScanStreamBroadcaster] = {}
    COMPLETED_TTL_SECONDS = 180
    MAX_COMPLETED_STREAMS = 32

    @classmethod
    def _prune_locked(cls) -> None:
        now = time.monotonic()
        completed = sorted(
            ((key, stream) for key, stream in cls._by_run_id.items() if stream.finished),
            key=lambda item: item[1].finished_at if item[1].finished_at is not None else now,
        )
        excess = max(0, len(completed) - cls.MAX_COMPLETED_STREAMS)
        for index, (key, stream) in enumerate(completed):
            expired = stream.finished_at is not None and now - stream.finished_at >= cls.COMPLETED_TTL_SECONDS
            if expired or index < excess:
                del cls._by_run_id[key]
                if cls._active is stream:
                    cls._active = None
        active = cls._active
        if (active is not None and active.finished and active.finished_at is not None
                and now - active.finished_at >= cls.COMPLETED_TTL_SECONDS):
            cls._active = None

    @classmethod
    def prune(cls) -> None:
        with cls._lock:
            cls._prune_locked()

    @classmethod
    def register(cls, broadcaster: ScanStreamBroadcaster) -> None:
        with cls._lock:
            cls._active = broadcaster
            if broadcaster.run_id is not None:
                cls._by_run_id[broadcaster.run_id] = broadcaster
            cls._prune_locked()

    @classmethod
    def get_active(cls) -> ScanStreamBroadcaster | None:
        with cls._lock:
            cls._prune_locked()
            return cls._active

    @classmethod
    def get_by_run_id(cls, run_id: int) -> ScanStreamBroadcaster | None:
        with cls._lock:
            cls._prune_locked()
            return cls._by_run_id.get(run_id)

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._active = None
            cls._by_run_id.clear()


def server_owned_scan_stream(
    events: Iterator[str],
    *,
    name: str,
    run_id: int | None = None,
) -> Iterator[str]:
    """Start a worker now; closing its bounded progress feed never cancels the audit.

    The worker owns the source iterator, including its leases and cleanup. The
    response reads a progress buffer, while ScanStreamHub buffers events for
    clients that refresh, reconnect, or return after closing the browser.
    """
    broadcaster = ScanStreamBroadcaster(name=name, run_id=run_id)
    ScanStreamHub.register(broadcaster)

    progress: deque[str] = deque(maxlen=256)
    condition = Condition()
    finished = False
    primary_disconnected = False
    omitted = False

    def publish(event: str) -> None:
        nonlocal omitted
        broadcaster.publish(event)
        with condition:
            if primary_disconnected:
                return
            if len(progress) == progress.maxlen:
                omitted = True
            progress.append(event)
            condition.notify()

    def run() -> None:
        nonlocal finished
        err_msg = None
        try:
            for event in events:
                publish(event)
        except Exception:
            logger.exception("Audit worker failed: %s", name)
            err_msg = json.dumps({
                "type": "engine_notice",
                "message": "Audit stopped after a server-side error. Check server logs; saved findings remain available.",
            }) + "\n"
            publish(err_msg)
        finally:
            with condition:
                finished = True
                condition.notify_all()
            broadcaster.finish()

    def watch() -> Iterator[str]:
        nonlocal primary_disconnected, omitted
        try:
            while True:
                with condition:
                    condition.wait_for(lambda: bool(progress) or finished)
                    if not progress:
                        return
                    event = progress.popleft()
                    skipped = omitted
                    omitted = False
                if skipped:
                    yield _gap_notice()
                yield event
        finally:
            with condition:
                primary_disconnected = True
                progress.clear()

    Thread(target=run, name=f"puedobot-{name}", daemon=True).start()
    return watch()
