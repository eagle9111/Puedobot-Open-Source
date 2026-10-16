"""Audit workers outlive their HTTP progress readers, including absent readers."""
import json
from threading import Event

import pytest

from app.services.scan_lock import RepositoryBusyError, RepositoryLease
from app.services.scan_stream import server_owned_scan_stream


def test_closing_progress_feed_does_not_cancel_audit_or_release_lease(tmp_path):
    proceed, saved, cleaned = Event(), Event(), Event()

    def audit():
        try:
            with RepositoryLease("owner/repo", tmp_path):
                yield '{"type":"start"}\n'
                assert proceed.wait(5)
                saved.set()  # Work after the browser disconnects must still run.
                yield '{"type":"complete"}\n'
        finally:
            cleaned.set()

    feed = server_owned_scan_stream(audit(), name="disconnect-test")
    try:
        assert json.loads(next(feed))["type"] == "start"
        feed.close()
        assert not cleaned.is_set()
        with pytest.raises(RepositoryBusyError):
            RepositoryLease("owner/repo", tmp_path)
        proceed.set()
        assert saved.wait(2)
        assert cleaned.wait(2)
        with RepositoryLease("owner/repo", tmp_path):
            pass
    finally:
        proceed.set()
        cleaned.wait(2)


def test_worker_runs_even_if_browser_never_reads_response():
    saved = Event()

    def audit():
        saved.set()
        yield '{"type":"complete"}\n'

    feed = server_owned_scan_stream(audit(), name="unread-test")
    assert saved.wait(2)
    assert json.loads(next(feed))["type"] == "complete"
    assert list(feed) == []


def test_slow_reader_does_not_block_audit():
    finished = Event()

    def audit():
        for index in range(2000):
            yield json.dumps({"index": index}) + "\n"
        finished.set()

    feed = server_owned_scan_stream(audit(), name="slow-reader-test")
    assert finished.wait(2)
    events = [json.loads(event) for event in feed]
    assert len(events) < 500
    assert events[-1] == {"index": 1999}
    assert any("skipped" in event.get("message", "") for event in events)


def test_worker_errors_are_reported_and_source_is_cleaned():
    cleaned = Event()

    def audit():
        try:
            yield '{"type":"start"}\n'
            raise RuntimeError("internal diagnostic")
        finally:
            cleaned.set()

    events = [json.loads(event) for event in server_owned_scan_stream(audit(), name="failure-test")]
    assert cleaned.is_set()
    assert events[0]["type"] == "start"
    assert "server-side error" in events[-1]["message"]


def test_reattaching_subscriber_receives_buffered_and_live_events():
    from app.services.scan_stream import ScanStreamHub

    proceed = Event()

    def audit():
        yield '{"index": 1}\n'
        yield '{"index": 2}\n'
        assert proceed.wait(5)
        yield '{"index": 3}\n'

    feed = server_owned_scan_stream(audit(), name="reattach-test", run_id=99)
    assert json.loads(next(feed))["index"] == 1
    feed.close()

    active = ScanStreamHub.get_active()
    assert active is not None
    assert active.run_id == 99

    reattached = active.subscribe(replay_history=True)
    assert json.loads(next(reattached))["index"] == 1
    assert json.loads(next(reattached))["index"] == 2

    proceed.set()
    assert json.loads(next(reattached))["index"] == 3
    assert list(reattached) == []

