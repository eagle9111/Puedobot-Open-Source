"""Bounded stream retention, delivery, and context-index regression proofs."""
import json
from unittest.mock import patch

import pytest

from app.services.scan_stream import ScanStreamBroadcaster, ScanStreamHub


@pytest.fixture(autouse=True)
def clear_hub():
    ScanStreamHub.clear()
    yield
    ScanStreamHub.clear()


def test_finished_stream_expires_from_both_lookups_at_zero_clock():
    with patch('app.services.scan_stream.time.monotonic', return_value=0):
        stream = ScanStreamBroadcaster('finished', run_id=1)
        ScanStreamHub.register(stream)
        stream.finish()
    with patch('app.services.scan_stream.time.monotonic', return_value=179):
        assert ScanStreamHub.get_by_run_id(1) is stream
        assert ScanStreamHub.get_active() is stream
    with patch('app.services.scan_stream.time.monotonic', return_value=180):
        assert ScanStreamHub.get_by_run_id(1) is None
        assert ScanStreamHub.get_active() is None
        assert ScanStreamHub._by_run_id == {}


def test_completion_capacity_keeps_running_streams_and_existing_readers():
    running = ScanStreamBroadcaster('running', run_id=1000)
    ScanStreamHub.register(running)
    first = None
    with patch('app.services.scan_stream.time.monotonic', return_value=1):
        for index in range(ScanStreamHub.MAX_COMPLETED_STREAMS + 10):
            stream = ScanStreamBroadcaster(str(index), run_id=index)
            ScanStreamHub.register(stream)
            stream.publish(json.dumps({'index': index}))
            stream.finish()
            if first is None:
                first = stream
    assert len(ScanStreamHub._by_run_id) == ScanStreamHub.MAX_COMPLETED_STREAMS + 1
    with patch('app.services.scan_stream.time.monotonic', return_value=10000):
        assert ScanStreamHub.get_by_run_id(1000) is running
        assert ScanStreamHub.get_by_run_id(0) is None
        assert json.loads(list(first.subscribe())[0]) == {'index': 0}
        assert list(ScanStreamHub._by_run_id) == [1000]


def test_no_id_stream_expires_without_evicting_running_active():
    with patch('app.services.scan_stream.time.monotonic', return_value=1):
        stream = ScanStreamBroadcaster('anonymous')
        ScanStreamHub.register(stream)
        stream.finish()
    with patch('app.services.scan_stream.time.monotonic', return_value=181):
        assert ScanStreamHub.get_active() is None
        running = ScanStreamBroadcaster('active')
        ScanStreamHub.register(running)
        assert ScanStreamHub.get_active() is running


@pytest.mark.parametrize('terminal', ['complete', 'error'])
def test_slow_subscriber_receives_latest_terminal_and_gap_notice(terminal):
    stream = ScanStreamBroadcaster('slow')
    stream.publish('{"type":"start"}')
    reader = stream.subscribe()
    assert json.loads(next(reader))['type'] == 'start'
    for index in range(2000):
        stream.publish(json.dumps({'index': index}))
    event = json.dumps({'type': terminal})
    if terminal == 'error':
        stream.finish(error_event=event)
    else:
        stream.publish(event)
        stream.finish()
    assert len(stream.subscribers[0].events) == 512
    received = [json.loads(line) for line in reader]
    assert len(received) == 513
    assert 'skipped' in received[0]['message']
    assert received[-1] == {'type': terminal}
    assert not stream.subscribers
    assert json.loads(list(stream.subscribe())[-1]) == {'type': terminal}


def test_disconnect_during_history_replay_unregisters_only_that_subscriber():
    stream = ScanStreamBroadcaster('replay')
    stream.publish('{"index":1}')
    first, second = stream.subscribe(), stream.subscribe()
    next(first)
    next(second)
    survivor = stream.subscribers[1]
    first.close()
    assert stream.subscribers == [survivor]
    stream.publish('{"index":2}')
    stream.finish()
    assert [json.loads(event) for event in second] == [{'index': 2}]
    assert not stream.subscribers


def test_finish_without_pending_events_unblocks_subscriber():
    stream = ScanStreamBroadcaster('finish')
    stream.publish('{"index":1}')
    reader = stream.subscribe()
    next(reader)
    stream.finish()
    assert list(reader) == []
    assert not stream.subscribers


def _legacy_enclosing(self, path, line):
    best = None
    for fn in self.functions.get(path, []):
        if fn.start <= line <= fn.end and (best is None or fn.end - fn.start < best.end - best.start):
            best = fn
    return best


def test_index_owners_match_original_for_decorators_defaults_nested_and_async(tmp_path):
    from app.engine.triage.context_builder import RepoIndex
    source = '''outside()
@decorate(factory())
def outer(value=default()):
    before()
    @nested_decorator()
    async def inner(value=default()):
        nested()
    class Nested:
        def method(self):
            inside_method()
    after()

class Other:
    @wrap()
    def method(self):
        other_method()
last()
'''
    target = tmp_path / 'owners.py'
    target.write_text(source)
    index = RepoIndex(str(tmp_path))
    for line in range(0, len(source.splitlines()) + 3):
        assert index.enclosing_function(str(target), line) is _legacy_enclosing(index, str(target), line)
    for sites in index.callers.values():
        for site in sites:
            assert site.caller is _legacy_enclosing(index, site.file, site.line)
    assert index.enclosing_function('missing', 1) is None


def test_range_index_preserves_ties_and_does_not_allocate_by_line_count():
    from app.engine.triage.context_builder import FunctionInfo, RepoIndex
    functions = [FunctionInfo('first', 'file', 1, 10000000),
                 FunctionInfo('tie', 'file', 1, 10000000),
                 FunctionInfo('nested', 'file', 2, 3)]
    starts, owners = RepoIndex._index_function_ranges(functions)
    assert starts == [1, 2, 4, 10000001]
    assert owners == [functions[0], functions[2], functions[0], None]


def test_f13_full_build_benchmark_and_output_equivalence(tmp_path):
    """Compare full builds; timings are measurements, never a flaky speed assertion."""
    import statistics
    import time
    from app.engine.triage.context_builder import RepoIndex

    measurements = []
    for size in (200, 1000, 3000):
        target = tmp_path / f'generated_{size}.py'
        target.write_text('\n'.join(f'def function_{i}():\n    function_0()\n    function_1()\n    function_2()' for i in range(size)))
        baseline_times, indexed_times = [], []
        for _ in range(3):
            with patch.object(RepoIndex, 'enclosing_function', _legacy_enclosing), \
                 patch.object(RepoIndex, '_index_function_ranges', return_value=([], [])):
                start = time.perf_counter()
                baseline = RepoIndex(str(target))
                baseline_times.append(time.perf_counter() - start)
            start = time.perf_counter()
            indexed = RepoIndex(str(target))
            indexed_times.append(time.perf_counter() - start)
        def signature(index):
            return {name: [(site.line, site.caller.name if site.caller else None) for site in sites]
                    for name, sites in index.callers.items()}
        assert signature(baseline) == signature(indexed)
        assert len(indexed.functions[str(target)]) == size
        assert sum(map(len, indexed.callers.values())) == size * 3
        measurements.append({'functions': size, 'calls': size * 3,
                             'before_seconds': statistics.median(baseline_times),
                             'after_seconds': statistics.median(indexed_times)})
    print('\nF13 full-build medians (3 runs): ' + json.dumps(measurements))
    (tmp_path / 'f13_measurements.json').write_text(json.dumps(measurements, indent=2))
