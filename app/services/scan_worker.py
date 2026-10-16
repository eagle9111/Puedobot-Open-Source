"""Spawned scan supervisor. No app/settings imports occur before child guards."""
from __future__ import annotations

import dataclasses
import importlib
import json
import multiprocessing
import os
import signal
import time
from contextlib import ExitStack

MAX_FRAME_BYTES = 262144


def _json_default(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json')
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if hasattr(value, 'value'):
        return value.value
    raise TypeError('Unsupported scan message')


def _send(connection, payload):
    from app.core.scan_budget import ScanLimitExceeded
    data = json.dumps(payload, default=_json_default).encode()
    if len(data) > MAX_FRAME_BYTES:
        raise ScanLimitExceeded('ipc_bytes')
    connection.send_bytes(data)


def _receive(connection):
    return json.loads(connection.recv_bytes(MAX_FRAME_BYTES))


def _child(connection, module, name, args, kwargs, limits, settings_values):
    os.setsid()
    with ExitStack() as stack:
        if os.environ.get('PUEDOBOT_ISOLATED_TEST') == '1':
            # Spawn does not inherit unittest patches. Install the same safety
            # boundaries before importing an application module in a child.
            from tests.worker_safety import install
            install(stack)
        from app.core.config import settings
        for key, value in settings_values.items():
            setattr(settings, key, value)
        from app.core.scan_budget import ScanBudget, ScanLimitExceeded, budget_scope, FINDING_SINK
        budget = ScanBudget(limits)
        def finding_sink(repo_id, node, outcome):
            _send(connection, {'kind': 'finding', 'repo_id': repo_id, 'node': node, 'outcome': outcome})
            reply = _receive(connection)
            if reply.get('kind') != 'saved':
                raise RuntimeError('Finding persistence failed')
            return reply['id']
        token = FINDING_SINK.set(finding_sink)
        try:
            with budget_scope(budget):
                _send(connection, {'kind': 'ready'})
                target = importlib.import_module(module)
                for component in name.split('.'):
                    target = getattr(target, component)
                result = target(*args, **kwargs)
                if hasattr(result, '__next__'):
                    for item in result:
                        budget.check()
                        _send(connection, {'kind': 'event', 'value': item, 'counts': budget.counts})
                else:
                    _send(connection, {'kind': 'result', 'value': result, 'counts': budget.counts})
                _send(connection, {'kind': 'done', 'counts': budget.counts})
        except ScanLimitExceeded as exc:
            _send(connection, {'kind': 'partial', 'reason': exc.reason, 'counts': budget.counts})
        except BaseException:
            _send(connection, {'kind': 'failed'})
        finally:
            FINDING_SINK.reset(token)
            connection.close()


def supervised_messages(module, name, args=(), kwargs=None, *, seconds=None, limits=None):
    """One child, bounded frames, no retries, finite parent wait and reap."""
    from app.core.scan_budget import ScanLimits, ScanLimitExceeded
    from app.core.config import settings
    limits = limits or ScanLimits.configured()
    seconds = limits.seconds if seconds is None else min(seconds, limits.seconds)
    # Explicit settings preserve programmatic configuration across spawn.
    names = ('ENABLE_SEMGREP', 'ENABLE_DEPENDENCY_SCAN', 'ENABLE_AGENT_SCOUT', 'ENABLE_VERIFIER',
             'SEMGREP_BIN', 'SEMGREP_CONFIGS', 'HISTORY_MAX_COMMITS', 'MIN_CONFIDENCE',
             'SCAN_OSV_WORKERS', 'SCAN_OUTPUT_TOKENS', 'AI_PRIORITY')
    settings_values = {key: getattr(settings, key) for key in names}
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe(duplex=True)
    process = context.Process(target=_child, args=(child, module, name, args, kwargs or {}, limits, settings_values),
                              name='puedobot-scanner', daemon=False)
    started = time.monotonic()
    ready = False
    counts = {}
    confirmed = 0
    process.start()
    child.close()
    try:
        while True:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                yield {'kind': 'partial', 'reason': 'deadline', 'counts': counts, 'confirmed': confirmed}
                return
            if not parent.poll(min(remaining, 0.1)):
                if not process.is_alive():
                    raise RuntimeError('Scan worker exited without a final status')
                continue
            try:
                packet = _receive(parent)
            except (EOFError, OSError, ValueError):
                raise RuntimeError('Invalid or incomplete scan worker message') from None
            kind = packet.get('kind')
            counts = packet.get('counts', counts)
            if kind == 'ready':
                ready = True
            elif kind == 'finding':
                from app.schemas.node import SuspiciousNode
                from app.schemas.finding import SecurityTriageResult
                from app.engine.triage.verification import Outcome, save_finding
                node_data, outcome_data = packet['node'], packet['outcome']
                if node_data.get('prebuilt_result') is not None:
                    node_data['prebuilt_result'] = SecurityTriageResult.model_validate(node_data['prebuilt_result'])
                if outcome_data.get('result') is not None:
                    outcome_data['result'] = SecurityTriageResult.model_validate(outcome_data['result'])
                # Parent-side commit must succeed before the child emits confirmed.
                identifier = save_finding(packet['repo_id'], SuspiciousNode(**node_data), Outcome(**outcome_data))
                _send(parent, {'kind': 'saved', 'id': identifier})
            elif kind == 'done':
                return
            elif kind == 'failed':
                raise RuntimeError('Scan worker failed; previously saved findings remain available')
            elif kind in {'event', 'partial', 'result'}:
                if kind == 'event' and packet['value'].get('type') == 'hotspot_confirmed':
                    confirmed += 1
                if kind == 'partial':
                    packet['confirmed'] = confirmed
                yield packet
                if kind == 'partial':
                    return
            else:
                raise RuntimeError('Unknown scan worker message')
    finally:
        # Kill the entire session group, including tools orphaned by a crashed worker.
        if ready:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif process.is_alive():
            process.terminate()
        process.join(2)
        if ready:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.is_alive():
            process.kill()
        process.join(2)
        parent.close()
        process.close()


def supervised_call(function, *args, seconds=None, **kwargs):
    from app.core.scan_budget import ScanLimitExceeded
    result = None
    for packet in supervised_messages(function.__module__, function.__qualname__, args, kwargs, seconds=seconds):
        if packet['kind'] == 'partial':
            raise ScanLimitExceeded(packet['reason'])
        if packet['kind'] == 'result':
            result = packet['value']
    return result


def scan_events(target_path, repo_id, **kwargs):
    """Public dictionary events, with explicit terminal partial state."""
    seconds = kwargs.pop('seconds', None)
    repo_name = kwargs.get('repo_name')
    for packet in supervised_messages('app.engine.orchestrator', 'stream_scan_pipeline',
                                      (target_path, repo_id), kwargs, seconds=seconds):
        if packet['kind'] == 'event':
            val = packet['value']
            if repo_name and isinstance(val, dict) and not val.get('repo_name'):
                val['repo_name'] = repo_name
            yield val
        elif packet['kind'] == 'partial':
            summary = {'partial': True, 'reason': packet['reason'], 'counts': packet['counts'], 'repo_id': repo_id, 'repo_name': repo_name}
            yield {'type': 'engine_notice', 'message': f"Partial scan: {packet['reason']}. Saved findings remain available.", **summary}
            yield {'type': 'complete', 'total_files': packet['counts'].get('files', 0),
                   'total_hotspots': packet['counts'].get('triage', 0), 'confirmed_vulnerabilities': packet.get('confirmed', 0), **summary}
