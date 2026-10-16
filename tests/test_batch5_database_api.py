"""Query-count, pagination, and isolated database benchmark proofs."""
import json
import statistics
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Repository, Vulnerability, ScanRun, PERFORMANCE_INDEXES
from app.schemas import FindingStatus
from app.services import repository_service as rs, vulnerability_service as vs, activity_service as ac


@pytest.fixture
def database(monkeypatch):
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    for module in (rs, vs, ac):
        monkeypatch.setattr(module, 'SessionLocal', factory)
    yield engine, factory
    engine.dispose()


def seed(factory, size, findings=5):
    with factory() as db:
        for i in range(size):
            repo = Repository(target_path=f'/synthetic/{i}', repo_name=f'owner/repo{i}',
                              scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
            db.add(repo)
            db.flush()
            db.add_all([Vulnerability(repository_id=repo.id, file_path=f'/synthetic/{i}/a.py',
                       line_number=j+1, vulnerability_type='Test', description='synthetic') for j in range(findings)])
        db.commit()


@contextmanager
def queries(engine):
    statements = []
    def record(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement)
    event.listen(engine, 'before_cursor_execute', record)
    try:
        yield statements
    finally:
        event.remove(engine, 'before_cursor_execute', record)


def test_f10_repository_counts_one_query_and_zero_findings(database):
    engine, factory = database
    seed(factory, 20)
    with factory() as db:
        db.add(Repository(target_path='/synthetic/empty', repo_name='owner/empty'))
        db.commit()
    with queries(engine) as sql:
        rows = rs.RepositoryService.list_repositories()
    assert len(sql) == 2
    assert sorted(row['findings_count'] for row in rows) == [0] + [5]*20


def test_f10_findings_eager_parent_and_remote_cache_per_directory(database):
    engine, factory = database
    seed(factory, 20)
    with queries(engine) as sql:
        rows = vs.VulnerabilityService.list_vulnerabilities('all')
    assert len(sql) == 2
    assert len(rows) == 100
    with factory() as db:
        db.query(Repository).update({'repo_name': None})
        db.commit()
    with patch.object(vs.GitService, 'get_github_remote', return_value='local/remote') as remote:
        rows = vs.VulnerabilityService.list_vulnerabilities('all')
    assert remote.call_count == 20
    assert all(row['github_repo'] == 'local/remote' for row in rows)


def test_index_ddl_matches_approved_migration():
    from sqlalchemy.schema import CreateIndex
    from sqlalchemy.dialects.postgresql import dialect
    compiled = [str(CreateIndex(index).compile(dialect=dialect())) for index in PERFORMANCE_INDEXES]
    assert len(compiled) == 8
    assert 'lower(repo_name), scanned_at DESC' in '\n'.join(compiled)
    assert "WHERE github_issue_url IS NOT NULL AND github_issue_url != ''" in compiled[-1]


def test_keyset_pages_ties_filter_binding_and_nested_details(database):
    engine, factory = database
    seed(factory, 7, findings=3)
    cursor, ids = None, []
    while True:
        result = rs.RepositoryService.repository_page(limit=2, cursor=cursor)
        ids.extend(row['id'] for row in result['repositories'])
        assert result['pagination']['total'] == 7
        cursor = result['pagination']['next_cursor']
        if not cursor:
            break
    assert ids == list(range(7, 0, -1))
    first = vs.VulnerabilityService.finding_page('all', 1, limit=2)
    token = first['pagination']['next_cursor']
    assert token
    assert vs.VulnerabilityService.finding_page('all', 1, 2, token)['findings'][0]['id'] == 3
    from app.core.pagination import InvalidCursor
    for fn in (lambda: rs.RepositoryService.repository_page(cursor=token),
               lambda: vs.VulnerabilityService.finding_page('pending', 1, cursor=token),
               lambda: vs.VulnerabilityService.finding_page('all', 2, cursor=token)):
        with pytest.raises(InvalidCursor):
            fn()
    detail = rs.RepositoryService.get_repository(1, findings_limit=2)
    assert len(detail['findings']) == 2
    assert detail['findings_pagination']['total'] == 3
    assert rs.RepositoryService.get_repository(1, 2, detail['findings_pagination']['next_cursor'])['findings'][0]['id'] == 3


@pytest.mark.parametrize('cursor', ['', '%%%%', 'e30', 'a'*2049])
def test_malformed_cursor_is_rejected(database, cursor):
    from app.core.pagination import InvalidCursor
    with pytest.raises(InvalidCursor):
        rs.RepositoryService.repository_page(cursor=cursor)


def test_activity_pages_sql_grouping_and_payload_bound(database):
    engine, factory = database
    seed(factory, 4, findings=3)
    with factory() as db:
        for finding in db.query(Vulnerability).all():
            finding.github_issue_url = f'https://github.com/owner/repo/issues/{finding.repository_id}'
        db.add_all([ScanRun(mode='MANUAL', target='synthetic', status='completed', worker_pid=1,
                            worker_host='synthetic-other-host') for _ in range(30)])
        db.commit()
    with queries(engine) as sql:
        first = ac.ActivityService.snapshot(recent_limit=2, reports_limit=2)
    assert len(sql) == 6
    assert len(first['recent_runs']) == 2
    assert len(first['reports']) == 2
    assert first['reports_count'] == 4
    assert first['recent_pagination']['total'] == 30
    assert all(row['findings_count'] == 3 for row in first['reports'])
    second = ac.ActivityService.snapshot(recent_limit=2, reports_limit=2,
                                        reports_cursor=first['reports_pagination']['next_cursor'])
    assert set(r['url'] for r in first['reports']).isdisjoint(r['url'] for r in second['reports'])


def test_cli_follows_pages_and_rejects_repeated_cursor(monkeypatch):
    import httpx
    from app.cli.client import PuedoBotClient, PuedoBotClientError
    calls = []
    def handler(request):
        calls.append(dict(request.url.params))
        cursor = request.url.params.get('cursor')
        return httpx.Response(200, json={'findings': [{'id': 2 if cursor else 1}],
            'pagination': {'next_cursor': None if cursor else 'next'}})
    monkeypatch.setattr(PuedoBotClient, '_client', lambda self: httpx.Client(transport=httpx.MockTransport(handler)))
    assert PuedoBotClient(base_url='http://synthetic').get_errors() == [{'id': 1}, {'id': 2}]
    assert calls[1]['cursor'] == 'next'
    def repeated(request):
        return httpx.Response(200, json={'findings': [], 'pagination': {'next_cursor': 'same'}})
    monkeypatch.setattr(PuedoBotClient, '_client', lambda self: httpx.Client(transport=httpx.MockTransport(repeated)))
    with pytest.raises(PuedoBotClientError, match='repeated'):
        PuedoBotClient(base_url='http://synthetic').get_errors()


def test_f10_measured_repository_query_counts(database, tmp_path):
    engine, factory = database
    records = []
    for size in (10, 100, 1000):
        # Add only the difference; no real rows and no destructive fixture operations.
        with factory() as db:
            existing = db.query(Repository).count()
        seed(factory, size - existing)
        old_times, new_times = [], []
        for _ in range(3):
            with queries(engine) as old_sql:
                start = time.perf_counter()
                with factory() as db:
                    old_rows = [(r.id, db.query(func.count(Vulnerability.id)).filter(
                        Vulnerability.repository_id == r.id).scalar()) for r in
                        db.query(Repository).order_by(Repository.scanned_at.desc(), Repository.id.desc()).all()]
                old_times.append(time.perf_counter() - start)
            with queries(engine) as new_sql:
                start = time.perf_counter()
                result = rs.RepositoryService.repository_page()
                new_times.append(time.perf_counter() - start)
        assert [(r['id'], r['findings_count']) for r in result['repositories']] == old_rows[:100]
        assert len(old_sql) == size+1 and len(new_sql) == 2
        records.append({'repositories': size, 'findings': size*5,
                        'old_selects': len(old_sql), 'new_selects': len(new_sql),
                        'old_rows_materialized': size, 'new_rows_materialized': min(size, 101),
                        'old_seconds': statistics.median(old_times), 'new_seconds': statistics.median(new_times),
                        'new_payload_bytes': len(json.dumps(result).encode())})
    print('\nF10 SQLite medians: '+json.dumps(records))
    (tmp_path/'f10.json').write_text(json.dumps(records))


def test_f11_measured_activity_history_memory(database, tmp_path):
    import tracemalloc
    engine, factory = database
    seed(factory, 1000)
    with factory() as db:
        findings = db.query(Vulnerability).all()
        for i, finding in enumerate(findings):
            finding.github_issue_url = f'https://github.com/synthetic/repo/issues/{i%2000}'
        db.add_all([ScanRun(mode='MANUAL', target='synthetic', status='completed', worker_pid=1,
                            worker_host='other', started_at=datetime(2026, 1, 1, tzinfo=timezone.utc)) for _ in range(20000)])
        db.commit()
    def legacy():
        with factory() as db:
            running = db.query(ScanRun).filter(ScanRun.status == 'running').all()
            runs = db.query(ScanRun).order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).all()
            published = (db.query(Vulnerability, Repository).join(Repository)
                         .filter(Vulnerability.github_issue_url.isnot(None), Vulnerability.github_issue_url != '')
                         .order_by(Vulnerability.id.desc()).all())
            reports = {}
            for finding, repo in published:
                report = reports.setdefault(finding.github_issue_url, {'url': finding.github_issue_url,
                    'repo_name': repo.repo_name, 'repository_id': repo.id, 'scan_mode': repo.scan_mode.value,
                    'findings_count': 0})
                report['findings_count'] += 1
            recent = [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in run.__dict__.items()
                       if not k.startswith('_') and k not in {'worker_pid', 'worker_host'}} for run in runs
                      if run.status != 'running'][:20]
            return {'running': [], 'recent_runs': recent, 'reports': list(reports.values())[:50], 'reports_count': len(reports)}
    results = {}
    for name, operation in [('before', legacy), ('after', ac.ActivityService.snapshot)]:
        timings, peaks = [], []
        for _ in range(3):
            tracemalloc.start()
            start = time.perf_counter()
            with queries(engine) as sql:
                payload = operation()
            timings.append(time.perf_counter()-start)
            peaks.append(tracemalloc.get_traced_memory()[1])
            tracemalloc.stop()
        results[name] = {'seconds': statistics.median(timings), 'peak_bytes': statistics.median(peaks),
                         'selects': len(sql), 'payload_bytes': len(json.dumps(payload).encode())}
        if name == 'before':
            expected = payload
        else:
            for key in expected:
                assert payload[key] == expected[key]
    results.update({'runs': 20000, 'findings': 5000, 'report_urls': 2000,
                    'before_orm_rows': 26000, 'after_orm_rows': 21,
                    'after_report_projection_rows': 51})
    print('\nF11 SQLite medians: '+json.dumps(results))
    (tmp_path/'f11.json').write_text(json.dumps(results))
