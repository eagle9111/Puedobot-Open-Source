"""Scanner regressions using synthetic manifests/code; no live providers or Git."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.engine.scanners import dependencies
from app.engine.scanners.npm_manifest import parse_npm_manifest


def write_manifest(root: Path, spec: object, *, name: str = "demo") -> Path:
    path = root / "package.json"
    path.write_text(json.dumps({"dependencies": {name: spec}}, indent=2))
    return path


def write_lock(root: Path, spec: str, *, version: object = "1.2.9", name: str = "demo",
               record: dict | None = None, filename: str = "package-lock.json", lock_version: int = 3) -> Path:
    path = root / filename
    path.write_text(json.dumps({"lockfileVersion": lock_version, "packages": {
        "": {"dependencies": {name: spec}},
        f"node_modules/{name}": record if record is not None else {"version": version},
    }}, indent=2))
    return path


@pytest.mark.parametrize("version,expected", [
    ("1.2.3", "1.2.3"), ("0.0.0", "0.0.0"), ("1.2.3-beta.1+build.9", "1.2.3-beta.1+build.9"),
    ("=1.2.3", "1.2.3"), ("v1.2.3", "1.2.3"), (" 1.2.3 ", "1.2.3"),
])
def test_exact_npm_pins_are_preserved(tmp_path, version, expected):
    manifest = write_manifest(tmp_path, version)
    entries, notices = parse_npm_manifest(str(manifest))
    assert [(entry.name, entry.version, entry.file_path) for entry in entries] == [("demo", expected, str(manifest))]
    assert notices == []


@pytest.mark.parametrize("spec", [
    "^1.0.0", "~1.2.3", ">=1.0.0 <2.0.0", "1.2.3 || 2.0.0", "1.2.3 - 2.0.0", "1.2.x", "*", "latest",
    "file:../demo-1.2.3", "workspace:^1.2.3", "git+https://synthetic.invalid/demo#v1.2.3",
    "https://synthetic.invalid/demo-1.2.3.tgz", "owner/demo#v1.2.3", "01.2.3", "1.2.3junk", "1.2.3-01",
    123, None, {}, [],
])
def test_unresolved_or_nonregistry_specs_never_reach_osv(tmp_path, monkeypatch, spec):
    write_manifest(tmp_path, spec)
    query = Mock(side_effect=AssertionError("Unresolved version must never reach OSV"))
    monkeypatch.setattr(dependencies, "_query_osv", query)
    findings, notices = dependencies.scan_dependencies(str(tmp_path))
    assert findings == []
    assert any("skipped" in notice and "demo" in notice for notice in notices)
    query.assert_not_called()


@pytest.mark.parametrize("target", ["real-package", "@scope/real-package"])
def test_exact_alias_uses_target_identity(tmp_path, monkeypatch, target):
    write_manifest(tmp_path, f"npm:{target}@1.2.3", name="alias")
    query = Mock(return_value=[[]])
    monkeypatch.setattr(dependencies, "_query_osv", query)
    assert dependencies.scan_dependencies(str(tmp_path)) == ([], [])
    query.assert_called_once_with([("npm", target, "1.2.3")])


@pytest.mark.parametrize("lock_version", [2, 3])
@pytest.mark.parametrize("spec", ["^1.0.0", "~1.2.3", "latest"])
def test_lockfile_version_is_used_instead_of_range_base(tmp_path, monkeypatch, lock_version, spec):
    write_manifest(tmp_path, spec)
    lock = write_lock(tmp_path, spec, lock_version=lock_version)
    query = Mock(return_value=[["SYNTHETIC-ADVISORY"]])
    monkeypatch.setattr(dependencies, "_query_osv", query)
    monkeypatch.setattr(dependencies, "_fetch_advisory", lambda advisory: {
        "id": advisory, "database_specific": {"severity": "HIGH"}, "summary": "Synthetic advisory"})
    findings, notices = dependencies.scan_dependencies(str(tmp_path))
    query.assert_called_once_with([("npm", "demo", "1.2.9")])
    assert notices == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == str(lock)
    assert '"node_modules/demo"' in lock.read_text().splitlines()[finding.line_number - 1]
    assert "1.2.9" in finding.code_context
    assert "recorded in package-lock.json" in finding.prebuilt_result.description


def test_lockfile_exact_alias_requires_recorded_target_identity(tmp_path):
    manifest = write_manifest(tmp_path, "npm:@scope/real@^1.0.0", name="alias")
    write_lock(tmp_path, "npm:@scope/real@^1.0.0", name="alias", record={"name": "@scope/real", "version": "1.9.0"})
    entries, notices = parse_npm_manifest(str(manifest))
    assert [(entry.name, entry.version) for entry in entries] == [("@scope/real", "1.9.0")]
    assert notices == []


@pytest.mark.parametrize("record", [
    {"version": "1.2.9", "link": True}, {"version": "1.2.9", "name": "another"},
    {"version": "^1.2.9"}, {"version": 123}, None,
    {"version": "1.2.9", "resolved": "file:../demo"},
    {"version": "1.2.9", "resolved": "git+https://synthetic.invalid/demo"},
    {"version": "1.2.9", "resolved": "https://synthetic.invalid/demo-1.2.9.tgz"},
    {"version": "1.2.9", "resolved": "https://[invalid/demo"},
])
def test_unusable_lock_entries_do_not_become_exact_findings(tmp_path, record):
    manifest = write_manifest(tmp_path, "^1.0.0")
    # None here represents an entry that is explicitly null, not the helper's default.
    lock = write_lock(tmp_path, "^1.0.0", record=record)
    if record is None:
        data = json.loads(lock.read_text())
        data["packages"]["node_modules/demo"] = None
        lock.write_text(json.dumps(data))
    entries, notices = parse_npm_manifest(str(manifest))
    assert entries == []
    assert any("skipped" in notice for notice in notices)


@pytest.mark.parametrize("kind", ["stale", "missing_root", "v1", "malformed", "symlink", "missing_version"])
def test_unsupported_or_stale_locks_do_not_resolve_ranges(tmp_path, kind):
    manifest = write_manifest(tmp_path, "^2.0.0")
    lock = tmp_path / "package-lock.json"
    if kind == "stale":
        write_lock(tmp_path, "^1.0.0")
    elif kind == "missing_root":
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/demo": {"version": "2.0.0"}}}))
    elif kind == "v1":
        lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {"demo": {"version": "2.0.0"}}}))
    elif kind == "malformed":
        lock.write_text("{")
    elif kind == "symlink":
        external = tmp_path / "external-lock"
        external.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
        lock.symlink_to(external)
    elif kind == "missing_version":
        write_lock(tmp_path, "^2.0.0", record={})
    entries, notices = parse_npm_manifest(str(manifest))
    assert entries == []
    assert notices


def test_shrinkwrap_takes_precedence_over_package_lock(tmp_path):
    manifest = write_manifest(tmp_path, "^1.0.0")
    write_lock(tmp_path, "^1.0.0", version="1.2.3")
    write_lock(tmp_path, "^1.0.0", version="1.9.0", filename="npm-shrinkwrap.json")
    entries, notices = parse_npm_manifest(str(manifest))
    assert [entry.version for entry in entries] == ["1.9.0"]
    assert notices == []


def test_invalid_shrinkwrap_does_not_fall_back_to_lower_priority_lock(tmp_path):
    manifest = write_manifest(tmp_path, "^1.0.0")
    write_lock(tmp_path, "^1.0.0")
    (tmp_path / "npm-shrinkwrap.json").write_text("{")
    entries, notices = parse_npm_manifest(str(manifest))
    assert entries == []
    assert notices


def test_single_file_scan_does_not_read_sibling_lockfile(tmp_path, monkeypatch):
    manifest = write_manifest(tmp_path, "^1.0.0")
    write_lock(tmp_path, "^1.0.0")
    query = Mock()
    monkeypatch.setattr(dependencies, "_query_osv", query)
    findings, notices = dependencies.scan_dependencies(str(manifest))
    assert findings == [] and notices
    query.assert_not_called()


@pytest.mark.parametrize("data", [[], None, {"dependencies": []}, {"dependencies": "bad"}])
def test_malformed_manifest_shapes_are_not_claimed_as_dependencies(tmp_path, data):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps(data))
    entries, notices = parse_npm_manifest(str(manifest))
    assert entries == [] and notices


def test_conflicting_declarations_and_exact_lock_conflicts_are_skipped(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"demo": "1.2.3"}, "devDependencies": {"demo": "2.0.0"}}))
    assert parse_npm_manifest(str(manifest))[0] == []
    write_manifest(tmp_path, "1.2.3")
    write_lock(tmp_path, "1.2.3", version="2.0.0")
    assert parse_npm_manifest(str(manifest))[0] == []


@pytest.mark.parametrize("name", ["stmt", "query", "users_query", "statement", "q", "request_q"])
def test_dynamic_sql_is_not_suppressed_by_variable_name(tmp_path, name):
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "dynamic.py"
    source.write_text(f'{name} = "SELECT * FROM users WHERE name=" + user\ncursor.execute({name})\n')
    nodes = scan_file_for_hotspots(str(source))
    assert [(node.function_name, node.line_number) for node in nodes] == [("cursor.execute", 2)]


@pytest.mark.parametrize("expression", [
    'text("SELECT * FROM users WHERE name=" + user)',
    'text(f"SELECT * FROM users WHERE name={user}")',
    'text("SELECT * FROM users WHERE name={}".format(user))',
    'sqlalchemy.text("SELECT * FROM users WHERE name=%s" % user)',
    'select(text(f"SELECT * FROM users WHERE name={user}"))',
    'build_query().where(text(f"name={user}"))',
    'statement.options(user)', 'query.filter(user)', 'query.join(user)',
])
def test_dynamic_sql_is_not_suppressed_by_wrapper_names(tmp_path, expression):
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "wrapped.py"
    source.write_text(f"db.execute({expression})\n")
    assert [node.function_name for node in scan_file_for_hotspots(str(source))] == ["db.execute"]


def test_shadowed_sql_wrapper_is_not_assumed_safe(tmp_path):
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "shadowed.py"
    source.write_text('def text(value):\n    return value + user\ndb.execute(text("SELECT * FROM users WHERE name="))\n')
    assert [node.line_number for node in scan_file_for_hotspots(str(source))] == [3]


@pytest.mark.parametrize("call", [
    'cursor.execute("SELECT 1")',
    'cursor.execute("SELECT * FROM users WHERE name = ?", (user,))',
    'cursor.execute("SELECT * FROM users WHERE name = %s", [user])',
    'cursor.execute("SELECT * FROM users WHERE name = :name", {"name": user})',
    'db.execute(statement="SELECT * FROM users WHERE name = :name", parameters={"name": user})',
    'cursor.execute(query="SELECT * FROM users WHERE name = %s", vars=(user,))',
    'cursor.execute(operation="SELECT 1")',
])
def test_literal_and_genuinely_bound_queries_remain_suppressed(tmp_path, call):
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "bound.py"
    source.write_text(call + "\n")
    assert scan_file_for_hotspots(str(source)) == []


@pytest.mark.parametrize("call", [
    'db.execute(statement=query)', 'cursor.execute(query=f"SELECT {user}")',
    'cursor.execute(**payload)', 'cursor.execute(query="SELECT 1", **payload)',
    'cursor.execute(query="SELECT 1", statement=user)',
    'cursor.execute("SELECT * FROM users WHERE name=" + user, {"name": user})',
])
def test_uncertain_keyword_or_interpolated_queries_are_retained(tmp_path, call):
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "uncertain.py"
    source.write_text(call + "\n")
    assert len(scan_file_for_hotspots(str(source))) == 1


def test_combined_scanner_and_discovery_receive_dynamic_sql_candidates(tmp_path, monkeypatch):
    from app.core.config import settings
    from app.engine.scanner import scan_file
    from app.engine.discovery import Discovery, run_discovery
    source = tmp_path / "dynamic.py"
    source.write_text('stmt = "SELECT * FROM users WHERE name=" + user\n'
                      'db.execute(stmt)\ndb.execute(text(f"SELECT {user}"))\n')
    nodes = scan_file(str(source))
    assert {(node.source, node.line_number) for node in nodes} >= {("ast", 2), ("ast", 3)}
    assert all(node.prebuilt_result is None for node in nodes)
    monkeypatch.setattr(settings, "ENABLE_SEMGREP", False)
    monkeypatch.setattr(settings, "ENABLE_DEPENDENCY_SCAN", False)
    sink = Discovery()
    list(run_discovery(str(tmp_path), sink))
    assert {(node.source, node.line_number) for node in sink.hotspots} >= {("ast", 2), ("ast", 3)}


def test_bound_sql_payload_stays_data_in_an_in_memory_database(tmp_path):
    import sqlite3
    from app.engine.scanners.ast_visitor import scan_file_for_hotspots
    source = tmp_path / "bound.py"
    source.write_text('cursor.execute("SELECT name FROM users WHERE name = ?", (user,))\n')
    assert scan_file_for_hotspots(str(source)) == []
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE users (name TEXT)")
        connection.execute("INSERT INTO users (name) VALUES (?)", ("ordinary",))
        payload = "' OR 1=1 --"
        assert connection.execute("SELECT name FROM users WHERE name = ?", (payload,)).fetchall() == []
    finally:
        connection.close()
