"""Tests for dependency vulnerability scanning via OSV.dev (mocked and live network)."""
import os
import tempfile
import pytest
from unittest.mock import patch

from app.engine.dependency_scanner import scan_dependencies, _query_osv


def test_dependency_scan_mocked():
    """Verify dependency scanner identifies known CVEs and constructs findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        req = os.path.join(tmpdir, "requirements.txt")
        with open(req, "w") as f:
            f.write("flask==0.12.2\npyyaml==5.1\nrequests==2.33.0\n")

        with patch(f"{scan_dependencies.__module__}._query_osv") as mock_query, \
             patch(f"{scan_dependencies.__module__}._fetch_advisory") as mock_fetch:

            mock_query.return_value = [
                ["GHSA-m2qf-hxjv-5gpq"],  # flask 0.12.2 has advisories
                ["GHSA-8q59-q68h-6hv4"],  # pyyaml 5.1 has advisories
                [],                       # requests 2.33.0 is clean
            ]
            mock_fetch.return_value = {
                "id": "GHSA-m2qf-hxjv-5gpq",
                "summary": "Flask DoS vulnerability in 0.12.2",
                "database_specific": {"severity": "HIGH"},
            }

            nodes, notices = scan_dependencies(tmpdir)
            mock_query.assert_called_once()
            assert len(nodes) == 2
            assert any("flask" in n.function_name.lower() for n in nodes)
            assert any("pyyaml" in n.function_name.lower() for n in nodes)
            assert all(n.prebuilt_result is not None for n in nodes)


def test_dependency_scan_osv_failure_handled():
    """Verify that OSV downtime emits a clear warning notice and does not crash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        req = os.path.join(tmpdir, "requirements.txt")
        with open(req, "w") as f:
            f.write("flask==0.12.2\n")

        with patch(f"{scan_dependencies.__module__}._query_osv") as mock_query:
            mock_query.side_effect = ConnectionError("Connection refused by OSV.dev gateway")
            nodes, notices = scan_dependencies(tmpdir)
            mock_query.assert_called_once()

            assert nodes == []
            assert len(notices) >= 1
            assert any("OSV.dev is unreachable" in n for n in notices)


@pytest.mark.network
def test_dependency_scan_live_osv_network():
    """Live integration test against OSV.dev API (marked network)."""
    # Query flask 0.12.2 directly from OSV.dev
    results = _query_osv([("PyPI", "flask", "0.12.2")])
    assert len(results) == 1
    # flask 0.12.2 has multiple known published CVEs on OSV
    assert len(results[0]) > 0
    assert any("GHSA" in vid or "PYSEC" in vid for vid in results[0])
