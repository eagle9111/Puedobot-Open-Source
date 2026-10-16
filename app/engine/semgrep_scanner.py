"""Compatibility forwarder: use 'app.engine.scanners.semgrep' instead."""
import sys
from app.engine.scanners import semgrep

# Module namespace aliasing ensures mock.patch and monkeypatch function correctly
sys.modules[__name__] = semgrep
