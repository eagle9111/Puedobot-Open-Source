"""Compatibility forwarder: use 'app.engine.scanners.git_history' instead."""
import sys
from app.engine.scanners import git_history

# Module namespace aliasing ensures mock.patch and monkeypatch function correctly
sys.modules[__name__] = git_history
