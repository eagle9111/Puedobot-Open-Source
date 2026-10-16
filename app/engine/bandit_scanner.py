"""Compatibility forwarder: use 'app.engine.scanners.bandit' instead."""
import sys
from app.engine.scanners import bandit

sys.modules[__name__] = bandit
