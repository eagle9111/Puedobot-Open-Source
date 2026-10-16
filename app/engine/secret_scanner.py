"""Compatibility forwarder: use 'app.engine.scanners.secrets' instead."""
import sys
from app.engine.scanners import secrets

sys.modules[__name__] = secrets
