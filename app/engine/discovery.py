"""Compatibility forwarder: use 'app.engine.scanners.discovery' instead."""
import sys
from app.engine.scanners import discovery

sys.modules[__name__] = discovery
