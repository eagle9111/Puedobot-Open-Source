"""Compatibility forwarder: use 'app.engine.triage.scout' instead."""
import sys
from app.engine.triage import scout

sys.modules[__name__] = scout
