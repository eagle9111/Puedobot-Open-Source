"""Compatibility forwarder: use 'app.engine.triage.verification' instead."""
import sys
from app.engine.triage import verification

sys.modules[__name__] = verification
