"""Compatibility forwarder: use 'app.engine.triage.context_builder' instead."""
import sys
from app.engine.triage import context_builder

sys.modules[__name__] = context_builder
