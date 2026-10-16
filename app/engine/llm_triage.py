"""Compatibility forwarder: use 'app.engine.triage.llm_triage' instead."""
import sys
from app.engine.triage import llm_triage

sys.modules[__name__] = llm_triage