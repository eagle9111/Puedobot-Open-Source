"""Compatibility forwarder: use 'app.engine.scanners.ast_visitor' instead."""
import sys
from app.engine.scanners import ast_visitor

sys.modules[__name__] = ast_visitor