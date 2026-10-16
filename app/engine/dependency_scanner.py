"""Compatibility forwarder: use 'app.engine.scanners.dependencies' instead."""
import sys
from app.engine.scanners import dependencies

# Module namespace aliasing ensures mock.patch("app.engine.dependency_scanner.<func>") functions correctly
sys.modules[__name__] = dependencies
