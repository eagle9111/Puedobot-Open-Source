"""Pytest global configuration and test environment setup."""
import os

# Ensure a valid, non-placeholder API key of >= 32 characters is set for test collection
os.environ.setdefault("PUEDOBOT_API_KEY", "pytest-test-suite-api-key-32characters-secure")
