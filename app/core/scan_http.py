"""Bound response materialization for OSV when a scan budget is active."""
import json
import httpx
from app.core.scan_budget import CURRENT_BUDGET, ScanLimitExceeded


def fetch_json(method, url, *, timeout, payload=None):
    budget = CURRENT_BUDGET.get()
    seconds = budget.remaining(timeout)
    with httpx.Client(timeout=seconds) as client:
        with client.stream(method, url, json=payload) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes(65536):
                budget.consume('read_bytes', len(chunk))
                if len(data) + len(chunk) > 4194304:
                    raise ScanLimitExceeded('http_output_bytes')
                data.extend(chunk)
            return json.loads(data)
