"""Bounded subprocess output inside a supervised scan process group."""
from __future__ import annotations
import os
import selectors
import subprocess
import time
from app.core.scan_budget import CURRENT_BUDGET, ScanLimitExceeded


def run_process(args, *, capture_output=True, text=True, timeout=120, **kwargs):
    budget = CURRENT_BUDGET.get()
    if budget is None:
        return subprocess.run(args, capture_output=capture_output, text=text, timeout=timeout, **kwargs)
    seconds = budget.remaining(timeout)
    started = time.monotonic()
    # Inherit the scan child's process group so its supervisor can reap descendants.
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs) as process:
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        with selectors.DefaultSelector() as selector:
            for handle in streams:
                os.set_blocking(handle.fileno(), False)
                selector.register(handle, selectors.EVENT_READ)
            try:
                while selector.get_map():
                    budget.check()
                    if time.monotonic() - started >= seconds:
                        raise subprocess.TimeoutExpired(args, seconds)
                    for key, _ in selector.select(min(0.1, seconds)):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        budget.consume('read_bytes', len(data))
                        if sum(map(len, streams.values())) + len(data) > 4194304:
                            raise ScanLimitExceeded('tool_output_bytes')
                        streams[key.fileobj].extend(data)
                result = process.wait(timeout=budget.remaining(max(0.001, seconds-(time.monotonic()-started))))
            except BaseException:
                process.kill()
                process.wait(timeout=2)
                raise
        stdout, stderr = (bytes(streams[handle]) for handle in (process.stdout, process.stderr))
        if text:
            stdout, stderr = stdout.decode(errors='replace'), stderr.decode(errors='replace')
        return subprocess.CompletedProcess(args, result, stdout, stderr)
