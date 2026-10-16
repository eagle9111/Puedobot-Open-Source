"""Per-process scan admission: no queue, checkout starts only after a slot."""
from __future__ import annotations
from contextvars import ContextVar
from functools import wraps
from threading import Lock
import time

from fastapi import HTTPException
from app.core.config import settings
from app.core.scan_budget import ScanLimitExceeded

CURRENT_JOB = ContextVar('scan_job', default=None)


class ScanJob:
    _lock = Lock()
    _active = 0

    def __init__(self):
        with self._lock:
            if type(self)._active >= settings.SCAN_ACTIVE_JOBS:
                raise HTTPException(429, 'Scan capacity reached; try again later', headers={'Retry-After': '5'})
            type(self)._active += 1
        self.started = time.monotonic()
        self.transferred = False
        self.released = False

    def remaining(self, maximum=None):
        remaining = (maximum or settings.SCAN_SECONDS) - (time.monotonic() - self.started)
        if remaining <= 0:
            raise ScanLimitExceeded('deadline')
        return remaining

    def release(self):
        with self._lock:
            if not self.released:
                type(self)._active -= 1
                self.released = True


def admit_scan(function):
    @wraps(function)
    def accepted(*args, **kwargs):
        job = ScanJob()
        token = CURRENT_JOB.set(job)
        try:
            return function(*args, **kwargs)
        finally:
            CURRENT_JOB.reset(token)
            if not job.transferred:
                job.release()
    return accepted


def own_events(events):
    job = CURRENT_JOB.get()
    if job:
        job.transferred = True
    def owned():
        token = CURRENT_JOB.set(job)
        try:
            yield from events
        finally:
            CURRENT_JOB.reset(token)
            if job:
                job.release()
    return owned()


def schedule_job(tasks, function, *args, **kwargs):
    job = CURRENT_JOB.get()
    if job:
        job.transferred = True
    tasks.add_task(function, *args, job=job, **kwargs)
