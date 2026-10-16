"""Terminal POSIX cbreak shortcut listener for interactive early exit."""
from __future__ import annotations

import select
import sys
import termios
import threading
import tty
from contextlib import contextmanager
from typing import Generator


@contextmanager
def terminal_shortcut_listener(stop_event: threading.Event) -> Generator[None, None, None]:
    """Listens in the background for 'Shift + D' (ASCII 'D') or Ctrl+C to stop scanning early."""
    old_settings = None
    is_tty = sys.stdin.isatty()
    if is_tty:
        try:
            old_settings = termios.tcgetattr(sys.stdin)
        except Exception:
            is_tty = False

    thread_active = threading.Event()
    thread_active.set()

    def listen() -> None:
        try:
            if is_tty:
                tty.setcbreak(sys.stdin.fileno())
            while thread_active.is_set() and not stop_event.is_set():
                r, _, _ = select.select([sys.stdin], [], [], 0.1)
                if r:
                    ch = sys.stdin.read(1)
                    if ch in ('D', '\x03'):  # 'D' = Shift+D, \x03 = Ctrl+C
                        stop_event.set()
                        break
        except Exception:
            pass

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()
    try:
        yield
    finally:
        thread_active.clear()
        if is_tty and old_settings:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass
