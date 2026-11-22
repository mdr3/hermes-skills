#!/usr/bin/env python3
"""Attach to an app on the first pidof hit and hold the session.

Usage: frida_early_attach.py <script.js> [--pkg PKG] [--keep SECONDS]

For apps whose startup checks run before a warm attach is possible. Polls every
50 ms, attaches on the first hit, holds the session without a tty, and prints
script messages plus a liveness line every 5 s.
"""
import argparse
import sys
import threading
import time

import frida

DEFAULT_PKG = "sa.gov.moi"
DEFAULT_ACTIVITY = "com.elm.android.individual.RoutingActivity"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--pkg", default=DEFAULT_PKG)
    ap.add_argument("--activity", default=DEFAULT_ACTIVITY)
    ap.add_argument("--keep", type=float, default=60.0)
    a = ap.parse_args()

    dev = frida.get_usb_device(timeout=10)
    try:
        dev.get_process(a.pkg)
    except frida.ProcessNotFoundError:
        pass
    dev.shell(f"am start -n {a.pkg}/{a.activity}")

    pid = None
    deadline = time.time() + 15
    while time.time() < deadline:
        for p in dev.enumerate_processes():
            if p.name == a.pkg:
                pid = p.pid
                break
        if pid:
            break
        time.sleep(0.05)
    if not pid:
        print("no pid", file=sys.stderr)
        return 1
    print(f"pid {pid} after", flush=True)

    session = dev.attach(pid)  # type: ignore[arg-type]
    script = session.create_script(open(a.script).read())
    script.on("message", lambda m, d: print(f"[send] {m.get('payload', m)}", flush=True))
    script.load()
    print("attached + loaded", flush=True)

    stop = threading.Event()
    end = time.time() + a.keep
    while time.time() < end and not stop.is_set():
        try:
            alive = bool(dev.enumerate_processes() and any(p.pid == pid for p in dev.enumerate_processes()))
        except Exception:
            alive = False
        print(f"alive={alive}", flush=True)
        if not alive:
            break
        time.sleep(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
