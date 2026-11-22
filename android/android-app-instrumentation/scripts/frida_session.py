#!/usr/bin/env python3
"""Drive a spawn/attach session against a remote frida-server without a tty.

The frida CLI reads EOF on stdin and exits right after `Resuming main thread`
when backgrounded, which looks exactly like a dying patient. This holds the
session and reports liveness instead.

usage: frida_session.py <script.js> [--timeout N] [--pid PID | --attach]
"""
import argparse
import subprocess
import threading
import time

import frida

ADDR = "127.0.0.1:61111"          # override: adb forward tcp:PORT localabstract:NAME
PKG = "com.example.target"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--attach", action="store_true")
    ap.add_argument("--pid", type=int)
    a = ap.parse_args()

    dev = frida.get_device_manager().add_remote_device(ADDR)
    if a.attach or a.pid:
        pid = a.pid or dev.get_frontmost_application().pid
        spawned = False
        print(f"[harness] attaching to pid {pid}", flush=True)
    else:
        subprocess.run(["adb", "shell", "am", "force-stop", PKG], check=False)
        time.sleep(1)
        pid = dev.spawn([PKG])
        spawned = True
        print(f"[harness] spawned pid {pid}", flush=True)

    session = dev.attach(pid)
    dead = threading.Event()
    session.on("detached", lambda r, c=None: (print(f"[harness] DETACHED {r} {c}", flush=True), dead.set()))

    script = session.create_script(open(a.script).read())
    script.on("message", lambda m, d: print(
        f"[{m['type']}] {m.get('payload')}" +
        (" stack: " + (m.get('stack') or '').replace("\n", " | ")[:600] if m.get('stack') else ""),
        flush=True))
    script.load()

    if spawned:
        dev.resume(pid)
        print("[harness] resumed", flush=True)

    t0 = time.time()
    while time.time() - t0 < a.timeout:
        if dead.is_set():
            break
        time.sleep(2)
        if subprocess.run(["adb", "shell", f"kill -0 {pid}"], capture_output=True).returncode != 0:
            print(f"[harness] process {pid} gone at t={time.time() - t0:.0f}s", flush=True)
            break
    print(f"[harness] end after {time.time() - t0:.0f}s", flush=True)
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
