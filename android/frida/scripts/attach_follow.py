#!/usr/bin/env python3
"""Spawn a hostile app, preload the agent, and keep hooks in whichever pid survives.

Hardened apps re-fork at resume: the pid spawn() returns is often not the process that
ends up owning the sockets, so a plain `frida -f app -l agent.js` installs every hook into
a corpse. This driver preloads the agent at spawn (so the spawn window is covered when the
process is the same one) and attaches to every new pid that appears, then holds.

Usage: attach_follow.py <agent.js> [hold_seconds]
Env:   PKG (default: derived from argv[3]), SRV (default 127.0.0.1:61113), ABST (unix:rasp3)
"""
import os
import subprocess
import sys
import time

import frida

PKG = os.environ.get("PKG") or (sys.argv[3] if len(sys.argv) > 3 else None)
SRV = os.environ.get("SRV", "127.0.0.1:61113")
ABST = os.environ.get("ABST", "unix:rasp3")
JS = sys.argv[1]
HOLD = int(sys.argv[2]) if len(sys.argv) > 2 else 45
FOLLOW_S = 55

if not PKG:
    raise SystemExit("need a package (env PKG or argv[3])")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def pids():
    return sh(f"adb shell pidof {PKG}").split()


def ensure_server():
    """A frida-server dies with the zygote/system_server it was bound to; respawn it."""
    if sh("adb shell 'su -c \"pidof frida-server || pidof sctd\"'").strip():
        return
    sh(f"adb shell 'su -c \"nohup /data/local/tmp/friservers/sctd -l {ABST} >/dev/null 2>&1 &\"'")
    time.sleep(4)
    port = SRV.rsplit(":", 1)[-1]
    sh("adb forward --remove-all")
    sh(f"adb forward tcp:{port} localabstract:{ABST.split(':')[-1]}")


ensure_server()
dev = frida.get_device_manager().add_remote_device(SRV)
dev.on("output", lambda pid, fd, data: print(data.decode("utf-8", "ignore").rstrip()) if data else None)

# force-stop needs a beat; an older instance otherwise stays in pidof and muddies every reading
sh(f"adb shell am force-stop {PKG}")
time.sleep(3)

sp = None
for _ in range(4):
    try:
        sp = dev.spawn([PKG])
        break
    except Exception as e:
        print("spawn retry", type(e).__name__, flush=True)
        ensure_server()
        time.sleep(2)
if sp is None:
    raise SystemExit("spawn failed")

# preload the REAL agent while suspended: an empty preload leaves the spawn pid unhooked
try:
    s0 = dev.attach(sp)
    sc0 = s0.create_script(open(JS).read())
    sc0.on("message", lambda m, d: None)
    sc0.load()
    print("preload", sp, flush=True)
except Exception as e:
    print("preload fail", type(e).__name__, flush=True)
dev.resume(sp)

hooks = {}
for p in [sp]:
    hooks[str(p)] = True

t0 = time.time()
while time.time() - t0 < FOLLOW_S:
    for cur in pids():  # pidof can print several pids: split, never int() the whole line
        if cur in hooks:
            continue
        try:
            s = dev.attach(int(cur))
            sc = s.create_script(open(JS).read())
            sc.on("message", lambda m, d: None)
            sc.load()
            hooks[cur] = True
            print("hooked", cur, flush=True)
        except Exception as e:
            print("attach-miss", cur, type(e).__name__, flush=True)
    time.sleep(0.05)

print("pids", pids(), "hooked", list(hooks), flush=True)
time.sleep(HOLD)
print("end", pids(), flush=True)
