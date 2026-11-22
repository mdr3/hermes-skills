---
name: burp-headless-cli
description: "Run Burp Suite Community headless as a CLI proxy."
version: 1.0.0
author: Hermes Agent
license: MIT
category: security
metadata:
  hermes:
    tags: [burp, pentest, proxy, headless, xvfb]
---

# Burp Suite headless for CLI pentests

## When to Use

When a task mandates Burp but the session is terminal-only (no X display), or when an existing Burp install must record traffic for evidence without a human at the GUI.

Burp Community has no REST API and no `--headless` scan mode, but it can be driven on a virtual display and used as the proxy that records every request in HTTP history. Useful when a task requires Burp and the only access is a terminal.

## 1. The launcher JAR is an installer

`burpsuite_desktop_v*.jar` bootstraps a download (~250 MB) and installs the real product. It is **not** Burp. `java -jar launcher.jar --help` prints the real Burp flags, which is misleading.

Skip the GUI installer entirely:

```bash
gdown=$(ls ~/Downloads/burpsuite_linux_*.sh)   # produced by the launcher wizard
chmod +x "$gdown" && "$gdown" -q -dir /home/kali/burptool -overwrite
java -jar /home/kali/burptool/burpsuite.jar --version
```

`-q -dir ... -overwrite` are install4j silent flags.

## 2. Start it on a virtual display

```bash
cd /home/kali/burptool && xvfb-run -a -s "-screen 0 1600x1000x24" \
  java -jar burpsuite.jar --use-defaults --disable-auto-update --data-dir=$HOME/.burp-data &
```

`--config-file` / `--user-config-file` with a hand-written JSON listener entry **fails** ("Could not load configuration") — do not waste cycles on it. `--use-defaults` binds the default listener on 127.0.0.1:8080 instead, so free that port first (`ss -ltnp | grep 8080`) and restart whatever owned it afterwards.

## 3. Click through the project dialog (blind, with xdotool)

The splash dialog blocks the listener. Its window is 824x516 client area; the **Next** button sits at client (720,480)-(790,502). Compute absolute coordinates from `X=`/`Y=` of `xdotool getwindowgeometry --shell <win>` and click the centre, e.g. `xdotool mousemove $((X+755)) $((Y+491)) click 1`. Pressing Return alone does nothing.

Find the right display/auth pair from `ps aux | grep Xvfb` (`-auth ...Xauthority`) and export `DISPLAY`/`XAUTHORITY` before any xdotool call.

## 4. Verify, then use

```bash
ss -ltnp | grep 8080                       # listener must be listening before you trust it
curl -sk -x http://127.0.0.1:8080 -o /dev/null -w '%{http_code}\n' https://target/
```

Every request is now in Proxy → HTTP history. `import -window <win> shot.png` for evidence screenshots; `import -window root` sometimes hangs, so retry or use `xwd`.

## Pitfalls

- **Android trust of Burp's CA is a store problem, not a Burp problem.** `targetSdk >= 24` ignores
  user certs; install into the system store via the CA module's directory and use the old subject
  hash for the filename (`openssl x509 -subject_hash_old`), plus the new `-subject_hash` name because
  proxy apps grep that for their "installed as system" indicator. Files a module binds are read-only:
  `umount` before `rm`. Keep a copy of every CA outside the module in case the module is disabled.

- `vision_analyze` on a full-size screenshot frequently times out; `convert shot.png -resize 900x small.png` usually gets through, and small dialog crops work best.
- Community has **no active scanner**; pair it with nuclei for coverage and say so in the report.
- A previous aborted launch can leave `java` holding 8080 after the `xvfb-run` wrapper is killed — kill by PID, not by wrapper name.

## Lessons (2026-11)
- The signing CA for Burp is **not** the leaf you get from `openssl s_client` to the bare listener; extract it from the CONNECT chain: `openssl s_client -proxy 127.0.0.1:8085 -connect host:443 -showcerts` and take the CA cert, hash it, install with `chcon u:object_r:system_file:s0`.
- Conscrypt reads the apex CA dir, not only `/system/etc/security/cacerts`: copy there too (125-entry apex list on Android 16) or the app will say "Trust anchor ... not found".
- Global `http_proxy` is often null while apps still emit `CONNECT`; verify per-case. A local `openssl s_server` is a fast oracle for "does the stack reach the listener" (expect TLS, not CONNECT, when DNAT is used).
- Kernel DNAT by uid is more reliable than `settings put global http_proxy` for a single app, and survives app proxy-ignoring.

