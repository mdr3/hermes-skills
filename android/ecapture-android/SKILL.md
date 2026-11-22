---
name: ecapture-android
description: Use when capturing TLS plaintext on Android with ecapture.
---
# ecapture on Android (Cronet / Tawakkalna)

Goal: plaintext HTTPS from a BoringSSL app without a proxy or Frida. Works via eBPF uprobes; anti-Frida RASP is irrelevant here.

## Builds and paths
- When asked for the stock binary, **fetch a GitHub release, do not rebuild**: `curl -skL https://api.github.com/repos/gojue/ecapture/releases/latest`, pick `ecapture-v<ver>-android-arm64.tar.gz`, extract, push as `/data/local/tmp/ecapture-stock`, `chmod 755`, `--version`. Stock needs `-b 2` (auto BTF picks core bytecode, this ROM's BTF is unparseable, and the cleanup path panics with a nil Collection) and its stdout hook sink prints nothing — but `--stream-listen` does stream events.
- Custom fork with HAR / Burp-XML / HTTP2 export and Android-16 fixes: `/home/kali/Desktop/ecap-har` (binary `bin/ecapture`, arm64). Its vendored cilium patch is what makes map-create work on Android 16; the release asset predates it and can die `bpf token: not supported on android` — stock is for baseline/comparison, the fork is for actual capture.
- Host toolchain for rebuilding the fork: NDK 29 clang, `TARGET_ARCH=arm64 ANDROID=1 make nocore`, `GOFLAGS=-mod=mod` (go-bindata is not vendored), host tests need `CC=gcc`/`CGO_ENABLED=1`.
- Kernel 7.2 Kali headers lack `arch/x86/include/asm/compiler.h`; eBPF noncore builds need an empty shim plus `-include <src>/include/generated/autoconf.h` in `KERN_INCLUDES_NOCORE` and a constant size in `bpf_probe_read_user` calls (verifier rejects runtime lengths).

## The library that matters
- Cronet's TLS lives in `libhttpengine.so` (stripped, no `SSL_*` exports; `.gnu_debugdata` holds only FIPS crypto symbols). `libcrypto_httpengine.so` has no SSL code. `libhttpengine` is **preloaded by zygote64**.
- ecapture needs symbol names: patch a copy of `libhttpengine.so` with `SSL_read` / `SSL_write` / `SSL_do_handshake` / `SSL_set0_wbio` / `SSL_set_fd|rfd|wfd` / `_ZN4bssl14ssl_log_secret...` added to `.symtab` (values are file offsets == VAs; also set st_size, attach validates it).
- A shell-namespace `mount --bind` is invisible to apps because they inherit zygote's mount ns **and an already-loaded mapping**. Correct: bind by path in root ns, `nsenter -t $(pidof zygote64 | awk '{print $1}') -m -- mount --bind …`, then `setprop ctl.restart zygote`. Verify the app maps the patched inode (`/proc/PID/maps` inode == source inode).
- Use `su -M` (global mount namespace) for these mounts; plain `su 0 mount` can land in a transient namespace. Bind mounts do **not survive reboot** — re-apply and restart zygote before capturing, and re-check the inode instead of assuming it is still patched.
- Hook mode needs `SSL_set_fd`-style probes for SSL*→fd mapping; Cronet never calls them, so the fork adds `probe_SSL_set0_bio` attached to `SSL_set0_wbio` reading `bio->num` at `+0x20`.

## Modes
- Raw text (default, minimal style): `tls -m text` — the fork now defaults text mode to `text-source=hook` (raw SSL_read/write buffers, no keylog, no `--libssl`; the default lib scan lands on conscrypt `libssl.so` and captures Cronet traffic too). Verified `Host: snf3.nic.gov.sa` end-to-end and via eCaptureQ (`--ecaptureq` + the example client).
- `--text-source=pcapng` is opt-in for decrypt/HAR (`--text-raw` requires it). The `--libssl=…/libhttpengine.so` route still works but is only needed if the conscrypt path fails.
- Decrypt/HAR: `-m text -i <iface> --harfile x.har --xmlfile x.xml`; needs master secrets. `ssl_log_secret` exists (`0x543ed4`, BoringSecretHunter agrees) but is effectively inlined: a raw tracefs uprobe there never fires during live handshakes, and the `SSL_do_handshake` fallback (boringssl_a_13 offsets) yields no keys — so pcapng/HAR currently produces nothing on this build.
- Stream/GUI: eCaptureQ v1.2 speaks **Protobuf v2 over `--stream-listen`**, which only the stock v2.12 binary has; the fork's older `--ecaptureq`/v1 client path is NOT accepted by the GUI. Working runner: `/home/kali/Desktop/ecap-har/run_ecaptureq_gui.sh` (stock + `-b 2 --stream-listen`, adb forward, launches `ecaptureq -mode live -data-source ws://127.0.0.1:28256/events`; without `-data-source` the GUI sits in mock with no source). Details: `references/ecaptureq-gui.md`.
- v1 CLI client (fork only): `--ecaptureq ws://0.0.0.0:28257` + `adb forward tcp:28257` + `examples/ecaptureq_client/ecaptureq_client`; script `run_ecaptureq.sh`.
- `references/fritap-offsets-path.md` — Frida-based cross-check that hits the same lib by offsets (works where RASP does not kill it); useful to prove plaintext/key extraction independently of ecapture.

## Pitfalls
- `tracing_on` is 0 by default: tracefs uprobe counters read 0 and fake a "probe not firing" conclusion. `echo 1 > /sys/kernel/tracing/tracing_on` before trusting counts. Perf/uprobe attach itself works without it.
- Empty captures: prove the traffic side before blaming the probe — watch the DNAT counter change (`iptables -t nat -L OUTPUT -v`, two samples) and `ss -tn :443`; a static counter means no TLS in the window (idle/cached UI, dead route, screen asleep), a moving counter with zero events means the probe/decode is at fault. Wake and refresh the screen, then drive a real fetch.
- Attach after launch with `--pid`; never restart the app after attaching (probe stays bound to the old pid). Catch boot traffic by running without `--pid` and starting the app afterwards.
- `am start` inside `su -M -c '…'` can garble/hang — launch apps with a plain `adb shell am start` instead.
- Settings pushed earlier can outlive the run: global `http_proxy`, adb reverse/forward, DNAT rules (delete by rule number if spec-delete fails), frida-server. Clean up when done.
- `bpf_probe_read_user` with a runtime length fails the verifier on this kernel; use constant size and clamp afterwards. Nil `map` writes in decoding code panic Go — initialise before assign.

## Current device state (2026-11-22)
Patched lib `/data/local/tmp/l8.so` remains bind-mounted at `/apex/com.android.tethering/lib64/libhttpengine.so` (root + zygote ns, inode 89850). Proxy, DNAT, adb reverse/forward and frida-server are off. To revert: umount in root and zygote ns, `setprop ctl.restart zygote`.

## Repos / delivery (2026-11)
- Source + runner script: https://github.com/mdr3/ecapture-har (private, `main`). GUI patch + linux-amd64 GUI: https://github.com/mdr3/ecaptureq-compat (private). Releases are private too: download needs `gh release download` or an authenticated session; unauthenticated asset URLs 404.
- `run_ecaptureq_gui.sh` launches the GUI already connected (`ecaptureq -mode live -data-source ws://127.0.0.1:28256/events`) and cleans up server/forward on exit; it prefers `/home/kali/Desktop/ecaptureq/dist/eCaptureQ` over the packaged binary.
- GUI export buttons: HAR 1.2 and Burp XML are built client-side from classified request/response events; pretty view strips the `[ts] PID… WRITE (n bytes):` prefix and never shows hex.
- Zygote patch survives until reboot only; `run_ecaptureq_gui.sh` re-applies it automatically when the apex inode differs.
- Build env (host): `env -u CC` for every host build (the shell often carries Android NDK `CC`), tests need CGO/gcc; arm64 builds use NDK 29 with `GOFLAGS=-mod=mod`.

