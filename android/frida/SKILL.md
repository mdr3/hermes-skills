---
name: frida
description: "Use when an app fights Frida: scripts, hardening, proof."
version: 1.0.0
author: mdr3
license: MIT
metadata:
  category: Android
  short-description: "Frida bypass work: pick scripts, survive hardened targets, verify"
  hermes:
    tags: [frida, bypass, ssl-pinning, anti-root, arm64, art, cronet, eBPF]
    related_skills: [android-frida-runtime, frida-native-instrumentation, android-ebpf-crypto-tracing, ios-frida-runtime]
---

# Frida

Entry point for Frida work on authorized lab targets. Two halves: **which script** (the
Frida-Toolkit catalogue) and **how to keep a hostile app alive long enough for the script
to matter** (hardening). Most failures are the second half, not the script.

## When to Use

- The target kills the process a few seconds after the agent loads.
- A bypass "arms" but never fires, or fires and the app still refuses the request.
- You need to know which seam a detector reads before writing hooks.
- A previous session ended in an abort, an ANR, or a `SEGV` inside a PLT stub.

Not for: pure static work (`apk-static-triage`, `dex-smali-analysis`), or debugger-level
evidence where no agent should be loaded (`android-debugging-tracing`).

## 1. Pick the script by detection, not by app

The toolkit is organised by *what the app checks*. Full survey with counts, technique histograms
and quality verdicts for all 18 categories: `references/toolkit-analysis.md`. Script-by-goal
table, including the `cpp/` detector→seam pairs: `references/toolkit-catalog.md`. Read both before
writing anything from scratch — but expect to route, not copy:

- native TLS / Cronet → `Bypass-SSL-Certificate-Pinning/native-tls-hook.js` (canonical),
  `tiktok-ssl-pinning-bypass.js` / `snapchat-ssl.js` (short variants)
- stripped libs, JNI seam → `Hook-Native-Functions/registernativesdump.js`
- `/proc` and path detectors → the `cpp/` pairs, one detector per seam
- Java template → any file in `Hook-Java-Methods` (96 near-duplicates)

Only ~6 of the 140 SSL scripts touch the BoringSSL custom-verify seam; the rest are Conscrypt or
okhttp Java stubs that never fire on a Cronet app. When the library exports nothing, follow
`references/cronet-and-stripped-libs.md` down the ladder instead of throwing names at it.

The `cpp/` tree is the valuable part: each `bypass_*.js` pairs with the native module it
defeats (`maps_scan.c`, `fd_scan.c`, `mount_check.c`, `plt_check.c`, `build_native.c`,
`device_trust_native.cpp`). Use them as a map of *which syscall seam each detector reads*, then
hook that seam — the pairs teach the technique even when you do not run the file.

Combine by seam, not by count: one script per layer (CA/verify, root paths, `/proc` scrubbing,
PLT attribution), each small enough to bisect. A 40-script pile that dies tells you nothing.

## 2. Never trust a hook that "armed"

The Frida baseline here **is 17.x** (17.26.2 on the test rig) — treat its JS contract as the
normal one, not a discovery:

- **`onLeave` receives the return value as the callback argument; `this.retval` does not exist.**
  `onLeave: function (retval) { if (retval && !retval.isNull()) ... }`. Reading `this.retval` throws
  `TypeError: cannot read property 'isNull' of undefined` on *every* hit — on a hot poll loop that
  is a wall of identical errors while the hook silently does nothing.
- **To change a return, call `retval.replace(value)`** (`retval.replace(ptr(0))`), not an assignment.
- OnEnter args are positional: `args[0]`, `args[1]` … — for a `dlsym`-style wrapper the name is in
  `args[1]` (RTLD handle is `args[0]`).
- Same contract in native callbacks and in `scripts/attach_follow.py` helpers; grep for `this.retval`
  in any older script before reusing it.

Every stage prints a marker and every stage is proven by *the process still running* + a
screenshot + traffic. "Hooked" logs from a corpse are worthless. Bisect by removing one layer
at a time; the layer whose removal stops the death is the one that was keeping it alive.

## 3. Hardened-target playbook

These are rules bought with crashes on a retail Android 16 device. Detail and offsets in
`references/hardening-notes.md`; cave/ART patch mechanics in `references/arm64-cave-patching.md`.

- **Check MTE before you patch ART.** `SIGSEGV code 2 (SEGV_ACCERR)` on a tagged pointer
  (`0xb40000…`), or an abort naming `ResetQuickAllocEntryPoints(...) unimplemented`, is usually MTE
  tag mismatch, not logic: the store target is a tagged thread pointer. Confirming test and fix are
  cheap — `adb shell su -c 'setprop persist.arm64.memtag.app off'` then reboot — and with MTE off a
  hardened app often runs under spawn with only the GOT repair, no ART patch at all. Disprove MTE
  first; otherwise a whole session goes into reverse-engineering a stub that was never the problem.
  Read the fault code, not just the address: `SEGV_MAPERR` = unmapped/garbage, `SEGV_ACCERR` =
  permission/tag, `SIGILL` in your own cave = bad encoding.

- **One frida-server at a time.** Two listeners make spawn flaky in a way that looks like
  detection. Restart the server after *any* zygote restart: it caches a binder handle to
  `system_server` and spawns then fail with `DeadSystemRuntimeException` while `am start` works.
- **Spawn, load-script-while-suspended, resume.** Attaching to a live process of a hardened app
  frequently ANRs it (ART patched mid-flight). Spawn is the supported path. The mirror case is a
  process that dies at 3–6 s *during attach*: the injector's own threads trip the OEM
  `ThreadStart` callback vector and the qpoint stub before any JS runs — fix by patching libart
  through `/proc/<pid>/mem` before attaching, or use spawn (detail in `references/hardening-notes.md`).
- **Trampoline pages are not executable on some targets.** `Interceptor.replace` faults with
  `SEGV_ACCERR`; patch the body instead (`mov w0,#imm; ret`). Where the original must still run,
  build a cave with `mmap` + `mprotect(RWX)` and branch to it — `Memory.alloc` is not enough.
- **`ret` only at function entry.** `AddNativeDebugInfo*`, `Thread::ResetQuickAllocEntryPointsForThread`
  and friends do `SuspendAll`/`ResumeAll`; a mid-function `ret` leaves threads suspended and the
  next thread creation deadlocks in `Mutex::ExclusiveLock`.
- **Repair, do not fight, the GOT.** A crash whose `#00` is a PLT stub means the slot lost its
  target after the agent loaded; recompute the slot from the `adrp`/`ldr` pair and rewrite it on
  every constructor call.
- **JIT off vs on decides which crash you get.** `-Xint`/`usejit=false` sidesteps JIT-entrypoint
  crashes but pushes `AddNativeDebugInfoForDex` into an unimplemented path; with JIT on, ret only
  the *JIT* variant. Change one property at a time and restart zygote between.
- **Hide `/proc` through the `read` hook**, not by path guessing: track the fd from `openat`,
  sanitize only tracked fds, and rename agent threads in `comm`.
- **The thread-name walk is the most common anti-frida signal.** Detectors enumerate
  `/proc/self/task/*/comm` and match `gmain` / `gum-js-loop` / `pool-frida`. Sanitize by parsing the
  tid out of the path at `openat`/`open`/`fopen` time and redirecting the junk names to a copy
  holding an innocent name (`Jit thread pool`), not by renaming with `pthread_setname_np`.
- **When the app restarts instead of crashing, bisect the bundle.** A guard that rets ART internals
  can *itself* provoke the restart on a newer build; guard / hide / TLS layers each change the
  outcome, so test one layer at a time instead of assuming every restart is a detector.

## 4. Prove the hooks are in the process that matters

`spawn` returns a pid that may not be the app you end up watching: on hardened targets the process
re-forks or self-restarts at resume, so a `-f app -l agent.js` run loads every hook into a corpse
and captures nothing while the UI looks alive.

Before trusting any result, compare in the same run:

```
adb shell pidof PKG            # what the system thinks the app is
ss -tnp | grep PKG-uid        # which pid actually owns the sockets
```

Zero hits from a `connect` / `SSL_write` hook is **not** evidence of no traffic. Before touching the
script, count sockets for that exact pid (`ss -tnp | grep <pid>`): ESTAB sockets with `conn=0` mean
the traffic goes through a stack you are not hooking (Cronet pair, another linker namespace), not
that the app is idle. And when an app "keeps stopping" with the agent attached, check
`logcat -s AndroidRuntime` first — `SQLiteNotADatabaseException` is the app's own corrupt DB
(`rm -rf databases/*`), not a detection result.

If the owner is not the spawn pid, follow the live pid (poll `pidof`, attach on change) and load
the agent there — `scripts/attach_follow.py <agent.js> <hold_s> PKG` does exactly that: preloads the
agent at spawn, retries spawn across a dead `system_server`, and re-attaches to every new pid. If the
observed chain never settles, hook the restart path (`prctl`/`ProcessStablePhase` threads,
`ResetQuickAllocEntryPoints`) instead of chasing pids.

Before blaming the SDK, read the launcher activity: a `SplashActivity` that only does
`startActivity(MainActivity); finish();` has no gate of its own, so the logo is the SDK's own
loading state and the blocking check sits in the SDK thread — enumerate its probes (§6) rather than
digging through splash code.

## 5. Read plaintext at the SSL boundary (ecapture pattern)

When a proxy is not in the path — or cannot reach the target host — decrypt in-process instead of
MITM'ing: attach `SSL_write` / `SSL_read` / `SSL_set_tlsext_host_name` in `libssl.so` (and any
`*_httpengine` twin), map the `SSL*` to the SNI, and dump the buffer in `onLeave`. No CA, no trust
store, no `Interceptor.replace`. This is the check that proves a bypass actually moves bytes:
real request lines and headers, not a handshake counter. See `references/agent-authoring-pitfalls.md`
for the buffer-decoding and return-type traps that make these taps silently emit nothing.

If `Java.perform` throws `Unable to find fields in java/lang/Thread` (Android 16 + Frida 17),
it is not a bridge regression: `getThreadFields()` scans the `ArtClass` for `ArtField*` needles, and
on A16 *instance* field IDs are plain offsets (`name` -> `0x186`) while static ones are still
pointers, so the match never succeeds inside `MAX_OFFSET` (0x100). Everything below the API layer
still works — `Java.vm.getEnv()`, `env.findClass()`, `Java.vm.perform()` and raw JNI all succeed,
which is how you tell layout breakage from a dead VM. Cheapest fixes in order: widen `MAX_OFFSET`,
accept an offset needle by comparing it against the first 16 bytes of each field entry, accept the
entry that matches the static pointer needle and reuse that offset for both, and only then fall back
to raw JNI (`GetStaticMethodID` + `CallStatic*`) with the field cache left unbuilt. Note that
app-namespace classes (e.g. Cronet impls) also need the app class loader — a boot-loader `findClass`
returns `ClassNotFoundException` even when the bridge is healthy.

## 6. Enumerate what the detector probes, do not guess

Attach path loggers before writing any hiding code: hook `openat` (arg 1), `open`/`fopen`/`faccessat`
(arg 0) and log only paths matching `/proc|sys/|frida|magisk|/su|xbin|superuser`. Also hook `syscall()`
nr 56/48/78 — an obfuscated lib may bypass libc entirely, and its absence is a finding too. To locate
the SDK, hook `prctl(PR_SET_NAME)` and `pthread_setname_np` and print a backtrace: the creator frames
name the .so and the offsets of the thread walk. Typical hardened-app set: `/proc/self/cmdline`,
`/sys/devices/system/cpu/possible`, `/proc/self/task/*/comm`, `access /system/app/Superuser.apk`,
`access /system/xbin/su` — no `/proc/self/maps` at all, which is why maps scrubbing alone does nothing.

One seam is easy to miss because it never touches the filesystem: a `dlsym(RTLD_DEFAULT, name)`
loop probing `frida_agent_main` and the `ida_*` symbols. Detect it with a `dlsym` logger that prints
`args[1]` and the returning caller, then hook that caller in the RASP and let it return 0 — do not
shadow libc `dlsym` globally and do not rename the agent export (neither travels across versions).

## 7. Measure with a proxy path the app actually uses

`settings put global http_proxy` is silently ignored by many apps — traffic then never reaches the
proxy and every count reads zero. Force the path instead: `adb reverse tcp:PORT tcp:PORT`, then
DNAT the app's uid (`iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner UID -j DNAT
--to-destination 127.0.0.1:PORT`) with `net.ipv4.conf.all.route_localnet=1`. Verify with `curl` on
the device before trusting any A/B. A proxy that cannot reach the upstream host also looks exactly
like a client that rejects the chain — curl the same host from the host before blaming pinning.

## 8. Native TLS reality check

Identify the TLS owner before choosing a seam. Take the stack of a failing `connect` (or check which
module actually exports `SSL_write`): sockets created from `libc` via `libjavacore` mean Conscrypt,
where `libssl.so` / `libjavacrypto.so` live in the conscrypt apex and their exports *do* resolve by
name; only Cronet is name-blind. Getting this backwards sends a whole session at the wrong module.

On Cronet specifically: Java trust hooks (`TrustManager`, `CertificatePinner`) never fire. Worse,
Cronet's BoringSSL is statically linked and symbol-stripped: `libcrypto_httpengine.so` exports no
`X509*`/`SSL*` names, so `findExportByName` silently matches nothing. Before claiming a bypass,
check whether the module exports the symbol at all (`readelf -sW --dyn-syms`) — if not, the path
is signature/uprobe based, or you lean on the CA store being trusted.

## 9. Evidence

Syscall-level truth comes from frida-server's `syscall-trace` service (eBPF, out of process).
Headless form: `frida-strace … --headless --stack 6 --limit 200` (patch: `mdr3/frida-strace-headless`).
It answers "which `/proc` file or `su` path did it read" without perturbing the process, so use it
before blaming the script.

## Reporting style for this user

Every turn ends with the deliverable, not the reasoning: the agent path, one copy-paste command
line, and a measured number (requests decrypted, fails/gets, requests captured). Analysis-only
replies read as stalling. State blocked items plainly and say which seam is next; never claim a
bypass works off an "armed" log line.

## Related

`android-frida-runtime` (hook craft), `ios-frida-runtime`, `frida-native-instrumentation`,
`android-ebpf-crypto-tracing`, `android-app-instrumentation`.

## Sources

- Frida-Toolkit: https://github.com/Ishanoshada/Frida-Toolkit
- Frida docs: https://frida.re/docs/javascript-api/

## Lessons (2026-11)
- `-U` is not universal: this server listens on an abstract socket, so forward it and use `-H 127.0.0.1:61111`. Plain `-U` gives `unable to connect to remote frida-server: closed`.
- `Java is not defined` in `-l` scripts unless the bridge is bundled; `Java.perform` never fires under spawn here, use `Java.performNow`. Importing the bridge has a cost: it hooks ART and can hang a protected app's splash.
- Timers are dead inside this agent runtime; use an interceptor/`clock_gettime` counter instead of `setInterval`.
- Enumerate classes lazily from `ClassLoader.loadClass`; `Java.use` at script load throws `ClassNotFoundException` for dex that is not loaded yet.
- On RASP builds, attach after the app is warm and after stabilizing ART; spawn-mode instrumentation usually loses.

