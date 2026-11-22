---
name: android-app-instrumentation
description: Use when instrumenting or bypassing a protected Android app.
version: 1.1.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [android, frida, rasp, ssl-pinning, injection]
    related_skills: [android-frida-runtime, apk-static-triage]
---

# Android app instrumentation

For apps that fight back: integrity checks, anti-Frida procfs sweeps, SSL pinning.
The deliverable is an interceptable session, not a payload that merely loads.

## When to Use

- a protected APK dies or hangs as soon as instrumentation is attached;
- SSL pinning has to be defeated and the trust decision is not in Java;
- the runtime itself aborts under a debugger and the payload is not the variable.

Start at the workflow below; for a process that dies in seconds, jump straight to
`references/raw-injection-gadget.md` instead of rewriting the payload.

## Deliverable and ordering

- **The run command is handed over as one `frida` CLI line, and the payload is a plain
  script.** `frida -H <host:port> -p $(adb shell pidof <pkg> | tr ' \r' '\n\n' | head -1)
  -l <payload.js>`, wrapped in the same line as the relaunch (force-stop launcher+app,
  `am start`, short sleep). frida-tools injects the Java bridge for `-l`, so **no bundle is
  needed on this path** — a ~60-line plain file beats a ~240 KB / ~1800-line bundle that
  reads like the payload is huge. Bundle only when the script is created by a driver
  (`create_script` has no bridge) or the user asks for one. A Python driver is internal
  scaffolding — this user rejects it as the answer ("i did not ask for python warper") — so
  keep the CLI line as the deliverable and mention a retry loop only because the first
  attach can die, not as a replacement.
- **One self-contained Frida script.** This user wants the bypass *as the script*:
  no BPF exit helper, no `guard.sh` wrapper, no gadget in the APK, no APK edit. A
  patch that only works because something outside the script stopped the process
  or wrote the bytes does not count. Helper binaries are fine for *measuring*,
  never as part of the answer.
- **RASP first, TLS second.** Do not start on pinning while the app still dies:
  prove the anti-Frida side by having the user complete a real login (an SSO app
  only exercises its harsh path there), and only then bypass TLS.
- **Never `pm clear` once the user is logged in.** They will not re-authenticate
  for your convenience. `am force-stop` + `am start` preserves the session;
  clear data only when the app's own state is provably rotten, and say so.
- **Proxy plumbing is handed over as one pasteable line, with its revert.** This user
  runs the commands himself: the line carries the uid lookup (`stat -c %u
  /data/data/<pkg>`, never hardcoded), the `adb reverse` to the port the proxy actually
  listens on, the `settings put global http_proxy`, and the teardown (`:0`, `iptables
  -t nat -F OUTPUT`, `reverse --remove-all`). Name the variable `APPUID`: zsh treats
  `UID` as a read-only special parameter and `UID=$(…)` dies with
  `zsh: failed to change user ID: operation not permitted` before any adb call runs.
  Check the port first (`ss -ltnp | grep <port>`): a reverse to a port nothing listens
  on accepts the TCP connect and then aborts mid-handshake, which reads as an app bug.

## Workflow

1. **Baseline before anything.** Run the app clean, note how it looks and how long
   it lasts. Then run a bare agent (a script whose only line is a `console.log`).
   If the app dies or hangs with a bare agent, the tracer/payload is not the
   variable — the agent's presence is, and blockers alone will not save it.
   **Confirm the clean run is really clean:** disable and unscope every other
   injector first (LSPosed/Xposed modules, a stray gadget). A scoped module is a
   JVMTI injector and reproduces a runtime abort byte-for-byte, so a crashing
   "clean" baseline sends you off to reverse a defect the app does not have.
   Classify *where* it dies before designing a blocker: a crash whose frames are
   in `libart.so`/`boot.oat`, before the app ever draws, is a defect in the
   runtime, not in the app's check. Fix the runtime first — no anti-Frida hook
   can be validated on top of a process that dies in 2 s. `references/frida-payload-layers.md`
   has the mechanism and the patch.
   A bare attach that survives under a second and then dies proves the same
   thing: it is not the payload, so stop rewriting the payload.
2. **Trace kernel-side first.** eBPF tracers are invisible to the app's own
   procfs scanning, so they work when Frida hooks already kill it. Filter by the
   app's uid, not by name, and look at the *sequence* around the kill
   (`sched_process_exit` is your anchor). Build recipes: `references/ebpf-tracer-builds.md`.
3. **Read the trace before designing anything.** A short, tight sequence of
   `openat`/`clone`/`readlinkat` right before exit is the check itself; it tells
   you which paths to spoof and which call sites to hook. Do not invent a
   spoofing plan from the app's source alone.
4. **Make the agent invisible before repairing the runtime.** A RASP that decides
   "instrumented" does not merely report — it damages the process (in this class of
   app by repainting ART runtime data). Defeating the cheap probes so the verdict
   never flips is usually cheaper and more stable than guarding the damage:
   thread names in `/proc/self/task/*/comm` and a `su`-path probe are the two to
   check first, and both die to one small native payload (`scripts/stealth_procfs.js`).
   Only if the app still dies go on to patch the runtime.
5. **Patch at the highest tolerated layer.** Order of preference: the app's own
   PLT stubs → the app's own functions → libc → ART/Java. Every step down costs
   tolerance; see the pitfalls.
6. **Only then unpin TLS**, and prefer the crypto library over Java when the ART
   layer is unstable — see `references/frida-payload-layers.md`.
7. **When the runtime defect cannot be patched in memory, ship a repackaged
   APK instead.** Removing a pin check from smali beats fighting the agent, but
   repackaging changes the signer and a hardened app reads that as tampering.
   Attribute before shipping: install the app's own APK untouched, then the
   same bytes re-signed with your key, and compare. Recipe and pitfalls:
   `references/apk-repack-and-modules.md`, driver `scripts/apk_repack.py`.
7. **Verify with evidence, not logs.** Request through mitmproxy and confirm a

## Capture setup

```
mitmdump --listen-port 8080 --set confdir=~/.mitmproxy -w /tmp/flows.mitm
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080     # unset: ':0'
```

Install the CA into `/data/misc/user/0/cacerts-added/<subject_hash_old>.0` with
`chmod 644` + `restorecon`. A bare agent plus a user CA still decrypts traffic
from hosts that trust user certs — that is your proof the proxy path works, and
the control the unpin has to beat.

**`http_proxy` alone is not enough.** Hardened apps routinely ignore the system
proxy (the platform stack they use — Cronet, a pinned OkHttp client — never
consults it), so a proxy-only setup captures the GMS connectivity checks and
nothing from the target. Redirect the uid instead; recipes and their
limitations: `references/mitm-capture-recipes.md`. Verify the plumbing with
`curl` through the redirect before blaming the app, and remember that
`settings put global http_proxy 127.0.0.1:PORT` silently reverts to `:0` —
re-read it after setting.

**Enforce in netfilter and sign with the CA you installed.** `REDIRECT` to loopback
plus `adb reverse` makes mitm forward to itself (`Request destination unknown`,
HTTP 502), so `DNAT` to the host's own address instead and let transparent mode
resolve the upstream from the SNI (`--set connection_strategy=lazy`); `curl`
without `-k` must return 200 before the app is worth touching. For `targetSdk` ≥ 24
the CA has to be a *platform* CA, and mitm has to sign with that same CA — extract
key and cert from the provisioning `.p12` into `<confdir>/mitmproxy-ca.pem` so the
chain the app verifies is the chain you installed. `-k` in the verification curl
hides exactly the failure being tested. Recipes: `references/mitm-capture-recipes.md`.

When the proxy is unusable, `SSL_read`/`SSL_write` hooks still hand you the
plaintext (request line, headers, bodies). They prove the app talks and what it
sends; they do **not** prove the app accepted a substituted certificate. Say
which of the two you have.

## Hardened-app facts to establish before writing hooks

- **Measure with pid equality, not `pidof` presence.** On a hardened target the spawn can die in
  under 2 s *with an empty script* while Android immediately restarts it; a presence check then reads
  green while the session is already detached and nothing is hooked. Compare `pidof` output to the
  spawned pid every few seconds and treat a different pid as failure.
- **Hook breadth kills startup.** Attaching `connect` across `Process.enumerateModules()` (with or
  without a re-arm timer) aborted startup before 10 s; attaching the same symbol in `libc.so` only
  stayed alive indefinitely. Hook the single module you need, never sweep.
- **Assume the file probes bypass libc.** A protected native lib can carry dozens of inline
  `svc #0` sites (`openat 0x38`, `read 0x3f`, `close 0x39`) so `open`/`fopen` hooks see nothing.
  Locate them with `r2 '/ad svc'` and correlate the `mov w8, #nr` before each site before trusting
  any libc-level spoof.
- **The watchdog is continuous, not a boot check.** A real case polls `/proc/<tid>/maps`,
  `/proc/self/status` (TracerPid), `/proc/self/task`, `/proc/self/fd` and `task/<tid>/comm` about
  once a second on a dedicated thread. Any spoof has to be resident and cover all five; a one-shot
  scrub at load only delays the abort.
- **Read the tombstone before trusting a theory.** Aborts here surfaced as `LOG(FATAL)` inside
  `art::ResetQuickAllocEntryPoints` (crash actually in libc++ ostream / `ToReflectedMethod`), and one
  `libmedia` GOT slot (`libmedia+0xab3c8`) needed repair or dlopen-era faults followed. `adb logcat -b crash`
  plus `/data/tombstones` is the cheapest source of truth.
- **Map native registration fast.** Protected libs register methods in bulk right after
  `System.loadLibrary` against obfuscated classes; a small tracer that swipes the JNIEnv vtable's
  `RegisterNatives` target and prints class/name/signature/offset produces the whole API surface in
  one run. `jnitrace` itself only captured `JNI_OnLoad` on Android 16 and is not a substitute.

## Pitfalls

- **Frida 17 return values are callback arguments, not context properties.** Use
  `onLeave: function (retval)`, read with `retval.toInt32()`, rewrite with `retval.replace(v)`.
  `this.retval` is undefined and `this.retval.isNull()` throws `TypeError: cannot read property
  'isNull' of undefined` on every hit — fatal-looking error spam on hot functions while the hook
  silently no-ops. Argument order follows the C prototype (`args[1]` is the symbol string in a
  `dlsym`-style wrapper; `args[0]` is the RTLD handle). Fix stale snippets before trusting them.

- **`Process.findModuleByName()` inside a `pthread_create` hook deadlocks ART** on
  arm64 Android 14+. ART holds the loader lock there; the symptom is SIGSEGV in
  `Jit thread pool` or the frontend threads. Cache `base`/`end` from a `dlopen`
  hook and only compare against the cached range.
- **A top-level `Java.perform` blocks the script's JS thread**, so every
  `setInterval`/`setTimeout` scheduled after it never runs (the ghost never arms,
  retries never fire). Schedule it: `setTimeout(() => Java.perform(fn), n)`.
- **Never call the Java bridge synchronously from a native hook.** `Java.available`
  can block forever while the VM is warming, freezing every other hook on the
  same runtime. Drive Java from timers, or from a host-side second script.
- **`Interceptor.attach` on a PLT stub fails for ~1 s after the library maps**
  (`unable to intercept function at 0x...`). Keep the interval alive and retry;
  do not clear it on the first throw.
- **`abort()` must return, not park.** Returning leaves the caller in garbage but
  the process lives; parking with `Thread.sleep` hangs it. `exit`/`_exit`
  replaced with a plain return is fine.
- **When the verdict exits through the app's own `svc` stub, patch the syscall
  number, not libc.** A hardened app issues `exit_group` from a hand-rolled thunk
  inside its `.so`, so a `_exit` patch never fires and the app "ignores" it — the
  tell is a `ret`/park that holds every other death but this one. Divert 94 at the
  stub, keeping the errno tail: `cmp w8,#94 ; b.eq <ret> ; svc #0 ;
  cmn x0,#1,lsl#12 ; cneg x0,x0,hi ; b.hi <errno>` — the tail is what keeps every
  *other* syscall's error reporting intact. Recipe and verification:
  `references/exit-path-patching.md`.
- **`/proc/<pid>/mem` takes bytes, not words.** Writing an instruction as its
  printed word (`7101781f`) instead of little-endian bytes (`1f790171`) installs
  `fnmadd` and the app dies of `Illegal instruction` while the patch looks
  applied. Assemble, then byte-swap each word.
- **A libc `mount --bind` never reaches an app process.** Zygote preloads libc, so
  every forked app inherits the mapping as it was at fork; a bind-mounted libc
  only affects processes started afterwards, and an app launch is not one of
  them. Patch libc offsets per process through `/proc/<pid>/mem`.
- **A hardened runtime hooks libc itself, and that silently eats your hooks.** It
  installs its own `ldr x16,#8 ; br x16` trampoline on exports like `openat`,
  `connect`, `getpid` and repaints whatever you put back. Two consequences: an
  `Interceptor.attach` on the export reports success, writes byte-identical
  content and **never fires** — so hook the target read out of their literal
  (offset +8) as well as the export; and a hook installed once goes stale, so
  re-arm on a short cycle. Re-arm only hooks that have not fired since the last
  tick (count in the callback), otherwise the churn itself stalls the app.
  Mechanism, detection and the re-arm loop: `references/libc-hook-survival.md`.
- **`_exit`→`ret` is not safe in that shared image.** Every process that exits
  returns into a dead frame (shells print `Segmentation fault` at exit, and the
  `adb shell` calls start timing out); `abort`/`kill`/`tgkill`→`ret` is fine.
  In process, invert it: park `b .` (`00 00 00 14`) on `_exit` and on the svc
  diversion, but keep `ret` on `abort`/`kill`/`tgkill` — parking those holds the
  process but stops signals being delivered, and the app answers with an
  `Application Not Responding` dialog instead of dying.
- **Patch without stopping the process.** A SIGSTOP/SIGCONT write loop during the
  splash trips the startup watchdog as surely as a late hook does. Writes through
  `/proc/<pid>/mem` bypass page protections, so write straight in with no stop,
  and stop only for a sequence that has to land atomically.
- **Write from inside the process with `pwrite64`, not `Memory.patchCode`.**
  `patchCode` (mprotect + write) crashes this class of target while the same
  bytes written through `/proc/self/mem` hold. Under Frida 17 the offset argument
  must be a `UInt64`: `pwrite64(fd, buf, len, uint64(addr.toString()))`, otherwise
  it throws `TypeError: Int64 object expected` and the patch silently never
  happens. Keep `patchCode` only as a fallback — `open("/proc/self/mem", O_RDWR)`
  itself fails with errno 13 while the RASP has dumpability cleared, and that
  flips between launches.
- **Creating files under `/data/data/<pkg>` as root makes the app crash.** The
  tree ends up root-owned and the app's own `mkdir` fails — `IOException: Failed
  to create directory …` out of Firebase/DataStore roughly ten seconds in, which
  reads exactly like an anti-Frida kill. `chown -R <uid>:<uid>` the package dir
  and check `ls -ld` before believing any survival result. Two traps on top: the
  uid **changes when the app is reinstalled** (read it from `stat -c %u` on the
  data dir, never hardcode), and a root-created subdir also loses the per-app
  SELinux categories (`s0:c174,c257,…`) so it needs `chcon` with the *parent's*
  context — `restorecon` alone restores only the type.
- **`pkill -f '<pattern>'` kills the shell that runs it** when the pattern occurs
  in that shell's own command line: the tool call dies with `exit -9` and the
  rest of the command never runs. Exclude `$$`/`$PPID`, or keep the killer in a
  script file.
- **A real RASP polls; spoofing must be resident and must cover every source.** A hardened
  app re-reads its own `/proc/<tid>/maps`, `/proc/self/status` (`TracerPid`),
  `/proc/self/task`, `/proc/self/fd` and `/proc/self/task/<tid>/comm` from a worker thread
  about once a second, for the life of the process (prove the cadence with a whitelisted
  `openat` trace). A scrub installed once at load is armed-looking and loses: keep the
  handler installed and serve every call, including the ones that arrive minutes later.
  Startup work is a separate, one-shot path — a signature/certificate check — and it only
  hands over to the maps scanner when it fails, so a clean startup proves nothing about the
  watchdog.
- **Classify injection as its own stage, separate from attach.** Attach can
  succeed while the agent never lands: no `frida-agent` in `/proc/<pid>/maps`,
  `frida -H … -p` answering `Failed to load script: operation was cancelled`,
  python raising `TimedOutError … waiting for stop`. When injection hangs while
  the process stays alive, stop tuning the payload — spawn loads the identical
  payload fine before init, and a gadget inside the APK removes the stage.
- **Test a bare spawn before blaming the payload.** `dev.spawn()` with no script,
  then `resume()`, then poll: if that also dies at ~2 s the payload is innocent
  and the loss lives in the spawn/resume protocol — fall back to `am start` plus
  an attach, which a warm app tolerates.
- **A `read()` hook over `/proc` must copy bytes, not strings.** `readUtf8String(n)`
  throws `can't decode byte 0x00` on the first NUL — which is every `/proc/self/status`
  read and most map lines — and the hook then silently hands back the untransformed
  buffer, so the spoof looks armed and the app still sees itself. Take `readByteArray`,
  build a Latin-1 string with `String.fromCharCode`, rewrite it, and write the result
  back with `writeByteArray` + `retval.replace(bytes.length)`.
- **Redirecting the hash-checked libraries to pristine copies is an A/B flag, not a
  default.** Serving `libc.so`/`libart.so` from `/data/local/tmp` copies (same bytes,
  out of the protector's hash range) made this target stop before its first connection;
  with the redirect removed the traffic returned. If you do keep it, patch the *copy*
  with the same bytes you patch in memory so file and mapping agree.
- **Establish which layer verifies before unpinning anything.** A native symbol
  sweep on a Conscrypt app and Java hooks on a Cronet app both look armed and
  change nothing. The tell is a whitelisted syscall trace of the anchor path: an
  `faccessat …/cacerts/<hash>.0` means the platform store decides, no `cacerts`
  access at all means bundled anchors, and `CertBlocklistImpl.isPublicKeyBlockListed`
  chatter is the platform blocklist rather than app pinning. Recipes:
  `references/trust-layer-provenance.md`.
- **A CA module's tmpfs store is per-mount-instance, so "the file is there" proves nothing.**
  On Android 14+ a `CustomCACert`-style module mounts a tmpfs over
  `/apex/com.android.conscrypt/cacerts` at `post-fs-data`; every app process gets its own
  snapshot of that directory at fork and never picks up files added later — not by `cp` into
  the shell's copy, not by `nsenter -t <pid> -m -- cp`, not even into zygote's.
  **The `nsenter` count cannot be the check**: it can read identical to the shell while the
  app sees fewer entries. Verify from inside the process (`new File(dir).list().length`,
  `exists()`, or simply whether the handshake still says `Trust anchor not found`) and treat a
  differing count as the only confirmation. On targets like this, stop installing certs and
  override trust in the script — see `references/trust-layer-provenance.md`.
- **A pinner built by DI over a database has no pin strings to grep.**
  `provideCertificatePinner(PublicKeysDao)` means the pins are encrypted Room rows,
  so a missing `sha256/…` literal proves nothing. Judge by whether
  `okhttp3.CertificatePinner.check` ever runs: `<clinit>` plus repeated `hashCode()`
  is only connection-pool keying, so the traffic never reached the pinned client.
- **The obfuscated pinner class is renamed every build — find it by structure, never by memory.**
  A remembered name (`ud.l`, `td.l`) resolves to nothing one release later while the pin map
  moves to a new package, and `Java.use` on a missing class only logs. Locate the pinner as the
  class whose only method is `a(String, <Function0-like interface>)` and confirm it by the class
  that holds the `sha256/…` literals (pin map). Hook the single internal implementation
  (`check$okhttp`'s renamed body) with a void no-op; the public overloads delegate to it.
- **Never truncate a mitm log that the running proxy still holds open.** `: > log`
  leaves mitmdump writing at its old offset, so the file reads back empty and a working
  capture looks like zero traffic — start a fresh path instead. A replacement instance on
  the same port meanwhile dies with `[Errno 98] ... failed to listen` while the first one
  keeps serving, so check `ss -ltnp | grep <port>` and kill the old pid before believing
  either log.
- **Shell-hooking libc gets noticed; hooking the app's own `.so` is tolerated.**
  When procfs spoofing is needed, rewrite the path argument at the app's
  `fopen`/`syscall(openat)` PLT stub and hand back a scrubbed temp copy, so
  libc's `read` never needs a hook either.
- **Attach to a warm app, never the splash.** One attach per launch: a reused
  process fails every later load (`operation was cancelled` / `connection is
  closed`). Launch clean, wait until the content is drawn and settled, then
  attach — attaching early is the difference between stable and dead in 10 s.
  Take the pid right before attaching and pass `-p`; `-N <package>` regularly
  answers `process not found`. `pidof` often returns **several pids on one line**
  (the app plus worker/service processes) and `head -1` does not split them, so
  `frida` gets `--pid "A B"` and dies on the argument — always
  `pidof <pkg> | tr ' \r' '\n\n' | head -1`.
- **Both sides of the "is it drawn" test have to be bounded.** The launcher
  screen is *larger* (~2.8 MB) than any app frame (0.5–0.8 MB), so a bare
  "bigger than the splash" test passes on the home screen while the app is still
  starting; and after `am force-stop` the last app frame stays visible until the
  launcher redraws. Bounds like `150000 < size < 2000000`, a pause after the
  force-stop, and a re-read of the pid *after* the screen check are what make the
  test mean anything. Sampling a screenshot every second is itself enough of a
  load spike to hurt a splash — sample every third poll.
- **A backgrounded app cannot be attached.** Android freezes background
  processes, so the ptrace stop never completes:
  `unexpectedly timed out while waiting for stop from process with PID …`. Check
  `dumpsys window | grep mCurrentFocus` — it must be the app's activity, not the
  launcher or a system dialog in front of it.
- **A degraded frida-server looks exactly like a bad script.** Loads that cancel
  out while the app stays alive mean the server, not the payload — restart it.
- **`adb forward --remove-all` silently kills the frida port.** Any proxy cleanup that clears
  forwards leaves the next `dev.attach()` answering `ServerNotRunningError: unable to connect
  to remote frida-server` while the server is alive and running, which reads as a dead server
  and sends you restarting the wrong thing. Re-add `adb forward tcp:<port> localabstract:<sock>`
  and confirm it with `adb forward --list` before touching the server.
- **`Interceptor.replace` on libssl kills the app; `Interceptor.attach` with
  `retval.replace()` is tolerated.** Three attaches on `SSL_CTX_set_verify`,
  `X509_verify_cert` and `X509_check_host` hold a hooked session with the UI
  intact; five is already too many. Same for the Java bridge: it is what kills
  attach, so unpin natively (BoringSSL) rather than in Java.
- **Never trust `Process.findModuleByName().base` for an APK-mapped library.**
  The app maps the split APK twice — once as a huge APK-sized copy and once as
  the real ELF segments — and Frida reports the first, so `base+offset` falls in
  an unmapped gap (`unable to intercept function`). Compute the base from
  `/proc/self/maps`, filtering by the **APK** name (the path never contains the
  `.so` name), but take the start from the **`r--p`** line of that mapping: there
  the file offset *is* the library offset, so the line's start is the base.
  `start - file_offset` on the `r-xp` line underestimates the base by the library's
  offset inside the APK, and the hooks then report success and never fire. Confirm
  the base against 4 known bytes at a fixed offset before hooking anything.
- **`ANR in` / "isn't responding" on attach is a rendering stall, not a JS bug.** The
  ANR trace shows the main thread in `ThreadedRenderer.draw` waiting on
  `RenderThread`, and RenderThread sitting in `/memfd:jit-code-cache` —
  `dalvik.vm.usejit false` does *not* stop methods that were already profiled from
  running as JIT code. Force AOT so nothing JITs over your patches:
  `adb shell su -c 'cmd package compile -m speed -f <pkg>'` (do it with the app
  stopped, then launch fresh). Attach while the dashboard is already drawn too,
  never mid-frame.
- **Rule out MTE before you patch ART.** A `SIGSEGV code 2 (SEGV_ACCERR)` whose faulting
  store targets a tagged `0xb4…` pointer, with `getprop persist.arm64.memtag.app` on, is the
  memory-tag check rather than a logic defect — the ART patches only treat its symptom. Set
  the prop to `off`, reboot once, re-read it, and re-measure before deriving any offset: on
  this target the app then reached its dashboard under a spawn with just the media repair and
  no ART patch at all. MTE off is not a guaranteed cure — the remaining faults simply move
  into `/memfd:jit-cache` — but every conclusion drawn with tagging on is suspect.
- **The ART abort is not a stub — read the source before patching it.**
  `ResetQuickAllocEntryPoints` is a full `switch` on the global `entry_points_allocator`
  (`runtime/entrypoints/quick/quick_alloc_entrypoints.cc`; `runtime/gc/allocator_type.h`
  orders it 0 bump, 1 TLAB, 2 RosAlloc, 3 DlMalloc, 4 NonMoving, 5 LOS, 6 Region,
  7 RegionTLAB). Only **4, 5 and >7** reach `UNIMPLEMENTED`, and the flag half of the
  condition is `entry_points_instrumented`, which selects the instrumented table. So do
  not force either byte blindly: read the live allocator kind first — forcing 0 on a TLAB
  heap installs bump-pointer entrypoints and the crash merely moves to
  `art_quick_invoke_stub` / `Thread::CreateCallback`. Fix by handing the FATAL tail to the
  real installer instead: `Interceptor.replace` the tail with a call to
  `SetQuickAllocEntryPoints_region_tlab(qpoints, flag)`. That is address-only, so it ports
  across ART builds, unlike a byte-level recipe. The abort fires on **every** thread
  creation because the function is inlined into `art::Thread::Init`, so a bare agent still
  dies in ~2 s, and blocking `abort` alone turns it into a SIGSEGV. Judge success by the
  crash signature moving; expect the `.data` repaint next. Detail:
  `references/frida-payload-layers.md`.
- **The UNIMPLEMENTED case ends in a log block, and NOP-ing its `abort` is not the fix.**
  Disassemble the case first: it is `mov w0,#6 ; mov x1,xzr ; bl ShouldLog ; tbz w0,#0,<epi>`
  and only when logging is on does it reach the stream + `bl abort`. Resuming there with a
  patched-out `abort` leaves the entrypoint table garbage and every later thread blocks in
  `Thread::CreateNativeThread` on `thread_list_lock_`. Install the healthy path instead —
  `mov x0,x19 ; mov w1,#1 ; blr SetQuickAllocEntryPoints_region_tlab ; br <the tbz target>` —
  and note the setter takes the entrypoint pointer in **x0** and the flag in **w1**.
- **A cave reached by a 4-byte `b` must be within ±128 MB.** `mmap(NULL,…)` lands ~300 MB
  away and the branch wraps silently (log the delta; `-282826707` means it wrapped). Find a
  hole in `/proc/self/maps` within ±0x6000000 of the module, page-align, and retry
  `mmap(hole, page, 7, 0x100022, -1, 0)` (`MAP_FIXED_NOREPLACE`) until one sticks. Do the
  arithmetic via `parseInt(p.toString(),16)`; `toUInt32()` truncates libart's `0x73b8…`
  addresses and the hole scan then always comes back empty.
- **The three ART sites that keep a hooked session stable must be `ret`ed at the function
  ENTRY, not mid-body.** `ThreadList::RunCheckpoint` (it holds `thread_list_lock_`; the
  symptom is main parked in `Thread::CreateNativeThread` and it never resolves on its own),
  `AddNativeDebugInfoForDex` and `AddNativeDebugInfoForJit`. The two debug-info functions wrap
  their body in `SuspendAll`/`ResumeAll`, so a `ret` placed a few instructions in skips the
  resume and the app dies with `Abort message: Caused main failure : SuspendAll timeout` or
  SIGSEGVs inside `X509…`-adjacent interpreter frames. Conversely the `ThreadStart`/ThreadDeath`
  no-ops are *not* needed once the cave is in — with both installed the thread-creation block
  returns, so treat them as one variable to test, not a default.
- **Take the `ret` sets as a pair: the debug-info rets without `RunCheckpoint`/`ResetQuickAlloc`
  park the app on the splash.** Splash-forever with a live pid and no traffic is the tell (not a
  crash, not an ANR) — the runtime keeps suspending for checkpoints that no longer complete.
  Either install all of them, or none plus the entrypoint cave.
- **libart offsets are per-build; hash the on-device `libart.so` before replaying any of them.**
  A system/apex update silently invalidates every cached offset while the failure signatures stay
  identical (`SIGSEGV … fault addr 0x130`, `unimplemented` aborts), which reads as "the technique
  stopped working". `sha256sum /apex/com.android.art/lib64/libart.so` and compare with the value
  the offsets were derived from; on mismatch re-derive them from the new binary (find the
  `ldr x8,[x8,#0x120] ; blr x8` pair in `InitEntryPoints`, the `paciasp` prologue of each
  `AddNativeDebugInfo*`, and resolve `abort` by export rather than a hardcoded libc offset).
  A repainted callback list that faults at 0x130 with a cave already in place is this, before it
  is anything else.
- **A re-signed APK is a tamper signal, and on a runtime whose
  `ResetQuickAllocEntryPoints` default is unimplemented it is fatal.** The RASP answers a signature
  mismatch by enabling ART entrypoint instrumentation, so the very next thread
  creation hits the FATAL and the app loops in `ScionFrontendAp`/`Firebase …`
  aborts. Before blaming your edit, install the app's own APK untouched and a
  byte-identical copy signed with your key: identical crashes mean the edit is
  innocent and the signer is the trigger. Keep the original signer — spoof it
  (CorePatch scoped to the package plus the APK's original certificate) —
  otherwise the repack installs, starts, and dies.
- **Keep the process off the start clock.** `dev.spawn()` leaves the app *suspended*:
  call `dev.resume(pid)` the moment the script is loaded. Forget it and the app idles at
  the splash while AMS counts, then dies with `Killing …: start timeout` — which looks
  exactly like a RASP kill and makes every layer you armed look guilty. Keep load-time
  work tiny for the same reason: `Module.enumerateExports()` over libart costs 1–2 s, so
  anchor non-exported functions to one *named* export plus a delta instead of walking the
  table. Patches that must precede the first thread go in before `resume()`, everything
  else after it. Recipe:  `references/spawn-timing-and-runner.md`.
- **Load the runtime patches first, in their own tiny script, then the big payload.**
  A several-hundred-KB bundle takes longer to `create_script`+`load` than an app in its
  startup crash loop survives, so the load dies mid-transfer (`TransportError: the
  connection is closed`) and the retry lands on an already dead process. Send a ~2 KB
  script that only nops the abort and `ret`s the ART sites, see its log line, and only
  then load the bundle on the same session. Same rule for a second, Java-only script:
  load it a few seconds *after* the main one — two `Java.perform`s starting together
  serialize and the first one stalls before reaching the rest of its own tail.
- **Arming from inside the script's timers is a trap; drive it from the host.** Timers
  registered inside `Java.perform` never fire (and a battery that *looks* installed is
  the failure mode). Expose `rpc.exports` and call them from the Python driver on a
  schedule, retrying while `Java` is still undefined.
- **A mid-function `Interceptor.replace` is not reliable** (`Thread::Init`'s UNIMPLEMENTED
  tail aborts on the next thread). Write a 12-byte literal branch instead —
  `ldr x16,#8 ; br x16 ; .quad <cave>` — with the cave (allocated `rwx`) doing the real
  call, and patch it *before* `resume()`. `Memory.writeU32` rejects negative numbers
  because JS bitwise ops return signed ints: shift every assembled word `>>> 0`.
- **Never patch generic `syscall()` wholesale.** A `ret` there breaks every libc caller
  and ART dies on `Check failed: membarrier_result == 0`. Filter instead: attach, read
  `x0`, and only override the return for the numbers you want (129/130/131).
- **After any surgical edit of the payload, count your hooks.** A block pasted twice by
  an edit installs two JS hooks on the same hot site, the JS thread saturates during boot
  and every later `rpc` call appears to hang; check `grep -c` on the log line and
  brace-balance the file before blaming the target.
- **Do not use a hot boot-image method as a hook canary.** `StringBuilder.toString`,
  `Object.getClass` and friends are AOT-inlined into every caller, so the entrypoint is never
  taken, the hook reports installed, and nothing fires — which looks identical to "the app
  never calls my target". Prove the bridge with an *interface* call (`PackageManager.getInstalledPackages`
  and friends) and treat a silent hook on a boot class as "unknown", not "not called".
- **Java hooks on apex-dex classes need `Java.deoptimizeEverything()` plus a re-arm tick.**
  Freshly installed hooks on `android.security.net.config.*` / `android.net.http.*` fault on the
  first invocation with `pc` printed as a 51-bit value (`0x26ffca9017bfd`) under an
  `ExecuteSwitchImplCpp` frame. After installing, call `Java.deoptimizeEverything()` and re-install
  the same implementations from a 400 ms `setInterval` — the process then survives the
  handshakes while the hooks stay armed.
  **Order matters more than the interval.** Deopt has to run *immediately after* the
  implementations are installed: deferred by ~1.5 s the hooks install, every log line reads
  green, and nothing ever fires (the app still fails with `Trust anchor not found`). Deopting
  at install time instead can kill the process ~2 s later in the `EmojiCompatInit` thread
  (`SIGSEGV code 1`, fault address in the tagged-looking range) — probabilistic, roughly 1 in
  2, so the host driver must retry: three launches, ~2 s settle between them, and only proceed
  once a process survives arming. Extra re-arm ticks are not free: 40 × 400 ms churned ART
  enough to make startup worse, while 3 × 700 ms held. Never type or tap into a run whose
  `END java layer`/`ready` line never appeared — that process has no hooks.
- **Old bundle size is load time, and load time is the failure window.** Compile every payload
  with `frida-compile -c -S` (compress, no sourcemaps): an inlined `frida-java-bridge` bundle
  drops ~745 KB → ~240 KB and lands inside the window instead of dying with `TransportError: the
  connection is closed`. Splitting native from Java halves does not help if each half is still
  unminified.
- **A stray `prelude.js` next to `prelude.ts` breaks every compile** with
  `prelude.js:2:13 - error TS-1: Expected ")" but found "as"` — the check picks the compiled
  twin and parses TS syntax as JS. Delete it; the same error means "shadowed prelude", not
  "bad entry file".
- **Patch one implementation, not every call site.** okhttp pinning is
  `okhttp3/CertificatePinner.check$okhttp(String, Function0)`; both public
  `check` overloads delegate to it, so an early `return-void` there disables all
  pin checks while the DI-provided pinner object, its pin set and chain cleaner
  stay intact. conscrypt `TrustManagerImpl` lives in the boot image and is not
  in the APK, so repackaging cannot touch the trust layer — the mitm CA has to
  be a platform CA (`targetSdk` >= 24 ignores user certs).
- **Never hand-roll zip alignment padding.** Writing a `PAD!` extra field to
  realign entries yields `BadZipFile: Corrupt extra field` for every later
  reader; keep `.so` and `resources.arsc` STORED and let
  `zipalign -f -p 4` align after the rewrite. `-p 4` is for 4 K pages — confirm
  with `adb shell getconf PAGESIZE` rather than assuming.
- **`d8` from build-tools 33 dies with an internal NPE on anonymous inner
  classes.** `String.length()` on a null argument, `CompilationFailedException`
  pointing at `X$1.class`; compiling with `-source 8 -target 8` triggers it.
  Use `javac --release 8` and check `javap -v | grep major` is 52 before `d8`.
- **Restart zygote only after you know what you are chasing.** `setprop ctl.restart zygote` re-reads `dalvik.vm.usejit`, but the frida-server then holds a dead runtime and `spawn` answers
  `DeadSystemRuntimeException`/`DeadSystemException` — kill and restart the server
  before concluding the session is broken. Zygote `usejit` is cached at boot, so
  setting the property without a restart changes nothing, and a `jit-code-cache`
  count of 2 in `/proc/<pid>/maps` is normal even with JIT off. The restart is also the
  cure once `ResetQuickAllocEntryPoints … unimplemented` starts aborting **with no
  instrumentation attached at all** — that bare abort is the signal it is device state
  (stale ART/AMS), not your payload, so stop rewriting and restart; afterwards `spawn`
  keeps failing with `unable to find application with identifier` until the server is
  restarted too, because its package cache died with the old system_server.
- **The attach window is narrow at both ends.** At ~1 s the process answers
  `ProcessNotRespondingError`; on a long-lived or already-stalled process the same
  call hangs and then fails, and once it is wedged (`ANR` dialog up) no injection
  succeeds at all — so the workable moment is mid-startup, after the splash is
  drawn. Retry with a bounded delay rather than at both extremes, and treat an
  `ANR` dialog as "too late, relaunch" instead of retrying into it.
- **A page the app poisons needs a writer hunt, not a snapshot.** Mark it
  `mprotect(PAGE, len, PROT_READ)` and re-arm from a native thread every 1–2 ms:
  only in-process stores fault, and the faulting `pc` resolved as `module+offset`
  names the writer. A write that arrives through `/proc/<pid>/mem` or
  `process_vm_writev` bypasses the PTE and never faults — the tell is a `maps`
  entry that is unchanged while the bytes change. Read a foreign page with
  `adb exec-out su -c 'dd if=/proc/<pid>/mem bs=4096 skip=<addr>>12 count=1'`
  (`adb exec-out`, not `adb shell >`, or CRLF corrupts it); compute the page index
  from the address rather than eyeballing it.
- **Trust the on-disk image only for regions that are not zero on disk.** ART's
  quick-entrypoint table is `.data` that ships as zeros and is filled at runtime;
  restoring a file-based copy overwrites it with zeros and the next allocation
  jumps to null. Mirror such a region live and never let a zero clobber a filled
  slot.
- **Frida 17 file and pointer API.** `new File(path, 'r')` (there is no
  `File.open`); `writeU64` insists on a `UInt64` object while `ptr()` rejects a
  bigint — for pointer-sized words just use `readPointer`/`writePointer` with
  `Number(...)` for arithmetic.
- **Read the tombstone, not your script, when deciding what crashed.**
  `adb shell su -c 'ls -t /data/tombstones | head -1'` then `cat` it: the frames
  name the exact ART or app function that faulted. See
  `references/finding-the-detector.md` for using it to locate check code.
- **While Frida is attached there is no tombstone.** `crash_dump64` cannot ptrace
  the patient (`failed to attach to thread ...: Operation not permitted`) and the
  only trace left is the one-line `Fatal signal` in `logcat -b crash`. Install
  `Process.setExceptionHandler` in the agent and print `ex.type`, the fault address
  and `pc`/`lr` resolved as `module+offset` — that is the only crash stack you get.
  Frames in `libart.so` are then resolved offline against `libart.so`'s dynsym plus
  `llvm-objdump`, and the libart build's `.dynsym` is sparse, so find a tight
  function by string xref: `strings -t x` for the message, then scan for the
  `adrp`/`add` pair whose page/offset match it.
- **`frida -q` swallows the payload's own `console.log`.** A run that armed perfectly
  looks like an empty session: `-q` (and `-q -o file`) suppresses banner *and* script
  output, so "no output" is read as a dead hook. Give the run line without `-q`, redirect
  stdout (`> run.log 2>&1`) if a log is needed rather than `-o`, and treat silence as "not
  armed", never as "quiet".
- **A script that dies during load leaves the app alive and the REPL prompt up.** The
  session connects, the load throws, and the prompt sits there looking healthy — so a
  failed load and a working one are distinguishable only by the `BEGIN`/`END` lines.
  Read the first output line, not the prompt, and never type into the UI after a load
  error.
- **A script with a syntax error runs nothing and the app stays alive.** Broken
  scripts look *stable*. `node --check` every payload, and confirm a hook log
  line actually appears before trusting a survival result — including your own
  earlier conclusions.
- **Timers dying is a symptom, not a feature.** If intervals stop after one tick,
  something is blocking the runtime (see the Java/perf bugs above), not "Frida
  timers are broken". When the whole process is failing within a second, JS
  timers are worthless for sampling — run the sampler on your own `pthread_create`
  thread instead.
- **JS API does not work from a native callback thread.** `Pointer.read()`,
  `Memory.readByteArray`, `Process.getModuleByAddress` from inside a
  `NativeCallback` throw `not a function`; `console.log` and `Instruction.parse`
  still work. From a native thread do the copying and file I/O in libc
  (`memcpy`, `fopen`/`fwrite`) through `NativeFunction` — reads, file writes and
  the `usleep` pacing all have to be libc calls.
- **A backgrounded `frida` CLI exits immediately.** Without a tty it reads EOF on
  stdin right after `Resuming main thread`, which looks exactly like a session
  that died. Drive spawn/attach from a Python harness that holds the session
  (`scripts/frida_session.py`) instead of shelling out to the CLI.
- **Frida 17 has no `Java` global and no `require`.** A plain script referencing
  `Java` dies with `ReferenceError: 'Java' is not defined`; the bridge is now an
  npm module you bundle yourself. Toolchain (fetch the tarball when npm is
  missing, `frida-compile` the payload, `import Java from 'frida-java-bridge'`):
  `references/frida17-toolchain.md`. `node --check` the plain script, compile,
  then `node --check` the bundle — a 700 KB bundle is normal. Inside the bundle the
  bridge is the **module binding**: import it, then `try { globalThis.Java = Java }
  catch (e) {}`, and gate the arm on `if (!Java || !Java.available)` — never on
  `globalThis.Java`. On an agent that already exposes `Java` as a getter-only global the
  assignment throws `TypeError: no setter for property` at load and *nothing* else runs,
  while the same bundle still loads from Python (`create_script` has no such property),
  so validate the payload with the CLI the user will actually run.
- **`frida -q` swallows the payload's own `console.log`.** A run that armed perfectly
  looks like an empty session: `-q` (and `-q -o file`) suppresses banner *and* script
  output, so "no output" is read as a dead hook. Give the run line without `-q`, and if a
  log file is needed redirect stdout (`> run.log 2>&1`) rather than `-o`.
- **`frida -q` swallows the payload's own `console.log`.** A run that armed perfectly
  looks like an empty session: `-q` (and `-q -o file`) suppresses banner *and* script
  output, so "no output" is read as a dead hook. Give the run line without `-q`, redirect
  stdout (`> run.log 2>&1`) if a log is needed rather than `-o`, and treat silence as "not
  armed", never as "quiet".
- **`frida -q` swallows the payload's own `console.log`.** A run that armed perfectly
  looks like an empty session: `-q` (and `-q -o file`) suppresses banner *and* script
  output, so "no output" is read as a dead hook. Give the run line without `-q`, and if a
  log file is needed redirect stdout (`> run.log 2>&1`) rather than `-o`.
- **`frida-compile` embeds the entry path in the bundle, relative to the project root.**
  Compiling the same source from a different directory (or via an absolute path) yields a
  byte-different file, so a rebuild that "succeeds" can still be a different program than
  the one tested. Always rebuild from the repo root with the same relative entry, and prove
  source↔bundle agreement by compiling to a temp path and comparing `sha256sum` before
  shipping — mismatched hashes mean the loaded file is not the source you read.
- **On a hardened target the first attach dies often, and a driver that does not notice
  reports success.** Here roughly every second launch died ~2 s after arming (SIGSEGV in
  the `EmojiCompatInit` thread, right after `Java.deoptimizeEverything`) while the process
  looked alive to a naive poll. Have the driver (a) wait for the script's own
  `END`/`ready` marker, (b) confirm the agent is really in the target
  (`grep -c frida-agent /proc/<pid>/maps` > 0), and (c) relaunch with a ~2 s settle on a
  death, then page success only on a live process. `deoptimizeEverything` must stay right
  after arming — moving it later leaves the hooks installed but never firing.
- **Hooking Java at spawn can kill the process in ~2 s while native hooks are
  fine.** Symptom is `SIGSEGV code 1 fault addr 0x0` in the *main* thread with
  `pc=0`, `lr=0`, one bogus frame in `art_quick_invoke_stub`, thrown the moment
  the app invokes the hooked method reflectively. libc hooks and *read-only*
  Java (`Java.use` + `getDeclaredMethods`, no `.implementation` assignment)
  survive the same spawn. So: keep the payload native, or attach within the
  first half-second by polling `pidof` and attaching on the first hit
  (`scripts/frida_early_attach.py`) — that is the only way to be in place before
  a startup check without replacing an ArtMethod.
- **The JNI global reference table is the real ceiling on Java-heavy payloads.**
  `JNI ERROR (app bug): global reference table overflow (max=51200)` then an abort
  in `JavaVMExt::AddGlobalRef`. A hardened app caches reflective `Method`/`Class`
  handles and sits near the cap on its own, so your wrappers tip it over; the
  symptom reads as "the app dies whenever the agent attaches". Stay on a handful
  of named classes, batch any namespace-wide scan, and keep the payload native
  where possible — native-only agents stay attached indefinitely.
- **`Java.enumerateLoadedClasses` (async) stalls the gadget on an app with tens of
  thousands of classes; `Java.enumerateLoadedClassesSync()` returns in ~1 s.**
  The async callback form can hang past a minute and the next `create_script`
  then fails with `frida.TransportError: timeout was reached`. Enumerate
  synchronously and filter the returned array in JS.
- **Even a scheduled `Java.perform` can silently no-op at spawn.** A payload whose
  first log never appears while the app stays alive is this, not a wrong hook:
  retry from a ticker guarded by `if (!Java.available)`, cap the attempts, and
  `send()` a `BEGIN`/`GIVEUP` line so the no-op is visible instead of looking like
  a stable run.
- **`avc: denied { getattr }` in logcat is detection input, not noise.** An
  untrusted app cannot `getattr` tracefs (`/sys/kernel/tracing/trace_marker`) or
  the `userfaultfd` inode, so a stat-based fd sweep scores both as suspicious and
  repeats every few seconds in `Thread-N`. Because such a sweep resolves targets
  by fd/path, filtering the `readdir` listing changes nothing — hook
  `stat`/`__statx` and return 0 with a zero-filled struct for those two targets.
- **In OLLVM-flattened code the block you return from is a state, not a function.**
  Attaching to a mid-function block and replacing its return value feeds the
  caller's `uxth`-and-table-jump dispatcher; a value that is not a live state id
  jumps into unmapped memory (`pc=lr=0x8`, `x29=0x24`). Either leave the original
  words alone or brute-force a valid state — see `references/finding-the-detector.md`.
- **`Java.use('android.R.id')` through the app's ClassFactory throws
  ClassNotFoundException**, and `Java.array` on framework classes behaves oddly
  under an app loader. Discriminate by class *name* (`d.getClass().getName()`)
  instead of resolving framework ids.
- **Dismissing every visible dialog breaks the flow.** A consent/privacy dialog
  and the anti-tamper dialog are different objects with different handlers; a
  blanket `Java.choose('android.app.Dialog', …dismiss())` closes the consent one
  before its button handler stores the answer, so it re-appears after every
  navigation. Match the guard's own class name, and let the user-facing dialogs
  be tapped.
- **Suppressing the dialog is not fixing the verdict.** The check re-runs on each
  activity start, so the guard dialog returns and the activity can be finished
  under you. Suppress + verify the activity survives; treat the verdict as its
  own problem (`references/rasp-java-layer-bypass.md`).
- **Decide whether the guard kills or merely reports before building stealth.** Read the call
  sites in smali: a guard whose verdicts only accumulate into a list that gates a screen (a
  `BLOCKED: […]` path, a diagnostics banner) needs nothing but the three verdict methods hooked
  to `false`; a guard that `exit_group`s or repaints ART needs the resident spoof instead. This
  decision is what keeps a diagnostic-only guard from triggering a week of procfs work — and a
  bound native lib registered against an obfuscated class (`JNI_OnLoad` + `RegisterNatives`,
  method names reduced to two letters) is the cheap signal that it is a check, not a killer.
- **A sleeping device swallows every tap.** `am start` still answers `intent has
  been delivered` and `uiautomator dump` still returns a hierarchy, so it looks
  like a UI bug. Check `dumpsys power | grep mWakefulness=` first, then
  `svc power stayon true` + `settings put system screen_off_timeout 1800000`,
  and `input keyevent 224` before driving the UI.
- **`uiautomator dump` omits `text=` on custom input widgets — screenshot before believing the
  field is empty.** A `TextInput`-style field formatted by the app (phone number with spaces)
  shows its value on screen while the node carries only `hint=`; concluding "the text did not
  land" from the dump leads to re-typing into a field that is already correct.
- **A button behind the IME swallows taps.** `input tap` on a submit button the keyboard covers
  reports nothing and fires no request. Press Back to dismiss the IME, confirm the value is still
  there by screenshot, read the button's bounds from a fresh dump, then tap — and treat a tap that
  produces no network call as "the click never landed", not as a bypass failure.
- **KernelSU `su` runs in its own mount namespace.** `mount --bind` from a
  `su -c` shell is invisible to app processes; go through
  `su -c 'nsenter -t 1 -m -- mount --bind SRC DST'` and prove it with
  `grep -c <name> /proc/<app-pid>/mounts` before trusting the mount.

- **When every attach dies, stop attaching: go ptrace-free with a raw injector.**
  A `/proc/<pid>/mem` code-cave injector (`github.com/ferib/android_injector`) that
  `dlopen`s a payload needs root and no debugger, so `TracerPid` stays 0 and no
  frida-server exists to be found. With frida-gadget as the payload this is the
  difference between dying in 5 s and running to the login screen. Recipe, build
  flags and the SELinux/`console.log` traps: `references/raw-injection-gadget.md`.
  Adopt it after the second attach-class failure — not after ten payload rewrites.
- **Gadget scripting has no timer loop.** Inside a gadget script `setTimeout` never
  fires (a one-line probe that writes a file on a 1.5 s timer proves it in seconds);
  top-level code does run. Do the work synchronously at load and export an arm hook
  (`globalThis.armJava = fn`) that the entry bundle calls after setting any late
  globals — a timer-driven arm silently never arms and the log just stops.
- **A gadget's `console.log` never reaches logcat.** Log to a file in app storage
  and `cat` it over adb, or a fully working payload looks completely silent.
- **`dlopen` of a pushed `.so` from `/data/local/tmp` fails on Android 14+:**
  `couldn't map ... segment 2: Permission denied`. Payloads must sit in the app's
  own storage with the app's uid, mode 644 and the parent's SELinux context — the
  injector runs as root, the loader does not.
- **Kernel-side exit blocking is `seccomp_unotify`, not a parked thread.**
  `github.com/funsafemath/syshook` (+ its `frida-syshook` package) intercepts
  `exit`/`exit_group`/`kill` and answers `neverRespond`, freezing the caller in the
  kernel with no spin. Build with `cargo ndk -t arm64-v8a -P 30`, load from app
  storage, and gate `setupUnotify` behind a delay — it blocks the JS thread, so
  anything scheduled after it stalls.
- **A stale `DNAT` rule silently blackholes all traffic.** Rules match in order, so
  a leftover rule pointing at an old host IP wins, the app hangs on the splash and
  mitm sees nothing while `ping` to the proxy still succeeds. Print the chain with
  `iptables -t nat -S OUTPUT` before blaming the app, and remember uid-scoped rules
  do not survive a reboot.
- **Transparent mitm needs `--set connection_strategy=lazy` when upstream comes
  from SNI.** Without it the addon throws `Cannot change server.address on open
  connection` on every connection and each request hangs.
- **Classify a bare-app death from the tombstone before calling it RASP.** A
  `libmedia`/`MediaMetadataRetriever` frame under Glide's `VideoDecoder` is a
  platform crash; nothing in the trust layer will fix it.
- **Hook a syscall *wrapper*, not the `svc` instruction.** Tracing at `svc #0` reads
  a zeroed `x8` (`Not compatible syscall number: 0`); the wrapper entry runs the
  `mov x8, x0` prologue first and decodes correctly.

- **Pin the client to the server's version, and read the server's `--version` first.** A
  newer python `frida` against an older `frida-server` (or the reverse) does not fail
  cleanly — it dies in `attach`/`load` in ways that read as target problems, so every
  payload conclusion drawn on the mismatched pair is junk. `frida-server --version` on
  the device, then `pip install frida==<that version>`, is part of setting up a session,
  not a debugging step.
- **Patching a `switch` case body: one 4-byte `b` at the case entry, everything else in
  a cave.** The other cases' `b.ne`/table targets point *inside* the case range, so a
  12–16-byte literal branch overwrites bytes another case jumps to. Symptom is a crash
  at the entry instruction with registers that look correct, or garbage in the register
  the saved code was supposed to carry. Only the first word of the case is exclusive.
- **A register the prologue saved is not valid at the case that uses it.** The compiler
  does `mov x19, x1` at function entry and `bl`s the sub-installer with `x0`; by the time
  that sub-function reaches its UNIMPLEMENTED default, `x1` has been clobbered, so
  neither `mov x19, x1` nor `mov x19, x0` in the cave reproduces it. Read the crashed
  thread's own `x19` out of the `Fatal signal` register dump — if it is a short garbage
  value rather than a `0xb4…` heap pointer, the cave is at fault, not the target.
- **Verify the edit reached the device before reading the run.** Editing the plain JS and
  launching without re-running `frida-compile` re-tests the old bundle — a flag flipped
  in the source looks ignored (`log` still prints the old path). Confirm with the new
  log line, a bundle mtime, or `grep -c` on the marker.
- **Survival is not progress.** An app can sit "alive" for 30 s+ on its splash and look
  like a win in the pid poll. Screenshot before claiming any progress, and report which
  screen (splash / login / dashboard) plus the current crash site — not an uptime.
- **Arm TLS before the app's first connection, not after it survives.** A client that
  rejects a substituted CA fails the handshake in ~60 ms and rarely retries, so hooks
  installed 40 s later look useless: every captured failure predates them. Push an
  accept-all `X509TrustManager` into **every** `SSLContext.init` TrustManager[] (covers
  okhttp, `HttpsURLConnection`, vendor managers and DI-provided pinners at once) instead of
  naming classes one by one, and log on the trust method so a fired hook is provable.
- **A module that statically links BoringSSL with hidden symbols is invisible to a symbol
  sweep.** `findExportByName('X509_verify_cert')` over all modules matched 2 of ~600 while
  the failing handshakes came from somewhere else entirely; sweeping at load is also too
  early for libraries that map later, and a `dlopen` hook misses `DT_NEEDED` loads. If the
  app's own `.so` has no SSL exports (check `readelf --dyn-syms`), plan Java-level pinning
  instead of a native sweep and say so rather than counting hooks.
- **Reach the proxy over the reverse tunnel, not the host's IP.** `DNAT` to the LAN address
  dies the moment the host changes network; `adb reverse tcp:PORT tcp:PORT` +
  `sysctl -w net.ipv4.conf.all.route_localnet=1` + `DNAT --to-destination 127.0.0.1:PORT`
  works regardless. Prove the tunnel before blaming the app: a manual
  `nc 127.0.0.1 PORT` must show `client connect` in the mitm log.
- **The proxy egresses from the host, so a Cloudflare-fronted host can 403 the app while the
  phone itself is fine.** A decrypted request that returns `403` with a Cloudflare
  `Attention Required!` HTML body after the TLS fix is not a broken bypass: run the same URL with
  `curl` on the host — the same 403 there means the host's egress IP is what got scored, and a
  404/200 from the phone's own path confirms it. Report it as an egress problem and re-test after
  a network change instead of rewriting hooks.
- **Prefer a late attach over spawn for TLS-only work, and re-attach when the pid moves.**
  Attaching after the app is running skips zygote-fork ART initialisation entirely; the
  system then restarts the process (`Process … has died: fg TOP`) and a driver that attaches
  once silently loses its hooks — poll `pidof` and attach on every change. A Motorola
  launcher's `CustomizationPanelLauncher` also steals top-resumed, so `am start` reports
  `Complete` while the app never comes up: `force-stop` the launcher (or `input keyevent 4`)
  and confirm `dumpsys activity activities | grep ResumedActivity` names the app.
  On `unexpectedly timed out trying to sync up with agent` the process is too early (<1 s)
  or already wedged, and re-attaching the *same* pid just loops: `am force-stop` and
  relaunch, attaching once per launch at ~1.3–2 s. Prove the server separately by
  attaching to an unrelated live process (`com.android.systemui`); if that also fails the
  server is degraded and needs a restart before any payload conclusion.
- **When told to start over, keep the old payload.** Copy it to `<name>.js.HHMM.bak` first and
  build the new attempt as a separate file; the user asks for a clean rewrite, not for the
  previous result to be destroyed, and two files also let you A/B a single flag.

## Supporting files

- `references/native-rasp-emulation.md` — running a stripped RASP `.so` under unidbg:
  harness setup on a modern JDK, a `JNIEnv`-vtable tracer, and recovering runtime-decrypted
  strings, plus the Java-bridge class-layout scan failure.
- `references/jeb-headless-mcp.md` — JEB 5.47 ships a headless MCP server but its
  `-c --script=` / `-c --mcp` CLI flags are dead in the Launcher; bootstrap the MCP
  client class yourself and drive it over HTTP.
- `references/ebpf-tracer-builds.md` — cross-compiling BPFroid / tracee-family and
  stackplz (Rust and Go) for arm64 Android, with the linker and header pitfalls.
- `references/frida-payload-layers.md` — what each patch layer costs, the ART
  abort in detail, and the honest status of each technique.
- `references/finding-the-detector.md` — locating the check/verdict code in a
  stripped, OLLVM-flattened library and confirming it with runtime backtraces.
- `references/apk-repack-and-modules.md` — dex-level repack and signing, keeping
  the original signer, building/injecting an Xposed module without Gradle, and
  the static-analysis tool quirks that waste time.
- `references/trust-layer-provenance.md` — establishing who decides trust (store
  probes, blocklist reads, alert codes, Cronet rule-out), seeing the Java verify
  path with an nterp uprobe, DI/database pinners, and why a correct CA still
  ENOENTs on a modern CA-store stack.
- `references/hala-control-1.1.40.md` — worked example on `sa.hala.control`: the
  `libhalaguard` / `NativeGuard` syscall-only guard (rc/hc/dc), why it reports
  instead of killing, the relocated okhttp pinner (`be.o.a`, pins in `ej.a`), and
  the re-derivation commands for the next release.
- `scripts/apk_repack.py` — rewrite an APK with replacement entries, correct
  STORED handling, then print the zipalign/apksigner commands to run.
- `scripts/frida_session.py` — spawn-or-attach driver that keeps the session
  open without a tty, streams script messages, and reports liveness every 2 s.
- `scripts/frida_early_attach.py` — attach on the first `pidof` hit (~50 ms
  polling), for apps whose checks run before a warm attach is possible.
- `references/frida17-toolchain.md` — making the Java bridge usable under Frida
  17 (bundling, loaders, ClassFactory) and what still crashes at spawn.
- `references/rasp-java-layer-bypass.md` — reading and defeating a reflection
  driven RASP layer: dialog suppression, verdict hunting, what the noise looks
  like.
- `references/raw-injection-gadget.md` — ptrace-free `/proc/pid/mem` injector +
  frida-gadget: build, SELinux-safe payload placement, gadget scripting rules, and
  the eBPF injector that builds but never captures.
- `references/mitm-capture-recipes.md` — redirect/reverse-mode interception for
  apps that ignore the system proxy, and where transparent mode fails.
- `references/spawn-timing-and-runner.md` — spawn/resume protocol, AMS start-timeout
  economics, host-driven RPC arming, code-cave patching, and repairing a library whose
  `.rela.plt` was never processed.
- `references/exit-path-patching.md` — diverting `exit_group` in an app's own svc
  stub (and in libc `syscall()`), byte order, ordering, and how to verify it.
- `references/libc-hook-survival.md` — why hooks on a hardened app land and never
  fire, the trampoline check, re-arm discipline, and the `/proc/self/mem` writer
  with its `uint64` and errno-13 traps.
- `references/edbg-and-ceserver.md` — breaking and backtracing on device with
  eDBG's MCP mode, and root memory reads through `ceserver` when Frida cannot
  attach; includes which TLS functions are actually on the call path.
- `references/emulator-and-remote-targets.md` — picking an ABI-compatible image,
  userdebug vs playstore, and driving an emulator on another machine over an adb
  server tunnel when the host has no admin rights.
- `scripts/art_patch_first.js` — the ~1 KB pre-load script (abort nop + the three
  `ret` sites) to send before the real payload, so the bundle load is not racing the
  crash.

## Lessons: eBPF path when a RASP kills Frida (Android 16, 2026-11)
- When every Frida attach dies (SIGSEGV status=11 in `dumpsys activity exit-info`) while the app runs fine plain, switch to ecapture eBPF: no injected agent, RASP checks for frida do not apply. See skill `ecapture-android`.
- ART-side stabilisers that kept the process alive long enough to work: dd two words into the mapped libart (`base+0x51e14c` = `07 00 00 14`, `base+0x51f7cc` = `1f 20 03 d5`) before attaching; attach after ~4-5 s, never spawn.
- Patching an apex library with `mount --bind` from a normal shell does NOT affect apps: they inherit zygote's mount namespace and an already-loaded mapping. Bind root + `nsenter -t $(pidof zygote64|awk "{print \$1}") -m -- mount --bind`, then `setprop ctl.restart zygote`; verify `/proc/PID/maps` inode equals the source inode.
- `su -M` (KernelSU mount-master) is required for the root-side bind to persist across su sessions.
- Cronet traffic cannot be redirected with an in-app connect hook forever; kernel DNAT (uid) to loopback Burp was the stable path, and later ecapture's hook source made the proxy unnecessary.

