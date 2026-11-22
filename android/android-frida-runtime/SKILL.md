---
name: android-frida-runtime
description: "Use Frida for authorized Android runtime observation: method hooks, JNI boundaries, object state, request signing, and dynamic code discovery."
metadata:
  category: Android
  short-description: "Use Frida for authorized Android runtime observation: method hooks, JNI boundaries, object state, request signing, and dynamic code discover"
---

# Android Frida Runtime

Use Frida only on a lab device or emulator you control and only against an authorized app. Frida changes runtime state and can trip integrity checks; preserve the static hypothesis, device image, Frida version, and exact script.

## Start narrowly

```bash
frida-ps -Uai
frida -U -f com.example.target -l hook.js --no-pause
frida -U com.example.target -l hook.js
```

Hook one meaningful boundary: request builder, signer, crypto helper, JNI declaration, file loader, or network client. Avoid hooking the UI tree broadly. Log argument types and lengths before dumping values, and cap buffers to prevent log explosions.

```javascript
Java.perform(function () {
  var Signer = Java.use('com.example.Signer');
  Signer.sign.overload('java.lang.String').implementation = function (input) {
    var output = this.sign(input);
    console.log('[sign] input=' + input + ' output=' + output);
    return output;
  };
});
```

## Dynamic class discovery

When a class is absent from the first DEX view, enumerate class loaders and loaded classes, then inspect candidates only after a trigger. Dynamic code and runtime-generated names should be tied to the file or loader that produced them.

For native code, prefer module-relative addresses and resolve exported symbols. Rebase before correlating with static addresses. Record architecture, module base, thread, and call count with each trace.

## Reliability

**Return-value contract on the Frida 17.x baseline.** `onLeave` gets the return value as its
argument — `onLeave: function (retval) { retval.toInt32() }`. There is no `this.retval`; reading it
throws `TypeError: cannot read property 'isNull' of undefined` on every invocation, which on a poll
loop floods the console while the hook does nothing. To rewrite a return use
`retval.replace(ptr(0))` / `retval.replace(0)`. Older snippets that assign `this.retval = …` or call
`this.retval.isNull()` are stale — convert them before reuse.

Never treat `pidof <pkg>` returning something as "it survived": on hostile targets the spawned pid
dies in seconds and Android restarts a fresh, unhooked one while the session is already detached.
Assert `pidof` == the spawned pid on every poll; if it differs, re-attach or respawn rather than
reporting success. Keep hook breadth minimal for the same reason — sweeping `connect` across every
module via `enumerateModules()` aborts startup, the same symbol hooked in `libc.so` alone does not.

Hook overloads explicitly. Use `try/catch` per hook and keep the return value unchanged unless the investigation explicitly requires controlled mutation. If the app crashes, distinguish hook error, anti-tampering response, and target bug by removing one layer at a time.

**`-q` is not the reason a stage never fires.** Timers (`setInterval`/`setTimeout`) do run under `-q` — verified on the same client. What actually kills them is a second `frida-server` running alongside the first: spawns go flaky, traces come back empty, and a script looks dead. Run one server, restart it after any zygote restart (it caches a binder handle to `system_server`, after which spawns fail with `DeadSystemRuntimeException` while `am start` works), and keep a heartbeat `setInterval` in every script so "no output" is distinguishable from "dialog never fired".

**Frida 17 renamed the pointer/export APIs.** `Module.findExportByName(mod, name)` is gone: use `Module.getGlobalExportByName(name)` or `Module.getExportByName(mod, name)`. `Memory.patchCode(addr, n, cb)` also reports `not a function` on some 17.x builds — fall back to `Memory.protect(addr, n, 'rwx')`, write with `ptr.writeU32(...)`, then `Memory.protect(addr, n, 'r-x')`.

**Attach by the name column, not the package.** `frida-ps -a` prints PID / display name / identifier. `-n` matches the display name (`Tawakkalna`), `-f`/`-l` take the package, and `-p <pid>` resolves through `/proc`. If `-p` reports "process not found" for a pid that `pidof` returns, the process is dying and being restarted between the two calls — check `pidof` twice before blaming Frida.

**Raw `svc` syscall wrappers: the number is not in x0.** A stub of the shape `mov x8, x0; mov x0, x1; ...; svc 0` already shuffled the arguments by the time the `svc` executes, so a hook on the `svc` must read and rewrite **x8**, not x0. Verify before hooking: read the instruction word and confirm it is `d4000001` (`svc 0`) on arm64. `Interceptor.replace` cannot see x8 at all because a `NativeCallback` only maps x0–x7 — mutation of the syscall number requires `Interceptor.attach` plus `this.context.x8`.

**Hooking a one-instruction hot stub races.** Replacing bytes in the middle of a function every thread calls (syscall thunks, allocators) lands on threads parked inside the rewritten window. Prefer hooking a cold caller that runs once per event (e.g. `JNI_OnLoad` or the per-check worker) and install the hot hook from there; otherwise expect an intermittent SIGSEGV a second or two after install.

**ART entrypoint resets abort under instrumentation.** `art::ResetQuickAllocEntryPoints` (`libart.so`, log line `quick_alloc_entrypoints.cc ... unimplemented`) is called from `art::InitEntryPoints` on every new thread; with a Java bridge loaded it hits the unimplemented GC-kind branch and aborts. Patching the function to `ret` swaps that for an `art::UnimplementedEntryPoint` abort because callers need real entrypoints. What works: `Interceptor.attach` to the function and rewrite the kind/flag pair in `onEnter` (kind at `libart+0xE03220` = 1, flag at `libart+0xE0F8B0` = 0) so the original body takes a handled branch. Offsets are per-libart-build; re-derive from the tombstone frame and the `ldrb`/`cmp`/`b` chain before reuse.

Use `android-debugging-tracing` when debugger state, syscalls, native registers, or crashes matter. Frida output is runtime evidence but does not by itself prove a cryptographic design or server acceptance rule.

## Native TLS is a different seam

Java trust hooks (`TrustManager`, `X509Util`, `CertificatePinner`) never fire on Cronet apps, and
replacing `X509_verify_cert` patches only system `libssl`/`libcrypto` because Cronet statically
links a stripped BoringSSL. The seam that works is the custom-verify callback setter
(`SSL_CTX_set_custom_verify`), or — when even that is unexported — a `RegisterNatives` capture of
`X509Util.verify`. Ladder and recipes: skill `frida`,
`~/.hermes/skills/android/frida/references/cronet-and-stripped-libs.md`.

## Sources

- Frida Android: https://frida.re/docs/android/
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- Objection: https://github.com/sensepost/objection

## Lessons: hostile app on Android 16 (2026-11)
- Spawn dies in seconds with this kind of RASP; attach mode after a warm-up is the only stable shape. Popping both art words via `/proc/PID/mem` and attaching at 4-5 s produced 60 s+ stable sessions.
- Global `Java` is absent in plain scripts; only frida-tools REPL injects the bridge. Bundling `frida-java-bridge` works (`require(...).default`, `Java.performNow`) but importing it makes the bridge hook ART itself and can stall the splash — ship native-only agents unless Java is required.
- `setTimeout`/`setInterval` never fire in this server; drive periodic work from a `clock_gettime` attach counter.
- The stealth server hides app names from the process list (`ProcessNotFoundError`); attach by pid read from `pidof`.
- The server is on an abstract unix socket: `adb forward tcp:61111 localabstract:<name>` and `frida -H 127.0.0.1:61111` (plain `-U` targets 27042 and fails). Sessions often die with the process; one attach per launch.

