# Hardening notes (Android arm64, retail device)

Field notes from keeping a hardened app alive under instrumentation. Offsets are per-build; treat
them as "where to look", always re-derive.

## Server hygiene

- Exactly one `frida-server`. Two listeners produce spawn timeouts and empty traces that read
  like detection.
- After **any** zygote restart the running server holds a stale binder handle: spawns fail with
  `android.os.DeadSystemRuntimeException` while manual `am start` works. Restart the server and
  re-add the `adb forward`.
- `adb kill-server` silently drops forwards; re-create them (`adb forward tcp:<p> localabstract:<name>`).
- Timers in scripts *do* fire (contrary to the older `-q` folklore) as long as only one server
  runs; the earlier "timers never fire" symptom was two servers. Still verify with a heartbeat.

## ART repaint symptoms and cures

| Symptom | Meaning | Cure |
|-|-|-|
| `ResetQuickAllocEntryPoints(QuickEntryPoints*) unimplemented` abort | protector repainted the entrypoint table, ART walked it | modern builds: the repaint is a **real function with a `LOG(FATAL)` tail** — NOP the `tbnz` that guards it and replay the pointer table (below), not a cave at the call site |
| crash inside `RuntimeCallbacks::ThreadDeath`/`ThreadStart` | same table, different dispatcher | `ret` at those two **entry** points, or cave-guard their single `ldr/blr` pair |
| `blr x30` with `x30 = [thread+<qpoints>+…]` holding **instruction bytes**, `fault addr` looks like two opcodes glued together | a *thread* inherited the protector's inline-stub variant of the table | call/replay the pointer variant into that thread's table; region setters write inline bytes and cannot be blindly reused |
| `__stack_chk_fail` after patching aborts | returning from `LOG(FATAL)` desyncs the frame | do not patch `abort`/`Runtime::Abort` first; neutralise the entrypoint walk instead |
| all threads parked in `Mutex::ExclusiveLock` inside `Thread::CreateNativeThread` | `ret` placed mid-function, `SuspendAll` never resumed | move the `ret` to the function entry |
| `#00` in a `lib*.so` PLT stub, `fault addr 0x130` | GOT slot lost its target after the agent mapped | recompute the slot from `adrp x16` + `ldr x17,[x16,#imm]`, rewrite on every constructor call |

## Caves

`Memory.alloc`/`Memory.protect` lie on this class of target. Build the cave yourself:

```js
var mm = new NativeFunction(Module.getGlobalExportByName('mmap'), 'pointer',
  ['pointer','size_t','int','int','int','long']);
var p = mm(ptr(0), 0x1000, 7, 0x22, -1, 0);   // RWX, MAP_PRIVATE|MAP_ANON
```

Cave template (null-safe call-through): `cbz x8, +8` / `blr x8` / `b <resume>`.

## Quick entry point table (OEM repaint)

When the abort names `ResetQuickAllocEntryPoints` **even with MTE off**, the function itself is the
problem: the protector kept the setter code but replaced its tail with a `LOG(FATAL)`. It is still
reachable from `art::InitEntryPoints` and from JIT'd code, so every thread attach is a coin flip.

What actually worked (verified by A/B, replay byte-identical to the original):

1. Read the two globals the function switches on — a *mode* byte and an *inline* byte in `.data`.
   Mode 1 + inline 0 takes the clean path that writes 12 pointers and `ret`s.
2. NOP the `tbnz` guarding the `LOG(FATAL)` block (the block ends by branching to the common tail,
   so skipping it loses nothing).
3. Call the function once into scratch while that path is live, snapshot the 12 pointers, and install
   a tiny cave that rebuilds the table from the snapshot and `ret`s. Keep it as the replacement.

Rules learned the hard way:

- **Do not swap in the exported setters** (`SetQuickAllocEntryPoints_{dlmalloc,rosalloc,bump,region}`)
  as a "more complete" implementation. They write a different scheme: bump/rosalloc died in 3–30 s,
  region writes inline stub bytes that callers `blr` as if they were pointers (instant SEGV), and only
  the snapshot replay survived minutes.
- **Run an empty-script control** before blaming your hooks: if spawn with a 0-byte agent also dies
  in ~4 s, the death is inherited-table damage in the forked pre-initialised process, not a hook.
- **`adb shell pidof` presence is not survival.** Poll and compare to the *pid you attached/spawned*;
  Android restarts a fresh process within a second, so `pidof` returning something while the session
  is detached reads as success. Two extra traps in the same family: frida **unloads the agent when
  the client disconnects** (a script process that exits ends the session — its maps lose every
  `frida`/`gum` line), and an auto-restart is silent. Print the sampled pid next to the attach pid and
  mark a change `RESTART`; a 300 s loop that passed with a changed pid is a crash, not survival.
- Surviving the abort is necessary, not sufficient. If the app sits on the splash, take `debuggerd -b
  <pid>` and a SIGQUIT trace and read the stacks; a repeating frame cycle in the main thread is an
  app-side recursion, which is the next bug, not a win.

## Kill paths: neutralise the import stubs, not the branches

When the protector ends the process deliberately (`abort`, `_exit`, message + abort), enumerate the
kill surface, then patch **one place per import**:

```bash
r2 -q -c 'aa; aar; axtj sym.imp.abort~CALL' lib<guard>.so      # full call-site list
r2 -q -c 'aa; aar; axtj sym.imp._exit~CALL' lib<guard>.so
r2 -q -pd 4 @ sym.imp.abort                                     # stub shape
```

Overwrite the first instruction of each PLT stub with `ret` (`Memory.patchCode(p, 4, c => c.writeU32(0xd65f03c0))`).
Every caller then resumes after its `bl`; all sites are covered at once and no per-site bookkeeping is
needed. Before trusting it, disassemble the instruction right after a few call sites — on real
protectors that is continuation code (`bti c ; b <loop head>`), not padding, which is why the return
lands safely.

- **Do not force the guarding branches as the primary patch.** Each kill call is preceded by
  `b.eq/b.ne/cbz/tbz` and many of those branches are taken on the *healthy* path into cleanup or an
  epilogue; converting all of them to the non-fatal successor skips legitimate exits and corrupts flow
  (symptom: quick self-restart, app ends up backgrounded on the launcher while `pidof` still answers).
  Keep branch forcing as a fallback for a specific check that still kills after the stubs are `ret`.
- Kill-stub `ret` alone is usually not enough: pair it with the GOT/entrypoint repairs the target
  already needs. A stub-only set dies in seconds where stub + repairs holds minutes.
- The kill is not always libc: hardened targets reach art's `Runtime::Abort` too, so keep that stub
  patched as well, and read `logcat -b crash` for `SI_QUEUE` (art abort) vs a real `SIGSEGV`.

## JIT vs interpreter

- `dalvik.vm.usejit=false` + `-Xint` avoids the JIT entrypoint crash but leaves
  `AddNativeDebugInfoForDex` on an unimplemented path.
- With JIT on, `ret` only `AddNativeDebugInfoForJit`.
- Flip one property per run and restart zygote (`setprop ctl.restart zygote`), then wait for
  PackageManager (~1–2 min) before spawning.

## ART thread-start race (retail A16, OEM-stripped libart)

Two faults alternate whenever the injector creates threads while the OEM qpoint stub is live:
`RuntimeCallbacks::ThreadStart` walking a corrupt callback vector (fault at `0x51e158`,
top-byte-tagged garbage), and `__stack_chk_fail` inside `ResetQuickAllocEntryPoints`
(`0x51f830`). JS patches land too late — the first injector thread can already be inside it, so an
attach dies in 3–6 s no matter what the script does.

Order of fixes:

1. **Prefer spawn** (`frida -U -f pkg -l agent.js`): injection happens before app code, so an early
   script patch wins. Attach is a fallback for apps where spawn loses a different race.
2. If attaching, write the skip branch **through `/proc/<pid>/mem` before the attach**: compute the
   libart base from `/proc/<pid>/maps` and `dd` the `b 0x51e168` word (`0x14000007`, little-endian
   `07 00 00 14`) at `base+0x51e14c`. Re-read to confirm. `dd` with `\xNN` escapes fails under
   `su 0 sh -c` nesting — pipe `base64 -d` instead.
3. Replace the qpoint stub from a cave with a table snapshot + replay and a self-check, then keep
   `Runtime::Abort` → `ret`.

With that in place the app can survive the agent *detaching*: after the session times out the
process keeps the dashboard, which is the strongest survival proof available without a proxy.

## dlsym name probe (frida/IDA detection)

Some RASP suites do not scan maps for `frida-agent`; they `dlsym(RTLD_DEFAULT, …)` a fixed name
list — `frida_agent_main`, `ida_checkmem`, `idadir`, `get_ida_subdirs`, `is_ida_kernel`,
`set_ida_state` — from one resolver wrapper, once per poll. Hooking the *app's* wrapper (not the
libc `dlsym`) and returning 0 is portable across frida versions and devices, and beats renaming the
agent export. Locate it by attaching a logger on `dlsym`, reading `args[1]`, and taking the
returning caller offset; then hook that offset with `onLeave: function (retval) {
retval.replace(ptr(0)) }`.

## Native TLS / Cronet

- Java trust hooks never fire; `android.net.http.X509Util` methods are never entered.
- `libcrypto_httpengine.so` / `libhttpengine.so` are stripped: no `X509_verify_cert`, no
  `SSL_get_verify_result`, no strings. Name-based stubs patch only `libssl`/`libcrypto`/`libjavacrypto`,
  which the app does not use.
- Confirm reachability first (`readelf -sW --dyn-syms`), then choose: signature scan + uprobe, or
  rely on the CA being in the system store (which is what actually makes most MITM work).
- A fresh, untrusted proxy CA is the honest A/B: without the patch every handshake fails
  (`Client TLS handshake failed`), so you can measure whether a patch does anything at all.

## Proc observation

Track the fd on `openat` return and sanitize only tracked fds in the `read` hook; map agent thread
names in `task/<tid>/comm`. Renaming to `main` is detectable by duplicate counting, so prefer
per-thread names that match the host app's own scheme.

## Evidence tools

`frida-strace` (patch `mdr3/frida-strace-headless`) drives the server's eBPF `syscall-trace`
service — out of process, so it does not perturb the target:

```bash
frida-strace -H 127.0.0.1:61113 -f <pkg> -i openat -i faccessat --headless --stack 6 --limit 200
```

Typical startup tells: `faccessat` on `/system/bin/su`, `/system/bin/.su`,
`/system/bin/we-need-root`, `faccessat`/`openat` on `/apex/…/conscrypt/cacerts`, and
`openat` on `/proc/self/task/<tid>/comm`.
