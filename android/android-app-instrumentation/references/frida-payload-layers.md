# Frida payload layers: what each costs

Ordered from most tolerated to least. Move down only when the layer above cannot
see what you need.

| layer | tolerated | reach | notes |
|---|---|---|---|
| app's own PLT stub (`fopen@plt`, `syscall@plt`) | yes | every call the app makes through libc | path rewrite here keeps the patch inside the app image; find the stub addresses with `llvm-objdump -d --section=.plt <lib>.so` |
| app's own function by offset | yes | one call site | `.so`-relative offsets, add the module base; `dlopen`-return addresses are not hook points, they are post-call sites |
| libc | **no** — app dies | everything, including its own reads | a single `open` hook is enough to trip it |
| libart / Java bridge | no | Java-level API | triggers the ART abort below |

## The ART abort

```
F libc : Fatal signal 11 (SIGSEGV), fault addr 0x... , tid (Jit thread pool)
F DEBUG: Abort message: 'void art::ResetQuickAllocEntryPoints(QuickEntryPoints *) unimplemented '
```

ART's quick-entrypoint reset is a **complete switch**, not a stub. It switches on
`gc::AllocatorType` (0 bump, 1 TLAB, 2 RosAlloc, 3 DlMalloc, 4 NonMoving, 5 LOS,
6 Region, 7 RegionTLAB) and on the `entry_points_instrumented` flag, and only 4, 5
and >7 fall through to `UNIMPLEMENTED`. Anything that instruments methods makes the
JIT thread call it, so an app whose heap sits on an unhandled allocator value dies.
Read the source, not the log line, and read the live allocator byte before touching
it: forcing 0 on a TLAB heap gives you bump-pointer entrypoints and the fault moves
to `art_quick_invoke_stub`. Consequences:

- `setprop dalvik.vm.usejit false` and AOT-compiling the app shrink the window but
  do **not** cure it: a bare agent still dies in ~2 s with both applied.
- Blocking `abort` only converts the abort into a SIGSEGV, because execution then
  runs into the entrypoint table the same inlined code was supposed to install.
- The reset is **inlined into `art::Thread::Init`**, not a callable symbol, so the
  only fix is a branch patch. Locate it by string xref: `strings -t x libart.so |
  grep 'quick_alloc_entrypoints.cc'`, scan for the `adrp`/`add` pair that builds
  that address, and the FATAL block is the `ShouldLog` + `LogMessage` sequence a
  few instructions on. `llvm-objdump` that range and confirm the `bl` after
  `LogMessageD1Ev` is unreachable for FATAL — the `LogMessage` **destructor** is
  what aborts, so NOP-ing the trailing `bl` changes nothing.

### Preferred fix (address-only, ports across builds)

The reset is inlined into `art::Thread::Init`, so you replace the FATAL tail *in that
copy*. Take the two addresses from the switch itself: the `default` tail (reachable
by `cmp`-and-branch from the allocator compare chain) and the
`SetQuickAllocEntryPoints_region_tlab` body it should have called for this heap.

```js
var rt = new NativeFunction(art.base.add(REGION_TLAB), 'void', ['pointer', 'int']);
Interceptor.replace(art.base.add(FATAL_TAIL), new NativeCallback(function (qp) {
  rt(qp, art.base.add(FLAG).readU8() & 1);
}, 'void', ['pointer']));
```

`Interceptor.replace` on a mid-function address is fine and needs no instruction
encoding — the hand-assembled byte patch is what produces `Illegal instruction`
when any register or offset is one off. But on this build `replace` on that tail is
*not* reliable: it faults inside the replacement or leaves the table half-installed.
Branch to a cave instead, and only patch **one 4-byte `b`** — the other switch cases'
targets point inside the case body.

### What the UNIMPLEMENTED case actually is

Disassemble it before designing the cave; it is not a call to the setter:

```
mov w0, #6          ; ShouldLog severity
mov x1, xzr
bl  ShouldLog
 tbz w0, #0, <epilogue>   ; logging off -> straight to the epilogue
 bl  __errno ; ldr w8,[x0] ; …   ; the LogMessage path
<epilogue>: sub x0, x29, #0xc ; bl ErrnoRestorer::~ErrnoRestorer ; (falls into the
            next out-of-line function)
```

So the continuation to resume at is the **`tbz` target**, and
`SetQuickAllocEntryPoints_region_tlab(QuickEntryPoints* in x0, bool in w1)` takes the
quick-entrypoint pointer first. `mov x0, x19 ; mov w1, #1 ; blr <region_tlab> ;
br <tbz target>` reproduces the healthy path. Do **not** just NOP the trailing
`bl abort`: the process survives, but with a garbage table, and every later thread
blocks in `Thread::CreateNativeThread` on `thread_list_lock_`.

### The cave must be in branch range

A 4-byte `b` reaches ±128 MB. `mmap(NULL, …)` lands ~300 MB away and the branch
silently wraps (`delta -282826707`) — the app runs with a cave nothing jumps to.
Scan `/proc/self/maps` for a hole within ±0x6000000 of the module, page-align the
start, and `mmap(hole, page, 7, 0x100022 /* MAP_FIXED_NOREPLACE */, -1, 0)` until one
sticks; log the delta so a wrapped branch is visible. Offsets inside libart are
`0x73b8…`-class, so pointer arithmetic must go through `parseInt(p.toString(), 16)`
— `toUInt32()` truncates and every comparison then finds no hole.

### Byte-level recipe (legacy, verified for this one build)

The healthy path skips the log and re-installs entrypoints; reproduce it in place.
Replace the 16 bytes of the FATAL tail with
`adrp x9,<globals>; ldrb w9,[x9,#<flag>]; and w1,w9,#1; b <continuation>`, i.e. the
same three instructions the surviving branch uses, then the unconditional branch to
the install block. Keep it to one module-build version — these are raw offsets.
Orient by the crash, not by the log: an abort that becomes a different fault is
success, and the next fault is the `.data` repaint below.

## The `.data` repaint

Once the abort is patched, the next blocker is a repaint of libart's `.data` page at
file offset `0xe00000`, ~200–250 ms in, with a **repeating 20-byte random blob**
(whole page, exact period; the `maps` line stays `rw-p 00e00000 ...libart.so`).
That page holds the JIT `ThreadLifecycleCallback` object at `+0x08` (vtable slot 3 =
`ThreadDeath`) and the alloc quick-entrypoint table at `+0x100`. The two crash
signatures are `RuntimeCallbacks::ThreadDeath` doing `ldr x8,[x0]; ldr
x8,[x8,#0x18]; blr x8` on a garbage vtable, and a `stp` into a garbage thread in
`Thread::Init`. Nothing in the RASP source needs to be understood to see this — it
is pure procfs-free memory writes.

Guard it, and know the limits: keep a shadow page, restore it at the **entry** of
the two consumers plus a short watchdog. Restoring only on a timer loses: a thread
already inside `Thread::Init` when the repaint lands still dies. Seeding the shadow
from the disk image is wrong for the runtime-filled half (see the zero-slot rule in
SKILL.md) — capture the reference page from a *clean, uninstrumented* run instead:
`adb exec-out su -c 'dd if=/proc/<pid>/mem bs=4096 skip=<page> count=1'`.

## What is verified

Verified on device: the abort patch removes the `ResetQuickAllocEntryPoints` abort
(progress shows up as the crash moving to the repaint); the repaint is
characterised end to end; a bare agent still dies ~2 s in, so **a fully hooked
session on this ROM family is not yet a solved thing** — do not present any single
script as a reliable recipe until it has produced a decrypted app-host request end
to end. Three more ART call sites have to be neutralised before the runtime is
usable at all, and each one kills the process on its own: `ThreadList::RunCheckpoint`
(→ `ret`; it holds `thread_list_lock_` and main blocks in `Thread::CreateNativeThread`
forever), `AddNativeDebugInfoForDex` and `AddNativeDebugInfoForJit`. The lifecycle
callback pair (`ThreadStart`/`ThreadDeath`) does **not** need a no-op once the cave
is in: with both no-op'd the thread-creation block comes back. Preserve evidence per attempt (`logcat -d | grep -iE 'Fatal signal|Abort
message'`, mitm flow file size) before drawing conclusions.

- Bare agent + user CA + mitmproxy decrypts TLS (TLSv1.3, headers, `X-Goog-Api-Key`)
  for hosts that trust user certs. That is the control, not the bypass.
- Java unpin payloads install and report success on every run — conscrypt
  `TrustManagerImpl`, `OkHostnameVerifier`, `CertificatePinner`, plus every loaded
  `HostnameVerifier`. `Java.registerClass` is **not** usable at spawn: it drops a dex
  in `/data/local/tmp`, which the app domain cannot read (`Permission denied`).
- Native (BoringSSL) unpin avoids ART entirely: `X509_verify_cert` → 1,
  `SSL_get_verify_result` → 0, `X509_check_host` → 1, `X509_check_ip_asc` → 1.
- With the runtime unusable, prefer the no-agent layer for TLS work at all — an
  LSPosed module, hooks deferred to `Instrumentation.callApplicationOnCreate`:
  `references/lsposed-modules.md`.
