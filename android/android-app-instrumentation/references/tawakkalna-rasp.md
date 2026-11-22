# Tawakkalna (sa.gov.nic.twkhayat) — RASP mechanics and the bypass that holds

Everything here was measured on a rooted Motorola edge (Android 16), Frida 17.x.

## How the verdict leaves the process

Patching libc `_exit` alone never helped: the app issues `exit_group` (94) through
its **own svc stub** at `libTwkappNative.so+0x31ddac`, and through libc `syscall()`
(`0xc2ae0`). Both must skip only nr 94, keeping the errno tail:

    cmp w8,#94 ; b.eq <ret> ; svc #0 ; cmn x0,#1,lsl#12 ; cneg x0,x0,hi ; b.hi <errno> ; ret

Beyond that:

- `_exit` (`libc+0x103540`) → park with `b .` (`00 00 00 14`), so the exiting thread spins
  instead of taking the process down.
- `abort` (`0x9b8ac`), `kill` (`0x100900`), `tgkill` (`0x100940`) → `ret` (`c0 03 5f d6`).
  Parking **these** delivers no signals and produces an ANR; `ret` is what keeps the
  UI responsive.

## Writing the patch

`pwrite` into `/proc/self/mem` (`open(..., O_RDWR)`, offset as `uint64`, not a
`NativePointer`). `Memory.patchCode` (mprotect) also works and is the fallback when
the fd cannot be opened.

`open("/proc/self/mem")` fails with **errno 13** on some launches — the RASP flips
`PR_SET_DUMPABLE`. Always ship the patchCode fallback; verify with the external
`/data/local/tmp/devmem <pid> <addr> <n>` reader that the bytes really landed
(`00 00 00 14` / `c0 03 5f d6`).

## Their hooks beat a naive Interceptor

Before the app is up, libc exports read as plain prologues; once the RASP runs it
installs its own `ldr x16,#8 ; br x16` trampoline on `openat`, `connect`, `getpid`
and friends. `Interceptor.attach` on the export then reports success but writes
identical bytes over their trampoline and **the callback never fires**.

Resolve the literal at `+8` and hook that address instead, and re-install on a tick:
reverting a hook that is still hot is fine, but keep a per-hook "fired since last
tick" flag so live hooks are left alone.

`X509_verify_cert` (`/apex/com.android.conscrypt/lib64/libcrypto.so+0xa6fc8`) is **not**
reached during normal traffic (eDBG: no hit in 60 s). Verification is Java-side
(`TrustManagerImpl`, `CertificatePinner`), so an SSL bypass has to be Java hooks.
`connect` backtraces only ever show `libcrypto!RAND_need_entropy ← RAND_bytes ←
NativeCrypto_RAND_bytes ← Conscrypt.OpenSSLRandom ← SecureRandom`.

Which object actually decides was narrowed with a control run **without any agent**:
the SDK logs our certificate and rejects it —

```
E/SecurityComp10300301: SX509TM(…): root ca issuer : O=mitmproxy, CN=mitmproxy
E/SecurityComp10300301: SX509TM(…): checkServerTrusted error : … Trust anchor … not found
```

— while the CA is present and correctly labelled in both stores
(`/apex/com.android.conscrypt/cacerts/<hash>.0`, `u:object_r:system_security_cacerts_file:s0`,
system store 151 entries / apex 122). So `SecureX509TrustManager` validates against a
**bundled** root list: no store-side fix (apex overlay, reboot, system CA) can help, only
`checkServerTrusted` on that class. Hook every plausible sibling blind —
`SecureX509TrustManager`, `HiCloudX509TrustManager`, `SecureX509SingleInstance`,
`SSFSecureX509SingleInstance` under `com.huawei.secure.android.common[.ssl]` — and
identify the live one by which `HIT` fires; the Huawei classes survive obfuscation as
strings only, no `L…TrustManager;` descriptor remains in the dex.

### Static-sweep red herrings

Name greps lie once the code is obfuscated. `watchDogThread` is
`com.huawei.riemann.location.gwivdr.utils.InputFreqCheckThread.run` (a location sensor
thread) and the only `Process.killProcess` + `System.exit` pair in the SDK dexes is GMS
`PhenotypeProcessReaper`; neither is the verdict. The app dies by signal, so enumerate
framework call sites (`dexdump -d <dex>` then grep `Landroid/os/Process;.killProcess`,
`Ljava/lang/System;.exit`) and treat a hit as a lead to confirm at runtime.

Thread-lifecycle traffic is the crash common denominator: `ThreadStart`,
`Thread::CreateCallback`, `ArtMethod::Invoke` and `RunCheckpoint` all appear in
symptoms. Guard `AddNativeDebugInfoForDex` (`libart+0x411d58`) and `RunCheckpoint`
(`libart+0x2e31e0`) with the shadow-page restore, and drop the app's own registration
by patching `RuntimeCallbacks::AddThreadLifecycleCallback` (exported, `0x5800fc`) to
`ret`, so the repainted callback list is never walked.

## ResetQuickAllocEntryPoints on this build

The live `entry_points_allocator` reads **1 (TLAB)** — read the byte at
`libart+0xe03220` before touching anything and leave `entry_points_instrumented`
(`0xe0f8b0`) alone too. Forcing kind 0 installs bump-pointer entrypoints on a TLAB
heap, after which the crash merely moves to `art_quick_invoke_stub` /
`Thread::CreateCallback`. Only 4, 5 and >7 need the fallback at all.

The FATAL default tail is `libart+0x55df4c`. Patching it in place is where the two
obvious encodings both go wrong:

- `Interceptor.replace` with a `NativeCallback` that calls the real installer is
  address-only and survives a rebuild, but it is a mid-function replace and aborts on
  the next thread on some builds;
- a 12–16-byte literal branch written at `0x55df4c` overwrites bytes that **other
  switch cases jump to** (`b.ne` targets live inside the body). Only 4 bytes are safe:
  write `b <cave>` there and put the whole sequence in the cave.

The handler itself: `InitEntryPoints` does `mov x19, x1` and `mov w20, w2` in its
prologue (`0x55d750` / `0x55d74c`) — so `x19` is the quick-entrypoints table and the
bool is `w2`, but at the tail `x1` is already clobbered by the `bl` into the
sub-installer, so neither `mov x19, x1` nor `mov x19, x0` restores it. The cave should
`ldr`/`str` the incoming `x19` around the call to `SetQuickAllocEntryPoints_region_tlab`
(`0x55e3f8`) and return to `0x55d76c`; the truth test is the `x19` value in the
`Fatal signal` register dump — a short garbage word (e.g. `f6e8…`) means the restore
never ran, and `fault addr` equals `x19 + 0x70`.

Removing the deadlock and removing the abort trade places: skipping
`StartupCompletedTask::Run` (`0x5afbf8` → `ret`) clears the `RunCheckpoint` suspend but
the process then walks straight into the tail abort, and a plain `ret` out of
`InitEntryPoints` leaves JNI entrypoints unset (deadlock returns in
`CreateNativeThread`). Treat both patches as required, not alternatives.

Deciding what actually killed it: `adb shell su -c 'ls -t /data/tombstones | head -1'`
then grep `Abort message` — `void art::ResetQuickAllocEntryPoints(QuickEntryPoints *)
unimplemented` means the allocator byte was out of range, not that the RASP fired.

## The check list lives in memory, not in the strings you can grep from the APK

A dump of the running process (per-process region dump, see
`references/memory-dump-and-detection.md`) yielded the decrypted detector table in an
anonymous `rw` region: `xposed`, `frida`, `substrate`, `cycript`, `frida_agent_main`,
`ida_checkmem`, `idadir`, `get_ida_subdirs`, `is_ida_kernel`, `set_ida_state`,
`/proc/self/fd`, `/proc/self/task`, plus `libc.so` and `libart.so` as hashed objects.
Take that table as the spec: it names exactly what has to answer differently, and it
is only readable while the process runs — a static sweep of the APK misses it.

Note the code references the table through data pointers, not direct `adrp`/`add` to
the string, so xref-hunting the strings from code finds nothing (0 hits over 380
page references). Do not burn time on it; drive the syscalls instead.

## Stealth by not touching ART

The crash was always the ART entrypoint path, so a variant that never hooks ART or the
Java bridge at all keeps the process alive where every richer payload died: 90 s+, main
thread idle in `Looper::pollInner`, no ANR, no tombstone. It works purely at the syscall
layer, all in one script:

- `openat`/`open` on a path containing `frida`, `gadget`, `linjector`, `gum-js`,
  `re.frida`, `magisk` → `-ENOENT` (also on `stat`/`access`),
- `/proc/self/maps` reads get the frida/gadget/linjector lines filtered out,
- `/proc/self/status` always reports `TracerPid:\t0`,
- `/proc/self/task/<tid>/comm` reports `gmain`, `gdbus`, `pool-frida` as `main`,
- track fds from the `open` return and clear them in `close`, so only the right reads
  are rewritten.

**Your own hooks are the tell when the app hashes libraries.** Hooking libc patches its
code, so a hash of `libc.so`/`libart.so` sees the instrumentation. Copy both to
world-readable storage (`chmod 644` — the app reads them as its own uid) and rewrite the
`openat` of the apex paths to those copies; hashing then reads pristine bytes.

**Keep the copy and the live mapping byte-identical.** The one patch still needed is the
`bl abort` at the end of the UNIMPLEMENTED entrypoint case (`libart+0x55dfac`) — the
abort fires even with pure libc hooks, ~5 s in, with `Abort message: …
ResetQuickAllocEntryPoints … unimplemented`. `Memory.patchCode` that word to `nop`
(`1f 20 03 d5`) *and* write the same bytes into the file offset of the pristine copy;
libart's text segment has `vaddr == offset`, so a file offset is a safe VA. Patch only
the copy and the hash check flags the difference.

Honest state after this: the process stays up at the splash and attempts no
`nic.gov.sa` connection at all, so the remaining blocker is the RD/trust path, not
stability.

## App data rots after aborted starts

Before that, though: a **bare** launch (no agent at all) dies with SIGSEGV in the
`libmedia`/`MediaMetadataRetriever` constructor under Glide. The PLT slot is never
resolved by the linker, so the fix is to write the GOT entry — `libmedia.so+0xae3c8`
(reloc for `_ZN7android22MediaMetadataRetriever10getServiceEv`) pointing at the real
`getService` (`0x990b8`); ~231 slots are similarly unresolved. Bind it from a `dlopen`
watcher on `libmedia.so` *and* on `libmedia_jni.so` (guard
`android_media_MediaMetadataRetriever_native_setup`) — a script that only loads at spawn
can otherwise miss the library, which arrives as a DT_NEEDED dependency rather than
through `dlopen`.

A few killed sessions and the app dies ~5 s after launch with SIGSEGV in
`MediaMetadataRetriever` on `glide-source-th` (libmedia). `pm clear` is the reset, but
then:

- start the app **first** so Android creates `files/` with the right uid and SELinux
  categories (a root-made dir gives `Failed to create directory: files/datastore`),
- the uid changes on reinstall (10429 → 10430) — read it from `stat -c %u`, never hardcode,
- the comm decoy at `files/fake_comm` must take the parent's context
  (`stat -c %C`), not plain `app_data_file:s0`.

## Attach window

~1 s → `ProcessNotRespondingError`; ~15 s+ → splash stall and an ANR dialog, after which
attach fails too. It lands between roughly 3 and 10 s. `harness.py` carries `--stop`
(SIGSTOP across attach, then CONT after load), `--retry`, and `FRIDA_ADDR`.
frida-server `undetected` wedges or dies after an aborted session — restart it per
attempt, and note a dead device USB (`lsusb` empty) looks identical to a broken script.

## Proxy side (for SSL work later)

A transparent proxy never learns the original destination when the traffic arrives
over adb/Wi-Fi: mitmproxy forwards to its own listener and logs
"Request destination unknown". What works: `mitmdump -k --mode reverse:https://api.tawakkalna.sa
-p 8080`, `/etc/hosts` mapping the host (the phone's resolver can also fail on it — the
app talks to 66.9.126.42 directly), and a Frida `connect()` rewrite of 443 to the host.
ProxyPin CA installed as a system CA under its `subject_hash_old` (`cde23f7b.0`).
