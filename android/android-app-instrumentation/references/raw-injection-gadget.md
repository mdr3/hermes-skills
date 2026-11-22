%# Raw injection with frida-gadget (ptrace-free)

Use when attach-class instrumentation dies on its own: bare attach SIGSEGVs in
`libart`, `frida -p` answers `process not found` / `connection is closed` at every
delay, and the app outlives the payload by seconds. The point is that **nothing is
debugged**: no `TracerPid`, no `frida-server`, no ptrace stop at startup.

## Build the injector

```
git clone --depth 1 https://github.com/ferib/android_injector
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
    -O2 -o /tmp/ainj src/main.c -llog
```

`-llog` is required; without it the link fails on `__android_log_print`.

## Prepare the payload

1. Payload = `frida-gadget-<ver>-android-arm64.so`, xz-decompressed (release assets
   often 504 through a corporate proxy — `https://ghfast.top/<url>` works).
2. **It must live in app-private storage**, `/data/data/<pkg>/libgadget.so`:
   `/data/local/tmp` gives `couldn't map segment 2: Permission denied`, because
   SELinux only grants `execute` on `app_data_file` with the app's own scontext.
3. `chown <uid>:<uid>`, `chmod 644`, `restorecon` — take the uid from
   `stat -c %u /data/data/<pkg>` (it changes on reinstall; 10xxx is u0_aXXX).
4. Config is a **sibling file named `<gadget>.config.so` containing JSON**:

```json
{"interaction":{"type":"script","path":"/data/data/<pkg>/agent.js"}}
```

5. Scripts and any `.so` a script loads go in the same directory, same ownership.

## Run

```
adb shell am force-stop <pkg>
adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1
sleep 1
P=$(adb shell pidof <pkg> | tr -d '\r' | tr ' ' '\n' | head -1)
adb shell "su -c '/data/local/tmp/ainj $P /data/data/<pkg>/libgadget.so'"
```

The injector hooks libc `malloc` with a code cave, `dlopen`s the gadget once,
restores the page and exits. Success shows as `LIBSTEALTH: HOOK malloc ... injected`
→ `write str ptr` → the payload's first log line, plus `avc: granted { execute }`
for the payload path.

## Payload rules under a gadget

- **`setTimeout`/`setInterval` never fire.** Top-level code runs, timers do not
  (probe: write a file from a 1.5 s timeout — nothing appears). Do everything
  synchronously, and expose arming as `globalThis.armJava = function () { ... }`
  so the entry bundle calls it after importing the java bridge and setting
  `globalThis.Java`.
- **`console.log` does not reach logcat.** Append to a file in the same directory
  and `cat` it; otherwise a working payload looks silent.
- A synchronous `Java.performNow` on the bridge is what makes `in java ctx` appear;
  there is no timer fallback.

## Verifying

- `grep -c <payload> /proc/<pid>/maps` — present means the library loaded.
- Any `.so` your script `Module.load`s also shows in `maps`; that is the cheapest
  proof the script body executed.
- Remaining footprint is thread names (`frida-gadget`, `gum-js-loop`) and the gadget
  path in `maps`; there is no server port and no `TracerPid`.

## Dead ends worth knowing

- **AndroGhostInjector** (`fatalSec`) is the more advanced variant (eBPF at zygote
  fork, cave scrub) but its capture predicate never fires on an Android 16
  Motorola kernel: it builds, prints `Attached. Waiting for target launch...`, then
  nothing, even after adding `setuid` as a second trigger. Building it needs four
  fixes anyway (typedefs `__u32`/`__be16`/`__wsum`, `BPF_MAP_TYPE_*` and `BPF_ANY`
  constants, `SEC("raw_tp/sys_enter")` with a local `struct
  bpf_raw_tracepoint_args` because the kernel BTF lacks `trace_event_raw_sys_enter`,
  arm64 `libbpf`/`libelf`/`libzstd` via `dpkg --add-architecture arm64`, and
  `-Wl,--allow-multiple-definition` for the libelf/libz `crc32` clash).
- Repackaging the APK with a gadget/`LD_PRELOAD` also works but changes the signer,
  which a hardened app reads as tampering.
