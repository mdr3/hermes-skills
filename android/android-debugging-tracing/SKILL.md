---
name: android-debugging-tracing
description: "Debug and trace authorized Android apps with adb, logcat, native debuggers, syscall tracing, crashes, and sanitizer/runtime evidence."
metadata:
  category: Android
  short-description: "Debug and trace authorized Android apps with adb, logcat, native debuggers, syscall tracing, crashes, and sanitizer/runtime evidence."
---

# Android Debugging and Tracing

Use this when the decisive evidence is execution order, register state, syscalls, thread behavior, or a crash. Keep a reproducible launch command, device build fingerprint, app version, architecture, and selected debugger.

## Establish a clean baseline

```bash
adb shell getprop ro.product.cpu.abi
adb shell dumpsys package com.example.target
adb logcat -c
adb shell am start -n com.example.target/.MainActivity
adb logcat -v threadtime
```

Separate application logs from framework and native crash records. `pidof`, tombstone locations, and mapping files tie a crash to an exact library/version.

## Native tracing

For a debug build or an explicitly controlled lab package, attach LLDB/GDB to the target process and record the mapped library base. Break on an exported JNI symbol, JNI registration function, suspicious syscall, or a static-analysis address plus module base. Inspect ABI-specific argument registers and stack alignment.

Use `strace`-style syscall traces to identify file, process, socket, and loader behavior. Correlate a syscall with the calling thread and static call path; a syscall log alone does not establish which function requested it.

## Trace strategy

- Prefer module-relative addresses over raw addresses.
- Stop on the first divergence from the expected state.
- Record register/memory bytes with width and endianness.
- Cap trace volume and rotate logs.
- Re-run once with a narrower breakpoint or hook to confirm causality.

Use Frida for high-level method and object observation, then a native debugger when instruction-level state or precise stack/register evidence matters.

When the app is frida-resistant or you need kernel-side evidence, eBPF uprobes attach to a mapped library symbol without touching the process and survive most RASP checks. Build/attach procedure, MTE pointer handling and verifier constraints live in the `android-network-crypto` skill, `references/ebpf-uprobe-crypto.md`.

## Sources

- Android debugging: https://developer.android.com/studio/debug
- LLDB: https://lldb.llvm.org/
- Android NDK debugger docs: https://developer.android.com/ndk/guides/

## Lessons: crash forensics that paid off (2026-11)
- `dumpsys activity exit-info <pkg>` gives the real death cause even with an empty crash buffer: `reason=2 (SIGNALED) subreason=0 status=11` = SIGSEGV, not an explicit kill/abort syscall.
- Tombstones live in `/data/tombstones`; a `SEGV_MAPERR` in `art::AddNativeDebugInfoForDex` was the Frida-attach death, reached during a `RegisterNatives` storm.
- bionic `abort`/`_exit` use inline `svc`, so syscall tracers that hook `kill`/`exit_group` wrappers see nothing; read exit-info instead.
- Attaching a tracer after the crash window records 0 lines (`process-terminated`). Either attach earlier or use `dumpsys`.
- `tracing_on=0` silently disables tracefs evidence; check it before concluding a probe never fired.

