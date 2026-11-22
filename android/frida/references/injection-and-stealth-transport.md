# Injection transport: frida fork hardenings and renef

Two fileless-adjacent delivery options to try when a ptrace attach is what the RASP catches. Both
move bytes with `memfd`/abstract sockets and neither is a substitute for the runtime repairs in
`hardening-notes.md`.

## Renef (third-party, C++/Lua, no ptrace)

Prebuilt arm64 release + Linux client from `Byterialab/renef`; deploy `renef_server`, `renef` and
`libagent.so` to `/data/local/tmp`, run the server as root, talk to it over
`adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit` (the docs also show
`--local` on-device).

What to expect on a hardened app that aborts under frida:

- `-s <pkg>` (spawn) is `kill -9` + `monkey -p <pkg> 1` + `pidof` + inject. It finds the pid and then
  **stalls inside inject**; treat spawn as unsupported for the target.
- `-a <pid>` completes the loader (its log shows 7 stages, "Injection complete") but the client still
  prints `(no response)` / `Failed to start process`. That string is a **client-side wait timeout, not
  a failure** — check the server's own log for "Injection complete" before judging.
- The app dies shortly after, so renef proves the transport works, not that the target survives.
- Its server logs with `std::cout`: block-buffered over adb, invisible while it runs. Start it under
  `adb shell -tt 'su 0 ...'` (interactive pty) or the log stays empty and debugging is blind.
- Design it uses: inline hook of `malloc`'s body, stage-1/stage-2 parked in the libc `timezone` data
  slot, signal pokes to force the trigger, payload path `/data/local/tmp/libagent.so`.

## Frida fork: memfd name and no-ptrace loader

Building a fork from source is the way to kill the fingerprint at its origin instead of scrubbing it
with a script. What actually makes a difference:

- **Rename the injected memfd at the real injection path.** `lib/agent/agent-glue.c`/`.vala` and the
  host-session are both irrelevant for attach: the name comes from `AgentResource.get_memfd` in
  `src/linux/linjector.vala` (`MemoryFileDescriptor.from_bytes ("jit-cache.so", blob)`). Renaming in
  `linux-host-session.vala` builds fine and changes nothing. Verify from the **detector's** side: hook
the maps parser in the guard lib, decode the path argument, and confirm zero `frida-agent` strings.
- **Abstract UDS control channel**, `frida-server -l unix-abstract:<name>`; nothing appears in
  `proc/net/tcp` and the client reaches it with `adb forward tcp:<p> localabstract:<name>`.
- **Do not reintroduce a helper.** A `frida-helper` child is visible in `ps -A`; the stealth path must
  not spawn one.
- **No-ptrace loader shape** (in `linux-host-session`, gated by an env var): read `/proc/<pid>/maps`,
  resolve libc, find `malloc`'s `R_GENERIC_JUMP_SLOT` via `Gum.ElfModule.enumerate_relocations`, find a
  zeroed code cave in libc `.text`, write a stage-1 trampoline through `/proc/<pid>/mem`, point the GOT
  slot at it. Stage 1 saves the caller state, streams the agent over an abstract socket into a
  `memfd_create` fd, `dlopen("/proc/self/fd/N")`, `dlsym(entry)`, calls it, closes fds, restores the
  slot and branches to the real `malloc`. Art's symbols `dlopen`/`dlsym` resolve from libc exports on
  modern Android.
- **Trampoline correctness:** restore the GOT slot as the *first* instruction after the prologue (the
  app's other threads keep calling `malloc`; leaving the hook armed re-enters init concurrently and
  corrupts the agent), save/restore `x19` if you use it (callee-saved), and keep every frame slot
  inside the allocated frame (`ldr/str` offsets past `sp+frame` quietly hit the caller's frame).
- **Prove it**: attach to `system_server` and assert `TracerPid:\t0` while attached, `jit-cache`
  mappings present, `frida` map lines 0, `frida-helper` count 0, and a `send()` roundtrip. Those five
  checks pass while a hardened app still dies fast — the loader running is not survival.
- Known remaining gap: when stage 1 runs the agent entry on the `malloc` caller thread instead of a
  dedicated thread (as the ptrace helper does), thread-lifecycle callbacks land on app worker threads
  and the app aborts within a second. Spawn a detached thread in stage 1 (`clone`) that does the
  dlopen/entry and let the malloc caller jump straight back.
