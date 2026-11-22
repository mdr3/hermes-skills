%# Hook survival on a self-hooking runtime

When the target installs its own trampolines over libc exports, a hook can report
success, write byte-identical memory, and never fire.

## Recognise it

- The prologue reads `ldr x16, #8 ; br x16` (`08 00 40 f9 / 00 02 1f d6`) at the
  export, followed by an 8-byte inline pointer that is **not** the real function.
- `Interceptor.attach` on the symbol resolves fine and never calls back.
- The real target is the pointer at `export + 8`. Read it, then hook that address.
  Re-read it on a short cycle, because the runtime repaints the slot.

## Re-arm discipline

- Keep a per-hook hit counter. Re-arm **only** hooks with zero hits since the last
  tick; re-attaching a live hook churns the runtime and stalls the UI.
- Bound the retry window (10–20 s) — a hook that still has not fired after that is
  probably not on the call path, not being repainted.

## Writing memory without stopping the process

- `Memory.patchCode` (mprotect + write) crashes this class of target; the same
  bytes through `/proc/self/mem` hold.
- Open `/proc/self/mem` `O_RDWR` and `pwrite64(fd, buf, len, uint64(addr))` — under
  Frida 17 the offset must be a `UInt64`, otherwise `TypeError: Int64 object
  expected` and nothing is written.
- Opening `/proc/self/mem` fails with `errno 13` while the RASP has dumpability
  cleared, and that flips between launches; fall back to `patchCode` then.
- Writes through `/proc/<pid>/mem` (a foreign pid) bypass page protection entirely,
  so a SIGSTOP/SIGCONT dance is unnecessary, and the stop itself trips the startup
  watchdog.

## Verifying without false positives

- A patch that "looks applied" can still be a wrong encoding: write instructions as
  little-endian bytes (`1f 79 01 71`), never as the printed word (`7101781f`), or
  the app dies of `Illegal instruction`.
- Confirm behaviour, not bytes: the app must survive the event the hook exists for,
  and the hook's own log line must appear.
