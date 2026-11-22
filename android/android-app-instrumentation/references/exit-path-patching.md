# Diverting the app's exit path

An app that leaves on its verdict through `exit_group` issued from its own `svc`
thunk cannot be held by patching `_exit` in libc — the thunk never goes through
libc. Patch the syscall *number* instead, at the thunk.

## Locate the thunk

It looks like any hand-rolled syscall wrapper: `mov x8, x0` then a chain of
argument shuffles ending in a bare `svc #0`. In the shipped library, the `svc`
sits at a fixed file offset; find it from the decompiler's xrefs to the exit call,
or scan for `01 00 00 d4` preceded by `aa 03 0? e8`-style shuffles.

Compute the runtime address from the APK, not the `.so`: the library's data offset
inside the zip plus the offset inside the library. Then read the mapping in
`/proc/<pid>/maps` whose **path is the APK** and take the start of its **`r--p`**
line — there the file offset *is* the library offset.

## The patch

Twenty bytes, little-endian, replacing `svc ; cmn ; cneg ; b.hi ; ret`:

```
cmp w8, #94           1f 79 01 71
b.eq <ret>            60 00 00 54      (imm = (ret - this)/4)
svc #0                01 00 00 d4
cmn x0, #1, lsl #12   1f 04 40 b1
cneg x0, x0, hi       00 94 80 da
b.hi <errno>          08 .. .. 54
ret                   c0 03 5f d6
```

The `cmn`/`cneg`/`b.hi` tail is not decoration: without it every other syscall in
the app reports raw `-errno` instead of `-1` with `errno` set, and callers that
compare against `-1` take the error branch as success.

Door-bell in libc as well when the app also calls `syscall()` directly — the same
diversion at the `svc` inside libc's `syscall()` wrapper (offsets from `.dynsym`
via `pyelftools`, then add the library base). Keep libc `_exit` unpatched if you
bind-mount libc; `ret` there returns into a dead frame and every process crashes
at exit.

## Order and timing

Patch before the verdict, which for a startup check means immediately after the
session exists — or before the attach at all, while the process is un-instrumented
and harmless to poke. Write with no SIGSTOP/SIGCONT.

## Persistence

The same twenty bytes go into the APK at the same file offset, which survives
relaunches and needs no tooling at run time (CorePatch or the original signer, so
the install is accepted). Verify the installed copy, not the file you built:
`pm path <pkg>`, then `dd bs=1 skip=<off> count=24 | od -An -tx1`.

## Reading the failures

- `Illegal instruction` — the bytes went in big-endian, so the first instruction
decodes as `fnmadd`.
- `Segmentation fault` printed by `adb shell` itself — you `ret`'d `_exit` in a
  bind-mounted libc.
- Patch present, app still dies — the exit is on another path (`abort`, a `kill`
  from a supervisor thread, or the spawn/resume protocol), not this thunk. Trace
  for `tgkill`/`kill` before widening the patch.
