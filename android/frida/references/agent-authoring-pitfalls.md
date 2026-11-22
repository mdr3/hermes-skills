# Authoring agents that actually arm and observe

Traps that make an agent look installed while emitting nothing, or that only surface once the
agent runs inside the app uid. Every one of these cost a debugging round-trip.

## Logging

- **Do not assume a shared `log()` exists.** A prelude that defines helpers for one module does not
  export them to another; a call to an undefined `log()` throws inside the arming function and the
  hook silently never installs. Define a local `function L(x){ console.log('[tag] ' + x); }` in each
  module.
- Prefix per module (`[e]`, `[c]`, `[p]`, `[k]`) so a single grep isolates one layer during a run.

## Buffers and native calls

- **`readUtf8String()` throws on `/proc` content** (`can't decode byte 0x00`). Read
  `readByteArray(n)` and build the string yourself; for payload dumps map non-printables to `.` and
  `\n` to a literal escape so one line stays greppable.
- **`NativeFunction` return type `'long'` gives an Int64 object, not a number.** `n === s.length` is
  therefore false and every write looks like a failure. Use `'int'` for `read`/`write`/`open` on
  Linux, and remember `open` is variadic: pass the mode as the third argument.
- Dump at the SSL boundary in `onLeave` using the saved pointer/length from `onEnter`; for reads use
  the **callback argument** (`onLeave: function (retval)`) — `retval.toInt32()` — and skip <= 0.
  `this.retval` is undefined on Frida 17 and throws `cannot read property 'isNull' of undefined`.
  Rewriting a return is `retval.replace(value)`.

## Filesystem

- **`/data/local/tmp` is `1771`** — group has write, *other* has execute only, so an app-uid agent
  cannot create files there. Redirect to `/data/data/<pkg>/files`, deriving `<pkg>` from
  `/proc/self/cmdline` (first NUL-delimited token) instead of hardcoding a package.
- Keep temp names short and per-tid (`.c<tid>`) so a thread-name scrub does not rewrite one file
  for every thread.

## Verification

- Print a marker only *after* the `Interceptor.attach` returns, and one more when the first real
  event lands. An "armed" line alone proves nothing about the process you are in.
- Check ownership before reading logs: `pidof` vs the pid in `ss -tnp`. Hooks in a dead pid produce
  perfect-looking output and zero traffic.
- **Preload the real agent at spawn, never an empty script.** A follow-driver that resumes with a
  do-nothing preload covers only the restarts: when the process happens not to re-fork, no hooks
  exist at all and the run looks like "the agent does nothing". Load the agent while suspended *and*
  attach to new pids.
- **`pidof` returns a space-separated list.** After a fast `am force-stop` + spawn, an older
  instance can still be alive, so `int(pidof_line)` raises and the loop dies. Split the output, and
  wait >=3 s after force-stop so the readings describe one process.
- `console.log` from the agent reaches the host through the device output stream; if lines appear
  for other modules but not yours, the module threw, it is not a transport problem.
