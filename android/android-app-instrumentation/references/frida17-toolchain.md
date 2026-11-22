# Java bridge under Frida 17

**Check the runner before bundling anything.** The bridge is only missing when
*you* create the script: `session.create_script(src)` in Python has no `Java`
global (and no `require`). The `frida` **CLI does** — frida-tools ships
`bridges/java.js`, the agent asks the host for it with a `frida:load-bridge`
message, and the host evaluates it in the script (see
`Application.try_handle_bridge_request`). So `frida -p PID -l plain.js` runs a
100-line plain script with a working `Java`, and a bundled payload is only
needed when the driver is a Python harness that does not handle that message.
Always `node --check` the plain script before loading it.

`Java.perform` still exists, and the rest below applies to bundled payloads.

**Corollary: ship a plain script when the deliverable is run from the CLI.** Because
frida-tools injects the bridge, a payload the user loads with `-l` needs no bundle at all —
~60 lines instead of ~240 KB / ~1800 lines of bridge. Bundle only for drivers that
`create_script` themselves (Python harness, gadget) or when the user asks for one. Judging
"too big" by the bundle is a sign the plain path was skipped.

When you do bundle, never assign the bridge to a global: newer agents already expose `Java`
as a getter-only property and `globalThis.Java = Java` throws `TypeError: no setter for
property` at load, killing the whole script while the same file loads fine from Python. Gate
on the module binding (`if (!Java || !Java.available)`); in a plain script gate on
`typeof Java === 'undefined'`.

## Toolchain

```
npm pack frida-java-bridge            # or: curl -kL <registry tarball> | tar xz
mkdir -p node_modules/frida-java-bridge && cp -r package/* node_modules/frida-java-bridge/
frida-compile payload.js -o payload.bundle.js
node --check payload.js && node --check payload.bundle.js
```

A ~700 KB bundle is normal. Check the plain script first: a syntax error in it
produces a bundle that loads and runs nothing, and the app then looks perfectly
stable — the most misleading failure mode there is.

On Kali the Python `frida-compile` also writes progress junk into the output
file (`📦`, a `<bytes> /src.js` line, `✄`) unless `-S` is used, and `-S` still
leaves the `📦`/size/`✄` header — `node --check` then fails on line 1 with
`Invalid or unexpected token`. Drop every line before the first `var __defProp`
and re-run `node --check`; a good bundle is ~450 KB for a Java-bridge payload.

## Two runtime errors that look like logic bugs

- `Error: expected an unsigned integer` on `Interceptor.attach` onEnter with
  `args[1] = ptr(0)` — an `int` parameter takes a **number**, not a pointer. Those
  errors fire per call for the whole session and bury the real logs.
- `TypeError: cannot read property 'call' of null` from `const orig =
  ov.implementation` — the getter is null for an overload that was never wrapped.
  Call the overload invoker instead: `return ov.call(this, ...)`.

## Where the bridge still hurts

- Re-attaching to a process that already carries a stale agent (a previous CLI
  session that exited) dies with `SIGSEGV` in `art::JNI::FindClass` on a worker
  thread. One attach per launch: force-stop, start, wait for the UI, attach.
- A plain script that produces no log line at all did not run — judge by the
  first line of *your* output, never by "the process is still alive".

- `Java.perform` scheduled from a timer can no-op silently at spawn; retry behind
  `if (!Java.available)` with a capped counter and a `BEGIN`/`GIVEUP` log line.
- Reading `Java.vm.getEnv()` at spawn throws until the VM is up — wrap it in the
  same retry ticker, never at top level.
- `Java.enumerateLoadedClassesSync()` returns; the async callback form can stall on
  a large app and wedge the gadget (`TransportError: timeout was reached`).
- An ArtMethod replaced at spawn can fault at `pc=0` inside
  `art_quick_invoke_stub`; prefer native hooks, or attach within the first half
  second (see `scripts/frida_early_attach.py`).

## Argument passing

`session.create_script(source, options)` exposes `Script.pin()`/rpc, but there is
no `argv`; for a value you want to vary per run, generate the constant into the
source (a `sed` on a `const X = 0;` line plus a recompile is fast enough) rather
than inventing a transport.
