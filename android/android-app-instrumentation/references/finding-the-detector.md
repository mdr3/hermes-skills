# Locating check code in a stripped, flattened library

Goal: turn "the app refuses" into a named call site, native entry and Java caller,
without symbols, strings or prologues to lean on.

## 1. Confirm the library

List the modules mapped from the app's own directory. A RASP library is not in
`/system` and not in `libart` — it is `dlopen`-ed from the split APK, so it shows
up under `/data/app/.../split_config.*.apk!/lib/<abi>/`. Everything else under the
app path is the odex/boot image.

ART loads it through `__loader_dlopen` or `__loader_android_dlopen_ext` in
`libdl.so`; it never calls the public `android_dlopen_ext`. Hook both.

## 2. Work in `onLeave`, not `setImmediate`

`onEnter` is too early (nothing is mapped), and `setImmediate` loses the race
against `JNI_OnLoad`, so startup checks run before your patch lands. In `onLeave`
the segments exist and `JNI_OnLoad` has not been invoked yet — patch or hook there
and every later call is covered. Keep the offset work in a helper you can also
call from a timer, and guard it with a `done` flag.

## 3. Get the real call sites from a backtrace, not from IDA labels

Hook the libc probes the check makes (`access`, `stat`, `openat`, `opendir`,
`readlinkat`) and, for interesting paths, send

```js
Thread.backtrace(this.context, Backtracer.ACCURATE)
  .map(a => { const m = Process.findModuleByAddress(a);
              return m ? m.name + "+0x" + a.sub(m.base).toString(16) : "" + a; })
```

Drop `libart.so` frames. What is left is the checker's own call sites plus the
`boot.oat` frames above them, which proves the check is a JNI native invoked from
Java — a fact that decides your whole strategy.

### 3b. One probe at a time: take the offset from `returnAddress`

When the target is a single distinctive probe (a path containing `/comm`, `/su`,
`TracerPid`), skip the backtrace and log the caller directly:

```js
Interceptor.attach(acc, { onEnter(a) {
  if (!LIB) LIB = Process.findModuleByName("libTwkappNative.so");   // not mapped at spawn
  const s = a[0].readUtf8String();
  if (s && s.indexOf("/su") >= 0)
    console.log("site " + this.returnAddress.sub(LIB.base));
}});
```

Resolve the module **inside** `onEnter`, never at the top of the script: at spawn
the library is not loaded yet and `getModuleByName` throws before any hook arms.
`returnAddress` is the instruction after the `bl`, so subtract `0x4` to land on the
call and disassemble forward and back from there. This is the fastest route from a
behaviour to the code that decides it when the string is decrypted at runtime and
there is nothing to grep for.

## 4. Enumerate candidate entries from the relocation table

Offsets taken from the disassembler at a `bl` are call sites inside a function, not
entries; `Interceptor.attach` there logs nothing. Instead take every
`R_AARCH64_RELATIVE` target that lands in `.text`:

```
readelf -rW lib.so | awk '{print $4}'   # filter to .text range
```

Hook **all** candidates within ±0x600 of the call sites with a log-only `onLeave`,
run once, and keep the offsets that actually fire. Typically one or two do; the
rest are dead branches of the flattened machine.

## 5. Recognise an early-return state stub

A block that is `mov x0,#imm16` / `mov x1,#imm16` / `ret` is not a function
epilogue with a value — it is a state return. Find them all by byte pattern
(`d2800000|imm<<5` for `mov xN,#imm`). The pair it returns is the machine's own
token pair, which is why inventing a plausible int (`0`, `1`, `true`) crashes.

If you must change the verdict here, brute-force the state space in one run per
candidate and classify: crash (`pc=lr=0x8`) = invalid state, alive + verdict
unchanged = valid but wrong branch, alive + verdict gone = the one you want.
Single-digit powers of two are enough to find the live neighbourhood.

## 6. Name the Java caller without enumerating classes

Inside the native hook:

```js
Java.performNow(() => {
  const E = Java.use("java.lang.Exception").$new();
  send("ST " + Java.use("android.util.Log").getStackTraceString(E));
});
```

That names class, method and the `Runnable`/thread that drives the check — the
anchor for a Java-layer bypass — without touching the class loader at all.

## 7. Judge by the gate, not the dialog

A dismissed "not secure" **info** dialog is not a bypass. Re-drive the action that
is gated (login) and look for the error variant of the same string. If it appears,
the verdict still stands and only the toast changed.
