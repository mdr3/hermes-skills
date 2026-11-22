# Java-layer verdict hunting (reflection-driven RASP)

For when the checks resolve into Java: obfuscated `com.<vendor>.internal.*`
classes, natives called through a reflection bridge, a verdict boolean consumed by
a badge/dialog poster and by the login gate.

## Enumeration that survives the reference table

The app caches `Method`/`Class` global refs and runs close to the 51 200 cap;
wide enumeration is what kills it (`global reference table overflow`, abort in
`JavaVMExt::AddGlobalRef`). Therefore:

- use `Java.enumerateLoadedClassesSync()` (the async form stalls), then filter the
  array by package prefix in JS — do not filter in `onMatch`;
- resolve a class through the loader that owns it: collect loaders with
  `Java.enumerateClassLoadersSync()`, take the one whose `toString()` shows the
  app's APK or an `InMemoryDexClassLoader`, then `Java.ClassFactory.get(l).use(name)`;
- hook one class namespace per run when the app is fragile, and keep native-only
  payloads for anything that must hold for minutes.

## Read signatures, do not guess them

```js
k.class.getDeclaredMethods().forEach(m => send("SIG " + m.toString()));
```

This lists name, parameter types and return type in one line, including
`native`, and it costs four wrappers per class instead of a scan. Method names in
these apps are UI-flavoured decoys (`logger`, `put`, `disableLogging`, `run`), so
the *types* are the only reliable sort: `put(int,long): byte[]` returning comma
joined ASCII is a frame describer, not a verdict.

## Find the verdict by differential return

Hook every `boolean`/`int`-returning method of the suspected classes with a
pass-through logger first. The verdict stands out as the one boolean that returns
`false` at startup, a handful of times, on the `Runnable` that fires the check.
Force it and watch what changes:

```js
if (r !== true) { send("LG " + r); return true; }
```

Forcing the verdict suppresses the launch dialog with no crash — a good sign, not
the end: the login path re-evaluates and refuses. Two outcomes to keep apart:

- verdict forced, dialog gone, gate still refuses → the gate reads a second source
  (a field written earlier, or a native scan that must also be spoofed);
- verdict forced, app closes on the consent button → verify with no agent attached
  whether that is app behaviour before blaming the payload.

## Suppression vs verdict

Suppressing the poster (`getBadgeContent`-style class) or dismissing only the
security dialog keeps the UI usable and is worth shipping on its own, but say
plainly which of the two you have. Never present a dismissed dialog as a bypassed
check.
