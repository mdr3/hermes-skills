# Hala Control (`sa.hala.control`) — guard, pinner and trust layer

App-specific map for the 1.1.40 Staging build. Everything here was read off the APK or
proved on device; class names are R8 output and change every release — re-derive them
before reusing (see "Re-finding the names").

## What the app actually has

- `libhalaguard.so` (9.6 KB) + `sa/hala/android_extensions/security/NativeGuard`, new in
  1.1.40. Registered in `JNI_OnLoad` as three natives:
  - `rc()I` — `faccessat(AT_FDCWD, path, F_OK, 0)` over `/system/bin/su`, `/system/xbin/su`,
    `/sbin/su`, `/su/bin/su`, `/vendor/bin/su`, `/data/local/bin/su`, `/data/local/xbin/su`,
    `/system/bin/.ext/.su`, `/system/xbin/daemonsu`, `/sbin/.magisk`, `/data/adb/magisk`,
    `/data/adb/modules`, `/cache/.disable_magisk`, `/data/adb/magisk.db`. Returns a bitmask
    (1 su, 2 magisk, 4 magisk-mount).
  - `hc()I` — `openat`+`read` of `/proc/self/maps`, case-insensitive scan for `frida`,
    `gum-js-loop`, `gmain-frida`, `frida-gadget`; also walks `/proc/self/task/*/comm`.
  - `dc()Z` — debugger (TracerPid).
  All calls go through the `syscall` import, **not** libc wrappers, so `open`/`fopen` hooks
  see nothing. The Java class is a thin wrapper (`isHookedNative`, `isDebuggerNative`,
  `isRootedNative`, `rootSignals`, `getLibraryLoaded`).
- It is a **reporter, not a killer**: `MainActivity` builds a `"BLOCKED: [...]"` list and the
  startup screen (`sa/hala/feature/startup/phone/h`) takes a different branch, but the
  process keeps running and login still works. Force the verdicts clean anyway
  (`isHookedNative`/`isDebuggerNative`/`isRootedNative` → false, `rootSignals` → 0,
  `getLibraryLoaded` → true) so the BLOCKED path never triggers.
- TLS is plain **OkHttp 5.3.2** (`User-Agent: okhttp/5.3.2`) on top of Conscrypt. There is
  no Cronet, no bundled CA, no `network_security_config`. It honours the global proxy.
- Pinning is okhttp's `CertificatePinner`, relocated to `be.*`; the pins table lives in
  `ej/a.<clinit>` as a `Map<String, List<String>>` for `login-stg`, `api-stg`,
  `accounts-stg`, `gateway-stg`, `gateway.hala.com`, one `sha256/…` per host. The object is
  built by `ij/c.a(...)` and the check method is `be.o.a(String, vc.a)` — **one** overload,
  returns void, so a single no-op implementation disables every pin.

## What that means for a payload

- Trust cannot come from the CA store: the cert-copy module's `/apex/com.android.conscrypt/cacerts`
  is snapshotted per process at fork and never sees files added later (shell and even
  `nsenter -t <pid> -m -- ls` show 126 entries while the app's own `File.exists()` says
  `false` for the same path, and Conscrypt reports "Trust anchor for certification path not
  found"). Bypass in process instead: `TrustManagerImpl.checkTrusted` → return the chain,
  `X509TrustManagerExtensions.checkServerTrusted` → return `arguments[2]`.
- `be.o.a` is the only pin hook needed; `okhttp3.CertificatePinner` never appears (the whole
  okhttp tree is repackaged). AOSP `com.android.okhttp.CertificatePinner` is not on the path
  either — keep it only as a cheap extra.
- Native `X509_verify_cert`/`SSL_get_verify_result` hooks are *not* sufficient on their own
  here: `TrustManagerImpl` still throws at the Java layer.
- The app dies on ~1 attach in 2 while the agent arms (`SIGSEGV` in `EmojiCompatInit` right
  after `deoptimizeEverything`). Retry; it is not a payload defect.
- OkHttp caching + the pre-flight `POST /connect/token` mean the first request often fires
  before hooks are in place if you attach late; arm first, then drive the UI.

## Re-finding the names after a release

```
# pinner: constant map + the class that consumes it
grep -rn 'sha256/' sm*/ | head
# then the method that builds the pinner, and its check method's signature
grep -rn 'Lej/a;->a' sm*/ | grep -v '/ej/'
# guard: native lib and its registration table
strings -a lib/arm64-v8a/libhalaguard.so | head -40
readelf -r lib/arm64-v8a/libhalaguard.so      # .rela.dyn gives name/sig/fn triples
```

The JNI method table sits in `.data.rel.ro`; entries are `(name, sig, fn)` and the addends
in `.rela.dyn` resolve them (e.g. `rc`/`()I`/`0xb84`), so no decompiler is needed to
inventory the natives.

## Working payload shape

`f2/hala_control_ssl_bypass.js` in the Hala workspace: guard verdicts → `TrustManagerImpl`
→ `X509TrustManagerExtensions` → `be.o.a` → hostname verifiers, armed from a
`setTimeout`-driven tick that waits on `Java.available`, with `deoptimizeEverything()` right
after the first arm and one re-arm. ~60 lines, bundled with `frida-compile -c -S`.
