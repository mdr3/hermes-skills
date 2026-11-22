# Static path: patching the APK, and injecting Java without an agent

Use when the agent cannot stay alive, or when the user wants a patched artifact
rather than a live session. The smali edit is the easy half; the signer and the
runtime are what decide whether the result runs.

## Before you edit anything

Record the attribution control first — it costs one install and saves a wrong
conclusion later:

1. install the app's own APK untouched, launch, confirm it stays up
   (`adb shell pidof <pkg>`, `dumpsys window | grep mCurrentFocus`);
2. sign a byte-identical copy with your key, install, launch, count crashes
   (`adb logcat -b crash -d | wc -l`).

If both crash the same way, the edit is not the variable. Read the tombstone
(`adb shell su -c 'ls -t /data/tombstones | head -1'`) and the abort message
before touching smali — on this runtime a re-signed APK aborts in
`art::ResetQuickAllocEntryPoints` because the RASP turns on entrypoint
instrumentation as its tamper response.

## Repack

Decode once (`apktool d -r` style tree), patch only the smali you need, and
reassemble only the dex that contains it — a full `apktool b` of a 200 MB,
16-dex app is slow and drags the resource pipeline in:

```
smali assemble smali_classes6 -o /tmp/classes6.dex        # smali_classesN -> classesN.dex
python3 scripts/apk_repack.py app.apk classes6.dex=/tmp/classes6.dex -o out.apk
zipalign -f -p 4 out.apk out.a.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
    --key-pass pass:android --min-sdk-version <pkg minSdk> out.a.apk
apksigner verify --print-certs out.a.apk ; zipalign -c -p 4 out.a.apk
aapt dump badging out.a.apk | head -2     # package/version must be unchanged
```

Verify the patch landed by disassembling the new dex
(`baksmali disassemble /tmp/classes6.dex -o /tmp/chk` and read the method), not
by trusting the assembler's exit code.

`extractNativeLibs=false` (the modern default) requires `.so` entries STORED and
page-aligned; `resources.arsc` STORED too. Drop stale `META-INF/*.SF|*.RSA|*.MF`
and any `stamp-cert-sha256` before signing. Report the delivered file's
`sha256sum`.

## Keeping the original signer

Install-time signature checks are the easy part (CorePatch
`bypass_verification`/`bypass_exact_sig_match`/`use_previous_signatures` are
global booleans, all true by default). In-app checks are the hard part: they
compare the running signer, and a mismatch is what arms the tamper path.

- Scope the spoofing module to the package and fake the original certificate:
  `adb shell su -c 'dumpsys package <pkg> | grep -A2 signatures'` on an
  untouched install records the live signature; the certificate itself comes
  from the APK (`unzip -p app.apk META-INF/*.RSA` then
  `openssl pkcs7 -inform DER -print_certs`). Hand the owner its sha256 and the
  DER/PEM so it can be configured.
- `use_previous_signatures` only helps if the module was already scoped while
  the original was installed; otherwise there is no record to fall back on.
- Deliver the unsigned variant when asked for one, but say that an APK must
  still carry some signature block to install.

## Xposed module without Gradle

An LSPosed/Vector module is an APK with `xposedmodule` meta-data; it does not
need Android Studio. `javac --release 8` against `platforms/<api>/android.jar`
plus tiny stubs of `IXposedHookLoadPackage`/`XC_MethodHook`/`XposedBridge`
(`-d` then `jar cf api.jar -C out .`) is enough to compile, then `d8`, then
package. `aapt2` may refuse the platform jar (`RES_TABLE_TYPE_TYPE entry offsets
overlap actual entry data` on API 36's sparse table) — when it does, repackage
an installed module instead of fighting resources:

```
adb pull "$(adb shell pm path <module-pkg> | sed 's/package://')" base.apk
zip -d m.apk 'classes*.dex' ; zip -j m.apk out/classes.dex
zip -d m.apk assets/xposed_init ; zip m.apk assets/xposed_init   # entry class
zipalign -f -p 4 m.apk m2.apk && apksigner sign ... m2.apk
adb uninstall <module-pkg> && adb install -r m2.apk
```

Signature differs from the original module, so uninstall first. Keep the
original `assets/xposed_init` deleted, not shadowed: a duplicate zip entry
leaves the old entry class loading.

There is no manager UI on a bare Vector/LSPosed install — enable and scope by
editing `/data/adb/lspd/config/modules_config.db` on the host (`sqlite3` is
usually absent on device):

- `modules(mid, module_pkg_name, apk_path, enabled, auto_include)` — set
  `enabled=1` and fix `apk_path` after any reinstall;
- `scope(mid, app_pkg_name, user_id)` — add `(mid, '<pkg>', 0)`; note the column
  is `app_pkg_name`, not `target_pkg_name`.

Push the db back, delete `-wal`/`-shm`, then `setprop ctl.restart zygote`, then
verify injection in logcat (`VectorZygiskBridge: onTransact … callerUid=<app uid>`).

Hook timing matters: install hooks from `Instrumentation.callApplicationOnCreate`
(`afterHookedMethod`) rather than in `handleLoadPackage`, so the app's own early
checks finish before the TLS surfaces change.

## Static-analysis tool quirks

- `eBPFDexDumper dumpso` reports `0 candidate module(s)` for an app whose libs
  are mapped from the split APK (`split_config.*.apk!/lib/…` with
  `extractNativeLibs=false`) — the candidates are filtered by filesystem path.
  Use the `.so` from the APK when the point is static analysis.
- Qiling 1.4.x: `ql.arch.regs.write(...)` (there is no `ql.reg`) and
  `ql.mem.map(addr, size, info=...)` (no `map_any`).
- Finding an emulation target in an OLLVM library: an unrolled byte-XOR string
  decryptor shows up as `ldrb`/`eor`/`strb` runs with a single key register;
  locate it by scanning for that trio plus the literal `mov w<n>, #0x14`-style
  key/length constants, then resolve call sites for the real arguments (direct
  `bl` callers may be absent if the routine is reached by tail branch).
