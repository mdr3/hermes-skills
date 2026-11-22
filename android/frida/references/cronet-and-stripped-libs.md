# Cronet and other stripped TLS stacks

Cronet (Chromium's stack, shipped as `libhttpengine.so` + `libcrypto_httpengine.so`, plus a JNI
shim) is the case where every Java-level trust hook silently does nothing. This is the escalation
ladder, cheapest first, and how to prove each rung actually did something.

## 0. Measure before patching

Use an untrusted, throwaway CA. With it in place every handshake fails (`Client TLS handshake
failed` in the proxy log) and a patch that works shows up as successful requests. A CA that is
already in the system store proves nothing.

## 1. Ask whether the symbol exists at all

```bash
adb exec-out "su -c 'cat /apex/com.android.tethering/lib64/libcrypto_httpengine.so'" > ce.so
readelf -sW --dyn-syms ce.so | grep -E ' X509_verify_cert| SSL_set_custom_verify| Java_'
```

On a retail Android 16 build: zero. BoringSSL is statically linked, exports are stripped, JNI is
`RegisterNatives`-registered, and even the strings are gone. `findExportByName` therefore returns
null and a name-based "universal" bypass patches only `libssl`/`libcrypto`, which Cronet ignores.

## 2. `enumerateSymbols` / `enumerateSymbolsSync`

Works only when a `.symtab` survived. Try `Process.findModuleByName(...).enumerateSymbols()` and
`Module.enumerateSymbolsSync('libart.so')`; if the list is empty for the target lib, move on.

## 3. Base + offset from a local copy

Pull the exact library from the device, find the function once (`r2 -A`, xrefs to
`SSL_set_custom_verify` callers, or diff against a non-stripped build of the same revision), note
the file offset, and patch `base.add(offset)` at runtime. Bind the offset to the APK/OS build —
libcrypto_httpengine changes between monthly patches.

## 4. RegisterNatives capture (the reliable seam)

The JNI shim must register `android/net/http/X509Util.verify` before any handshake. Hook
registration once and replace the recorded function pointer — no symbols needed.

```js
// find the real RegisterNatives in libart: symbols contain art + JNI, exclude CheckJNI
var rn = null;
Module.enumerateSymbolsSync('libart.so').forEach(function (s) {
  if (/art/.test(s.name) && /JNI/.test(s.name) && /RegisterNatives/.test(s.name) && !/CheckJNI/.test(s.name)) rn = s.address;
});

Interceptor.attach(rn, {
  onEnter: function (a) {
    var cls = Java.vm.tryGetEnv().getClassName(a[1]);
    if (cls.indexOf('X509Util') < 0) return;
    var n = a[3].toInt32(), arr = ptr(a[2]);
    for (var i = 0; i < n; i++) {
      var name = arr.add(i * Process.pointerSize * 3).readPointer().readCString();
      if (name === 'verify') {
        var slot = arr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2);
        slot.writePointer(new NativeCallback(function () {}, 'void', ['pointer','pointer','pointer','pointer','pointer']));
      }
    }
  }
});
```

`X509Util.verify` is `void` and signals failure by throwing, so an empty callback that returns
normally *is* the bypass. Match the arity to the registered signature before trusting it.

## 5. Custom-verify callback replacement (when the setter is reachable)

If `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` resolve (bundled Cronet such as TikTok's
`libsscronet.so`, Flutter's `libflutter.so`), wrap the callback instead of stubbing the chain:

```js
var f = Module.getExportByName(lib.name, 'SSL_CTX_set_custom_verify');
var real = new NativeFunction(f, 'void', ['pointer', 'int', 'pointer']);
Interceptor.replace(real, new NativeCallback(function (ssl, mode, cb) {
  real(ssl, mode, new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']));
}, 'void', ['pointer', 'int', 'pointer']));
```

`0` is `ssl_verify_ok`. For surgical trust, call the original callback and additionally compare
`SSL_get0_peer_certificates` DER against your CA with `CRYPTO_BUFFER_len`/`CRYPTO_BUFFER_data`
(the shape used by `native-tls-hook.js`).

## 6. Fall back honestly

If none of the above lands, the working answer is a CA the app actually trusts (system store) and
no script. Say that out loud instead of shipping a bypass that only prints "armed".

## Proof

- patch applied: read the bytes back (`mov w0,#0; ret` for stubs) or log the replaced pointer
- effect: requests through the untrusted CA start succeeding, and `frida-strace -i connect` shows
  the connections; a run with the patch removed must fail again
