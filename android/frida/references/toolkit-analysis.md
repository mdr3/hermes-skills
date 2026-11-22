# Toolkit survey — all 18 categories, all 653 scripts

Full walk of `Ishanoshada/Frida-Toolkit` (cloned at `/tmp/ftk`, 8.6 MB). Numbers are script
counts per category; "techniques" are what the bodies actually use, not what the folder claims.

| # | Category | Techniques present | Verdict |
|-|-|-|-|
| 140 | `Bypass-SSL-Certificate-Pinning` | 101 Java trust/`registerClass`, 50 `CertificatePinner`, 38 `NativeCallback`, 33 iOS, 32 TrustKit, 26 Flutter; only **6** touch the BoringSSL custom-verify seam | Use ~5 of them; the rest are app-specific Java stubs |
| 113 | `Bypass-Root-Jailbreak-Detection` | 70 Java, 39 export lookups, 13 `NativeFunction`, 4 ptrace; almost all `su`/Magisk path lists | Good breadth, shallow each; crib the path lists |
| 97 | `Hook-Java-Methods` | 96 `Java.use` templates | Near-duplicates, one per pattern; pick one and adapt |
| 72 | `Specialized-App-Bypasses` | per-app mixes, 20 Java, 12 iOS, 6 pinner | Only useful if your app is listed |
| 40 | `Intercept-Network-Traffic` | 31 Java okhttp/interceptors | Logging, not bypass |
| 37 | `Intercept-Crypto-Operations` | 23 Java cipher hooks, 1 `enumerateSymbols` | `findlibcryptofunctions.js` is the only native one |
| 30 | `iOS-Specific-Hooks` | ObjC/NSURLSession, 5 `NativeCallback` | iOS only |
| 24 | `Bypass-Anti-Debug-Protections` | ptrace/TracerPid/props, 1 Stalker | Fine, small |
| 17 | `cpp` | 15 `Interceptor.replace` + `NativeCallback`, 10 openat/`fgets` scrub, 4 `getdents64`, 3 `dlsym`+`dladdr` | **Best material in the repo**: each detector + bypass pair teaches one seam |
| 13 | `Bypass-Biometric-Authentication` | Java BiometricPrompt stubs | Narrow |
| 12 | `Hook-Native-Functions` | 4 `enumerateSymbols`, 4 replace, 3 `dlopen` | Holds `registernativesdump.js` and `jnitrace.js` — the two worth reading |
| 12 | `File-System-Access` | Java + native file hooks | Utility |
| 12 | `Enumerate-Classes-Methods` | `enumerateLoadedClasses`, iOS variants | Utility |
| 10 | `Memory-Operations` | 1 `Memory.scan`, hooks | Dump-oriented, not bypass |
| 8 | `Testing-Templates` | 6 unique names for 8 files | Skeleton only |
| 6 | `Spoof-Device-Properties` | props/IMEI | Utility |
| 4 | `Dynamic-Loading` | 1 custom_verify, 1 `Memory.scan` | Thin |
| 3 | `WebView-Manipulation` | iOS-only | Misnamed |
| 3 | `Linux-Native-Tools` | no Frida API hits (shell/notes) | Not scripts |

## Scripts that actually matter for a native TLS stack

| File | What it does | Take |
|-|-|-|
| `Bypass-SSL-Certificate-Pinning/native-tls-hook.js` | replaces `SSL_set_custom_verify`/`SSL_CTX_set_custom_verify`, wraps the supplied callback, returns `SSL_VERIFY_OK`; optional DER compare via `SSL_get0_peer_certificates` + `CRYPTO_BUFFER_*` | the canonical Cronet technique |
| `Bypass-SSL-Certificate-Pinning/tiktok-ssl-pinning-bypass.js`, `tiktokssl.js`, `snapchat-ssl.js`, `ovo-bypass-ssl-pinning.js`, `pollo.js` | same seam, `Interceptor.attach` on the setter and `retval.replace(0)` on the callback | shorter variant of the above |
| `Hook-Native-Functions/registernativesdump.js` | finds `JNI RegisterNatives` in libart via `Module.enumerateSymbolsSync`, walks `JNINativeMethod[]` (name/sig/fnPtr, stride `pointerSize*3`) | the way in when a lib exports no JNI symbols |
| `Intercept-Crypto-Operations/findlibcryptofunctions.js` | enumerates crypto exports by regex | quick inventory, no bypass |

`cpp/` pairs (all 17) are a detector→seam map: `root_check.c`→openat/props, `maps_scan.c`→openat+fgets,
`fd_scan.c`→openat+readlinkat, `plt_check.c`→dlsym+dladdr, `mount_check.c`→openat+fgets,
`build_native.c`→props, `device_trust_native.cpp`→all of them.

## Quality caveats (measured, not guessed)

- Median script is ~2 KB and many are one-pattern templates with the class name swapped; there are
  131 unique file names for 140 SSL scripts and 96 for 97 Java-hook scripts.
- Several SSL scripts assume Frida's **Java bridge** works. On hardened ART builds it does not, so a
  Java-only script "arms" and then the process aborts in `ResetQuickAllocEntryPoints`.
- Most are `Interceptor.replace`-based. On targets whose agent trampolines are non-executable that
  faults; body patches or `Interceptor.attach` + `retval.replace` survive.
- Only the six custom-verify scripts are written for Cronet; everything else is Conscrypt/okhttp
  Java-level and will never fire on a Cronet app.
- No script locates a function in a **stripped** library. `native-tls-hook.js` starts from
  `getExportByName` and prints "no verification methods found" otherwise — see
  `cronet-and-stripped-libs.md` for the ladder that handles that case.
