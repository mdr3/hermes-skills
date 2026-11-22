# Frida-Toolkit catalogue (selection map)

Source: https://github.com/Ishanoshada/Frida-Toolkit — ~640 scripts, 18 categories, Android + iOS.
Vendor a copy into the lab (`git clone --depth 1`) rather than pasting from the web page; script
bodies are what you need.

## What to reach for

| Target behaviour | Category | Notes |
|-|-|-|
| TLS pinning / verify refusal | `Bypass-SSL-Certificate-Pinning` | 140 scripts; start with the universal one, then narrow to the pinner actually in use |
| `su`, Magisk, mount, SELinux probes | `Bypass-Root-Jailbreak-Detection` | pairs with `cpp/root_check.c` |
| `TracerPid`, ptrace, debug flags | `Bypass-Anti-Debug-Protections` | |
| `/proc/self/maps`, fd symlinks, PLT origin | `cpp/bypass_maps_scan.js`, `bypass_fd_scan.js`, `bypass_plt_check.js` | the best teaching pairs in the repo |
| Java method tracing | `Hook-Java-Methods` | generic templates only; app classes still need your own targeting |
| JNI/native boundary | `Hook-Native-Functions` | |
| Crypto visibility | `Intercept-Crypto-Operations` | input/output of AES/RSA helpers |
| Traffic visibility | `Intercept-Network-Traffic` | okhttp interceptors etc. |

## The `cpp/` pairs worth reading

Each detector file states exactly which syscall it survives on; the matching `bypass_*.js` hooks
that seam. Read the pair, then hook the seam in *your* target:

| Detector | Seam |
|-|-|
| `root_check.c` | `openat` + `__system_property_get` + `strstr` |
| `frida_detect.c` | `dlsym` symbol hiding + `fopen` on `/proc` |
| `maps_scan.c` | `openat` + `fgets`, scrub needle lines |
| `mount_check.c` | `openat` + `fgets`, drop magisk/conscrypt tmpfs lines |
| `fd_scan.c` | `openat` + `readlinkat` |
| `plt_check.c` | `dlsym` + `dladdr`, forge a system module name |
| `build_native.c` | `__system_property_get`, return clean props |
| `device_trust_native.cpp` | combination of the above |

`cpp/master-unified-hooks.js` aggregates 130+ of them into one file — convenient for a first
pass, unhelpful when you need to bisect. It also assumes a working Java bridge, which hardened
ART builds do not always survive.

## Anti-patterns seen in the wild

- Running a whole category at once, then reporting "bypass works" without a live request.
- Trusting `Interceptor.replace` on targets whose agent pages are non-executable.
- Assuming `findExportByName` succeeds: stripped Cronet (`libcrypto_httpengine.so`) exports no
  `X509*`/`SSL*` symbols, so name-based TLS patches land on unused system copies.
- Using Frida's Java bridge on a target that aborts in `ResetQuickAllocEntryPoints` — ship the
  native-only agent first, add Java only after the process is stable.
