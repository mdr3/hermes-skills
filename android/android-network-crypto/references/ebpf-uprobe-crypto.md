# eBPF uprobe crypto capture on Android arm64

Kernel-side alternative to frida for observing crypto: no injection, no MITM CA, survives anti-frida and RASP checks, and sees plaintext before encryption. Everything below is verified on an arm64 GKI 6.6 device.

## Build

- BPF C: helpers only (no `vmlinux.h`, no CO-RE) so no kernel headers or BTF are needed for compilation; map definitions via `__uint(type, ...)`/`__type(k, v)` macros you define yourself. Emit `char _license[] SEC("license") = "GPL";` — helper calls fail prog load with "GPL-restricted function" otherwise.
- Compile with `clang -target bpfel -O2 -g -D__TARGET_ARCH_arm64`.
- Loader: Go + `github.com/cilium/ebpf`, object embedded with `go:embed`.
- Build the loader with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`, **not** `GOOS=android`: cilium's BPF-token path returns "bpf token: not supported on android" for every map create under GOOS=android. A `CGO_ENABLED=0` Go binary is fully static and runs fine on bionic.
- Never hand-write the loader in C against libbpf for Android — libelf/zlib cross-builds are the time sink, not the probes.

## Verifier constraints

- `bpf_ringbuf_reserve` needs a compile-time constant size. Use a per-CPU array map as a staging buffer (16 KB value) and `bpf_ringbuf_output` with two constant sizes (small/large branch). Userspace reads lengths from the header, never the record size.
- Bound every length with a mask (`len &= MAX - 1`) immediately before the read. `if (x > CONST) x = CONST` gets sunk by the optimizer and the verifier loses the range.
- A `u32` total spilled to the stack and reloaded loses its bound even when masked; keep sizes as `u64` and prefer constant operands at call sites.
- Reads into a per-CPU map value are unbounded-checked the same way as ring writes: mask, then read.

## Android 16 MTE: untag every user pointer

Pointers arrive with an MTE tag in the top byte (`0xb400007d...`). `bpf_probe_read_user` faults on them and the event renders as zeros plus a truncation flag, while reads of the untagged form through `/proc/pid/mem` succeed — that asymmetry is the diagnosis. Strip the tag first:

```c
static __always_inline u64 untag(u64 p) { return p & 0x00ffffffffffffffULL; }
```

Apply to every pointer before reading and before storing it in a state map. Do not assume a failed read means the buffer is invalid.

## Wire format

One header struct shared by C and the Go decoder, followed by key, IV, then data. A wrong header size shifts every field: the symptom of a 64 vs 80-byte header was comm printed as garbage and payloads starting 16 bytes early. Check field-by-field offsets against the C struct before trusting any capture.

## Tail calls duplicate probes

`EVP_CipherUpdate` ends in `b EVP_EncryptUpdate`, so an uprobe on both fires twice for one call and the second entry's LR is the uprobe trampoline `0x7ffffff000`, not the caller. Keep `chain`/`done` flags in the per-tid state map: the inner entry only refreshes the out/outl pointers, the first return emits and clears, the second return is skipped. Anything that reports the caller for return probes must use a caller saved at entry, not `PT_CALLER(ctx)` at return.

## Java attribution

Read the `libjavacrypto.so` executable mapping range from `/proc/pid/maps`, hand it to the BPF program in a pid-keyed map, and compare the entry LR against it. JNI functions in `libjavacrypto.so` are static (only ~556 dynsym entries, none named `NativeCrypto_*`), so `RegisterNatives`-based name hooking does not work.

## Attach paths

- APEX/normal `.so`: `link.OpenExecutable(path)` then `ex.Uprobe(sym, prog, &link.UprobeOptions{PID: pid})` per pid, one link per symbol, resolved from the target's own maps.
- Objects mapped out of an APK (`libchrome.so`, `libflutter.so`, path ends in `base.apk`): `OpenExecutable` fails with "bad magic number" because a zip is not an ELF. Parse the ELF through `/proc/<pid>/mem` (program headers → `PT_DYNAMIC` → `DT_SYMTAB`/`DT_STRTAB`, translate vaddr→file offset) and attach with the perf uprobe PMU: `perf_event_open` with `attr.Type` from `/sys/bus/event_source/devices/uprobe/type`, `Ext1` = pointer to a NUL-terminated path you keep alive, `Ext2` = file offset, `Config` = retprobe bit, then `PERF_EVENT_IOC_SET_BPF` and `_ENABLE`.
- Read symbol tables across multiple mappings: a 16 MB string table spans several, so loop per mapping instead of requiring one to cover the range.
- Only report per-library attach errors when that library attached nothing; partial symbol sets are normal.

## Symbol availability decides everything

Check first: `readelf -sW <lib> | grep ' SSL_write$'`. Conscrypt APEX `libssl.so`/`libcrypto.so` export the functions. Chromium's `libchrome.so` is stripped to ~1055 dynsyms that are imports only — `SSL_write` and `EVP_*` resolve to nothing and neither `adrp`+`add` xrefs to the `__func__` strings nor `.gnu_debugdata` exist there. Do not promise capture on Chromium-based browsers without checking; fall back to apps that link real `libssl.so`.

BoringSSL struct offsets used for key length and algorithm id: `EVP_CIPHER` has nid@0, key_len@8, iv_len@0xc. Confirm against the target binary by disassembling `EVP_CIPHER_nid`/`_key_length`/`_iv_length` instead of trusting headers. Turn the nid into a name with a table lifted from the library's own OBJ table (name ptrs at -0x10/-0x8 before a `0x9_0000_0000|nid` word).

## Throwaway java workload without building an APK

```bash
javac --release 11 -d cls TestCrypto.java
d8 --release --min-api 30 --output . cls/*.class
adb push classes.dex /data/local/tmp/TestCrypto.dex
adb shell '(setsid nohup app_process -Djava.class.path=/data/local/tmp/TestCrypto.dex /system/bin TestCrypto 400 >/tmp/o 2>&1 &)'
```

`javax.crypto`/`MessageDigest`/`Mac`/`HttpsURLConnection` in that process go through Conscrypt → `libjavacrypto.so` → `libcrypto.so`, so it exercises the java path and real TLS. The process comm is `app_process`/`main`, so attach by pid, not by name.

## adb shell gotcha

`adb shell 'pkill -f TestCrypto ...'` kills its own shell — the pattern is in the shell's own cmdline, so the command dies with exit 143. Run `pkill` in a separate adb call, or match `app_process.*Name`, and launch long-running workloads with `setsid nohup`.

## Output

Report algorithm (via nid), key, IV, direction, length, caller and hex + printable payload; JSONL as an option. Cap payload bytes and flag truncation so a big `SSL_read` cannot stall the ring. Verify with the java workload end to end: java tag present on JCE calls, HTTPS response plaintext captured, no duplicate events per call.
