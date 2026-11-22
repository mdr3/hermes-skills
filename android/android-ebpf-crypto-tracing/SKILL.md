---
name: android-ebpf-crypto-tracing
description: "eBPF tracing on rooted Android arm64: syscalls, uprobes, hardware breakpoints, crypto."
metadata:
  category: Android
  short-description: "Android arm64 eBPF tracing: build, attach, verifier and address pitfalls"
---

# eBPF tracing on Android arm64

Use when a task needs runtime evidence from an app on a rooted arm64 device
without frida, target patching or a MITM CA: crypto plaintext/keys, syscall and
file-access behaviour, or hitting one function at a known offset.
Working reference implementation: `~/Desktop/crypto_bpf` (Go + cilium/ebpf).

For syscall-level tracing, hardware execute breakpoints, per-thread arming and
apk-mapped address maths, see `references/syscall-and-hwbp-tracing.md`.

## What only eBPF can see

Native libs commonly perform syscalls through their **own inline `svc` stub**
(`mov x8, x0; ... ; svc #0`) instead of libc. A Frida `Interceptor.attach` on
`openat`/`open`/`__openat` then catches nothing while the kernel sees the calls,
so syscall-level interception has to be eBPF (kprobe on `__arm64_sys_*`) or the
app's own stub. Confirm by disassembling around the caller: a `bl` into a
`mov x8, x0 ... svc` stub means libc hooks are useless there.

## Build rules that are not optional

- **Stay on `GOOS=android` and patch the library, not the GOOS.** cilium/ebpf's
  `platform.IsLinux` is `runtime.GOOS == "linux"`, so under GOOS=android every map
  create dies with `bpf token: not supported on android` before a probe exists.
  `GOOS=linux` is tempting but cgo then compiles Go's *linux* net files against
  bionic headers and fails (`C.socklen_t` vs `C.size_t` in `cgo_resnew.go`). Fix in
  the dependency: `go mod vendor`, then make `IsLinux` also true for android in
  `vendor/github.com/cilium/ebpf/internal/platform/platform.go` and build with
  `-mod=vendor`. Official release binaries hit the same token wall on such a ROM,
  so a fresh build failing there is not evidence your build is broken.
- BPF object: `clang -target bpfel -O2 -g -D__TARGET_ARCH_arm64`. Skip CO-RE and
  vmlinux.h entirely; helpers + a hand-written `struct pt_regs` load on any 5.5+.
- **Keep the output binary arch-pinned and gate it.** `go build ./...` (what
  `hermes verify` runs) rewrites the binary with a **host** build, and the device
  then answers `not executable: 64-bit ELF file` while everything looks fine
  locally. Build only through a Makefile target with `GOARCH=arm64`, and add a
  `check-arch` target asserting `file` says aarch64 before any push.
- Wire the BPF record and the Go struct **in lockstep**: bumping a `MAX_ARGS`
  constant without resizing the Go field decodes past the slice and panics
  (`index out of range`) mid-run — after the tests pass. Assert the record size
  (a `binary.Size` check or a struct-size test) instead of trusting review.
- `char _license[] SEC("license") = "GPL";` or helper calls are rejected as GPL-restricted.

### Cross-building a big Go+eBPF project (ecapture) with the NDK

Recipe that produced a working arm64 binary:

1. libpcap must be **bionic**: the `aarch64-linux-gnu` cross build links glibc symbols
   (`__errno_location`, `__isoc23_sscanf`) that Android cannot resolve. Build it via the project's
   own libpcap target with `make CMD_CC_PREFIX=$NDK/bin/aarch64-linux-android33- CMD_CC=clang ...`
   (a bare `CMD_CLANG=/abs/path/clang` breaks the `.checkver_` target name), and skip `prepare`
   with `make -o prepare` when the host has no matching kernel tree.
2. Bytecode: `bpftool btf dump file <device /sys/kernel/btf/vmlinux> format c > kern/vmlinux.h`, then
   compile the `kern/*.c` with the NDK's `clang -target bpf` and the project's own asset target
   (`PATH=$NDK/bin:$PATH CMD_CLANG=clang CMD_LLC=llc CMD_STRIP=llvm-strip make -o prepare assets`).
   The NDK ships no `llc`, so keep the host one on PATH.
3. Build with the port's android tags (`-tags dynamic,ebpfassets,ecap_android`) and the NDK C
   compiler; the bindata asset file is tagged `arm64 && ecap_android`, so the tag must be present or
   the bytecode is silently not embedded.
4. Put the arm64 `vmlinux.h` in `.gitignore`: it shadows `kern/bpf/x86/vmlinux.h` and breaks host
   `make build` with `no member named 'ax' in 'struct pt_regs'`.

When pairing a capture tool with its GUI/consumer, check the socket direction first: ecapture's
`--eventaddr ws://…` writer and ecaptureQ's `--data-source` are **both** dialers (`client.Dial`), so
nothing listens and the pair needs a relay in between. They also disagree on frame type — the writer
sends rendered text, the consumer expects protobuf `LogEntry` — so a relay that forwards bytes still
shows an empty table until the frames are re-enveloped. Put the listener inside the consumer (loopback,
per-connection token, bounded queue) and transcode text→protobuf there; two separate tools cannot be
made to meet by flags alone. Rigging the phone end (supervisor wrapper, reverse tunnel per spawn,
quoting, manual exports): `references/ecapture-device-rig.md`.

Second wall behind the first: this ROM's module BTF is unparseable (`lookup type name for id …:
offset … is not the beginning of a string` for a kmod) and aborts the whole program load. A missing
module spec only matters if the bytecode references its types, so skip an unparsable module in
`vendor/github.com/cilium/ebpf/linker.go` instead of failing the load.
  GPL-restricted.

## Verifier rules (learned the hard way)

- `bpf_ringbuf_reserve` needs a **constant** size. Use a per-CPU array scratch
  value and `bpf_ringbuf_output(&rb, buf, CONST, 0)`: either a small or a large
  constant (e.g. 1024 / 16384), never a computed size — `total & 0x3fff` alone
  is not enough once the value spills to the stack.
- Bound lengths with **masks** (`len &= 0x1fff`) at the read site, not with `if`
  comparisons earlier in the function; clang sinks/merges compares and the
  verifier loses the range.
- Never `?:` on a length, it drops bounds. Use explicit `if (x) y = 1; else`.
- Syscall-wrapper kprobes: the ctx is the wrapper's only C argument, a pointer
the verifier sees as a scalar. Copy the first regs out with
`bpf_probe_read_kernel(&sr, sizeof(sr), (void *)P1(ctx))` into a 6-word struct
and read args from there; dereferencing `P1(ctx)` directly fails with
`R1 invalid mem access 'scalar'`.
- A program under a made-up section name (`hwbrk/hit`) fails to load with
`program type is unspecified`. Use `perf_event` for hardware-breakpoint
programs, `kprobe/<sym>` and `uprobe/<sym>` otherwise.
- **A dynamic index into the ctx (`ctx->regs[i]`) is refused** with
  `variable ctx access var_off=... disallowed`. The verifier cannot fold a map
  lookup into a ctx offset, so read the slot instead:
  `bpf_probe_read_kernel(&v, 8, (void *)((u64)ctx + idx * 8))`. Same shape works
  for any ctx field whose offset is a config value.

## Syscall evidence without writing a tracer

frida's own `syscall-trace` service is eBPF and out of process; `frida-strace` drives it. Headless
(no TUI, automatic stacks) with the patch `mdr3/frida-strace-headless`:

```bash
frida-strace -H 127.0.0.1:61113 -f <pkg> -i openat -i faccessat -i connect --headless --stack 6 --limit 300 --seconds 30
```

`--json` gives JSONL for grep/jq. Use before blaming a script: it answers which `/proc` file,
`su` path or CA store the app reads without perturbing the process. Startup tells worth knowing:
`faccessat` on `/system/bin/su`, `/system/bin/.su`, `/system/bin/we-need-root`;
`faccessat`/`openat` on `/apex/…/conscrypt/cacerts`; `openat` on `/proc/self/task/<tid>/comm`.
The tracer does not keep the app alive — on a hardened target spawn with the agent, not alone.

## Data correctness on real devices

- **MTE:** Android 16 tags user pointers in the top byte and
  `bpf_probe_read_user` faults on tagged addresses (silently: you get zeros +
  EFAULT). Mask every pointer `p & 0x00ffffffffffffff` before reading.
- Artifacts that tail-branch re-enter the probes (BoringSSL
  `EVP_CipherUpdate -> EVP_EncryptUpdate`) emit duplicates and lose the caller
  (LR = the `[uprobes]` trampoline page `0x7ffffff000`). Keep a per-tid
  `chain`/`done` flag: skip the nested entry, emit output only once.
- `md_len`/`out_len` out-params are sometimes NULL or uninitialised. Trust them
  only up to the block/MD size (16/32/64), otherwise read a fixed cap.

## Choosing a probe point (and keeping it portable)

When the goal is a *class* of calls rather than one known function, the probe
point decides everything. Two rules:

- **Attach at a function entry, never mid-body.** A symbol with a documented
  signature (`ArtMethod::Invoke`-style) has a stable ABI and is the default;
  mid-function instruction signatures are hotter but their register roles drift,
  so the same offset yields real records and garbage in the same run.
- **When the interesting entry is not exported, locate it by instruction
  signature and walk *back* to the prologue.** Scan for the constant part
  (`ldr x9,[x0,#0x10]` = the field load, followed by the indirect call
  `blr x9`), then step back to the nearest 4-aligned `paciasp` (
  `3f 23 03 d5`) — that is where the ABI matches the source signature. On arm64
  that same signature appears in more than one function copy; the first is the
  live one, the second sees almost no traffic, so ship a `--scan` that prints
  candidates and verify in a five-second run.
- Judge a probe point by **resolved-name ratio**, not event count. A point that
  emits 68k records of which 70 % cannot be resolved is worse than one with
  7k at 80 %, and the ratio is the only signal that the register you read is
the right one. Sanity-gate records in the BPF program (a plausible index or
flag range) so garbage never reaches the decoder.
- Keep the register a flag (`--arg-reg`, `--arg-deref`), not a constant: builds
differ in which register holds the object and whether it holds a pointer or a
compressed ref. Reading a compressed ref means a 32-bit load, not 64.

Depth for ART/JNI name resolution (struct offsets, dex tables, uleb prefixes):
`references/art-method-name-resolution.md`.

Rigging the phone end of a capture tool to a host consumer (shim, reverse tunnel,
quoting, manual exports): `references/ecapture-device-rig.md`.

Wire-format contracts when a capture tool has to *export* what it saw (HAR 1.2 with an h2 field
contract, Burp/ZAP/Caido bulk XML, h2→CRLF HTTP/1.1 normalization inside base64, import/replay
assumptions): `references/export-formats.md`.

## Attaching

- A perf breakpoint/PMU probe opened for a pid reaches **only that thread**. Arm
every tid from `/proc/<pid>/task/*` and keep re-arming on a ticker, or worker
their own thread. Arm every thread or the interesting code is never caught: a
single-thread arm shows 0 hits while the site executes thousands of times.
- Attach success is not delivery. After every attach, re-read the bytes/appear
and run the workload: `hwbp`/`uprobe` handles returning nil means nothing if no
event ever arrives, and a silent no-op looks exactly like "the app does not do
this".
- Prefer the perf uprobe PMU (`/sys/bus/event_source/devices/uprobe`, attr
  `Ext1 = path`, `Ext2 = file offset`, config bit from `format/retprobe` for
  return probes). It needs no ELF parse kernel-side, so it works for objects
  mapped out of an APK.
- `format/*` files are `config:0-0`, not bare ints — strip after `:` and before
  `-` or ret probes silently all fail while entry probes keep working.
- Discover by **anchor symbol presence in every executable mapping**, never by
  file name. Model it as families — `{name, anchors[], hooks[]}` — and attach a
  family's hooks only when one of its anchors resolves: `SSL_write` /
  `EVP_CipherInit_ex`, `mbedtls_ssl_write`/`mbedtls_aes_crypt_cbc`,
  `wolfSSL_write`/`wc_AesCbcEncrypt`, `crypto_secretbox_easy`. A name whitelist
  silently misses vendored, renamed and statically linked crypto.
- Hook breadth is what makes coverage real: record layer, `EVP_Cipher*`,
  `EVP_AEAD_CTX_*`, `RSA_*`, `EVP_PKEY_encrypt/decrypt`, digests, HMAC, plus the
  equivalent mbedTLS/wolfSSL/libsodium entries (layouts in
  `references/symbol-families.md`). Args 6-8 exist; a header that stops at five
  forces you to fake a signature.
- Probe the anchors of every mapping on each rescan and report which family
  matched which path — silent non-attachment looks identical to "app uses no
  crypto", so keep a `--debug` path that names the skip reason.
- APK-mapped libraries (`libchrome.so`, `libflutter.so`): parse the ELF through
  `/proc/pid/mem` (ehdr -> phdrs -> PT_DYNAMIC -> dynsym/strtab), translate
  vaddr to file offset via PT_LOAD, then attach with the PMU.

## Attribution (java vs native)

- There is no Java hook. Tag a call `java` when the return address (arm64 x30 at
  entry) falls inside an exec mapping of `libjavacrypto.so`; pass the ranges
  through a per-pid map. Signatures are stripped there, but the module is in the
  Conscrypt APEX, so it is found by basename.

## Known blind spots

- Pure-Java crypto (BouncyCastle) and bespoke C/asm AES: nothing is emitted — a
  family table cannot see them. Say so instead of implying full coverage.
- AndroidKeyStore/KeyMint runs in `keystore2`, so `Cipher` with an
  `AndroidKeyStore` key never reaches the app's libcrypto.
- `libchrome.so` (Chrome/Brave) exports no BoringSSL symbols (1055 dynsyms, all
  imports) — the APK/`/proc/pid/mem` resolver finds the ELF fine, then finds no
  `SSL_write`. Needs eh_frame/`__func__` xref signature scanning.
- QUIC/HTTP3 uses `SSL_provide_quic_data`, not `SSL_write`.
- Kernel-dependent signal control: `bpf_override_return` needs
`CONFIG_BPF_KPROBE_OVERRIDE`, and `fmod_ret` on `__arm64_sys_*` is refused with
`__arm64_sys_tgkill() is not modifiable` on many vendor kernels. Neither works
reliably. When the goal is "keep the app up", use a userspace supervisor
instead: watch the pid, relaunch the component when it disappears, and re-arm
probes for the new pid. Signals can also be frozen from userspace
(SIGSTOP + auto SIGCONT after a short delay) so a debugger can attach to a hit.

## Test workload without building an APK

`javac --release 11` -> `d8 --min-api 30` -> push `classes.dex` ->
`app_process -Djava.class.path=/data/local/tmp/x.dex /system/bin TestCrypto N`
via `setsid nohup` (plain `nohup` dies with the adb shell). Process comm is
`app_process`, so attach by pid, and never run `pkill -f Name` in the same
adb shell that contains the name — it kills its own shell (exit 143).
Drive GCM (`AES/GCM/NoPadding` + `GCMParameterSpec`) and RSA, not just CBC: the
AEAD and public-key paths are where argument layouts and out-params go wrong.

To prove the tool catches a custom implementation, build a fake `.so` with the
NDK that exports the real symbol names (`EVP_CipherInit_ex`, fake
`EVP_CIPHER` struct with nid/key_len/iv_len at +0/+8/+12) under an arbitrary
file name, and a driver that `dlopen`s it. Copying a system/APEX library and
dlopen'ing the copy can SIGBUS on device; a hand-written stub always loads.

## Verify the tool, not just the capture

The capture path only stays trustworthy with automated gates, because the wire
ABI drifts silently (a stale event-type gap renders as a blank name and no test
notices):

- Unit-test the decoder — build synthetic wire records, assert every header
  offset, payload split, truncation and comm field. Add a test that fails when a
  type constant has no display name, so renumbering cannot leave a hole.
- Test host-side helpers (`parseMaps`, symbol table on a real library, PMU
  `format/*` parsing incl. `config:0-0`).
- Host builds must not inherit the ambient `CC`: on an Android workstation it
  points at the NDK clang, which cannot assemble `runtime/cgo` for the host
  (`pushq %rbx` errors). Put build/test in a Makefile with `env -u CC -u CXX`
  and keep `build.sh` a wrapper, or every `go build ./...` gate fails for the
  wrong reason.
- Add a liveness endpoint (`--listen`, `/healthz` + JSON counters) when the
  project is verified with `hermes verify`; without root it must stay up in a
  degraded mode (`"ok": false`) instead of exiting, or readiness polls fail
  against a CLI. Register the mux on `http.Server{Handler: mux}` — omitting
  `Handler` yields a 404 on every path while the process looks healthy.

## Lessons: Android arm64 / kernel 7.x (2026-11)
- `bpf token: not supported on android` on map create is cilium/ebpf treating GOOS=android as non-Linux. Vendor cilium and make android count as Linux; do not set GOOS=linux (cgo bionic headers break).
- `tracing_on` is 0 by default: `trace_pipe` stays empty and tracefs uprobe hit counts read 0 even though probes work. `echo 1 > /sys/kernel/tracing/tracing_on` before believing counts; perf_event uprobes never appear in `uprobe_events`, so absence there proves nothing.
- Prove a target offset fires with a raw tracefs uprobe (`p:x /path/lib.so:0xOFF` + enable) before touching the BPF program.
- `bpf_probe_read_user` with a runtime length fails the verifier (`R2 min value is negative`); read a constant size and clamp afterwards.
- Kernel 7.2 Kali headers dropped `arch/x86/include/asm/compiler.h`: add an empty shim in `.../generated/asm/compiler.h` with `__STATIC_CALL_MOD_ADDRESSABLE` fallback and `-include .../include/generated/autoconf.h` for noncore builds.
- Host cgo tests against Android NDK CC fail on `gcc_amd64.S`; pin child `go build` env to `CC=gcc`/`CGO_ENABLED=1` and filter inherited `CC`, `GOOS`, `GOARCH`.

