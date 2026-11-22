---
name: deobfuscation-unpacking
description: "Recover obscured native code and data with control-flow analysis, string/constant recovery, VM analysis, staged unpacking, and evidence-preserving reconstruction."
metadata:
  category: Binary
  short-description: "Recover obscured native code and data with control-flow analysis, string/constant recovery, VM analysis, staged unpacking, and evidence-pres"
---

# Deobfuscation and Unpacking

Use this for authorized analysis of packed, virtualized, encrypted, or control-flow-obfuscated binaries. Preserve the original sample, every intermediate stage, hashes, mappings, and the operation that produced each stage.

## Diagnose the mechanism

Look for high entropy, sparse imports, a small decryptor stub, writable-executable transitions, self-modifying code, runtime-generated API resolution, encrypted resources, unusual section names, VM dispatch loops, opaque predicates, and dead-code floods. A high-entropy `data` section may also be a legitimate model or resource.

## Stage recovery

Break after the unpacker has written and protected memory, then dump the reconstructed image with correct base, permissions, and mapped pages. Capture the original entrypoint, OEP, import fixes, and any runtime configuration. Dump only after the code is stable; an early snapshot can contain partial decryption.

## Static reconstruction

Use emulation/debugger traces to resolve decryptors, then rebuild control flow. For VM obfuscation, identify the dispatcher, opcode fetch, handler table, virtual register file, and semantics. For opaque predicates, prove a branch is invariant from dataflow, not just appearance.

## Safe execution

Unknown code runs only in a disposable VM with network isolation and snapshots. Never detonate a sample on the host. Do not paste recovered secondary payloads into a normal working directory; store them under a quarantined lab path.

## Verification

Rebuild a minimal input and observe the same behavior from the original and reconstructed stages. Report any incomplete code/imports/data. "Dumped successfully" does not mean "fully unpacked."

## Sources

- capa capability analysis: https://github.com/mandiant/capa
- Frida: https://frida.re/docs/home/
- QEMU: https://www.qemu.org/docs/master/
- Unicorn: https://github.com/unicorn-engine/unicorn

## Lessons: symbols for stripped Android libs (2026-11)
- `.gnu_debugdata` is an xz-compressed ELF with a mini .symtab; `llvm-objcopy --dump-section .gnu_debugdata=...` then `xz -d`. Android 16 Cronet keeps only FIPS crypto symbols there, but that is enough to bootstrap names.
- To make eBPF/ecapture resolve a mangled function: `llvm-objcopy --add-symbol name=.text:off,function,global` writes it to .symtab only — and you must patch `st_size` afterwards (0-size symbols fail attach validation). file offset == VA for these libs.
- BoringSecretHunter-style voting (count ADRP+ADD label strings passed as arg) finds `ssl_log_secret` in minutes: friTap ships `dev/find_ssl_log_secret_offset.py`.
- A bind-mounted "patched lib" is useless until the process actually maps that inode: bind in the zygote mount namespace and restart zygote.
- `make format`/clang-format noise obscures real diffs; commit kernel edits separately from generated/format churn.

