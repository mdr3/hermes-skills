# Building eBPF tracers for arm64 Android

These are kernel-side and invisible to an app's own procfs scanning, which is why
they still work once Frida hooks get you killed. Build them on the host, push the
binary, run as root.

## BPFroid (tracee fork with Java-API uprobes)

Repo ships a minimal hand-written `3rdparty/include/vmlinux.h` — **keep it**.
Regenerating it from the device BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux
format c`) redefines `struct context`, which collides with tracee's own typedef and
breaks the build with "redefinition of 'context'".

`vmlinux.h` is not enough on its own: the BPF object needs a shim header for the
kernel macros it does not carry (`PAGE_SIZE`, `VM_EXEC`, `VM_WRITE`, `AF_UNIX`,
`AF_INET`, `AF_INET6`, `ULLONG_MAX`, `_TIF_32BIT`) passed with `-include`.

```
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -D__ANDROID__ \
  -DCONFIG_ARCH_HAS_SYSCALL_WRAPPER -include /tmp/shim.h \
  -I 3rdparty/include -I 3rdparty/libbpf/src -c tracee/tracee.bpf.c -o out.bpf.o
```

libbpf must be built for android against the **elfutils/zlib that libbpf-sys
produced for `aarch64-linux-android`** (find them under
`target/aarch64-linux-android/*/build/libbpf-sys-*/out/`), with `CFLAGS` pointing
at that elfutils tree.

**The link trap:** `libbpfgo` hardcodes `-lelf -lz`, and `-lelf` resolves to the
host's x86_64 `/usr/lib/.../libelf.so`, so the binary records `NEEDED libelf.so.1`
and dies on device with `library "libelf.so.1" not found`. Make a directory with
`libelf.so`/`libz.so` symlinked to the static `.a` files and put it first on the
link line — the NEEDED entry disappears because the archives are consumed.

Go build (note the extra `-I` for the `bpf/*.h` includes libbpfgo wants; libbpf's
headers live flat in `src/`, so copy them into `include/bpf/`):

```
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=$NDK/aarch64-linux-android29-clang \
  CGO_CFLAGS="-I$PWD/3rdparty/libbpf/include -I$PWD/3rdparty/libbpf/src -I$ELFUTILS/lib" \
  CGO_LDFLAGS="-L/tmp/elfshim /tmp/libbpf_android/libbpf.a" go build -o bpfroid .
```

The binary embeds the BPF object from `bpf_bundle_injected.go`
(`func init() { bpfBytesInjected = \`<base64>\` }`) and reads `hooks.json` from
the **same directory as the executable** — push both.

Run with a trace expression, not a flag: `./bpfroid -t 'pid=<pid>'`. It needs root
and prints events as a table (`TIME UID COMM PID TID RET EVENT ARGS`).

## stackplz

Both ports build and trace, and produce symbolised stacks for a native `.so`:

- Rust port: needs NDK r27 (API 29) and `--features embedded_bpf`; the `linux`
  cfg gates must be widened to `any(linux, android)`, `libbpf-sys` needs
  `vendored-libelf` + `vendored-zlib`, and its build.rs triplet must be patched to
  `aarch64-linux-android`. Pass `CONFIG_SITE=/tmp/config.site` so autotools
  cross-configures. Pass offsets in **decimal**, not hex.
- Go upstream: `bash build_env.sh`, then
  `make ebpf_stack ebpf_syscall ebpf_perf_mmap && make genbtf && make assets && make build`.

Both need the device's own kernel config/BTF pulled first
(`/proc/config.gz`, `/sys/kernel/btf/vmlinux`); a mismatched header set builds fine
and fails at load.
