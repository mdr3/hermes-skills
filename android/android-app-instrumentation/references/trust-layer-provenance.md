# Proving which layer decides trust

Before unpinning anything, establish *who* verifies. Guessing costs hours: a
native sweep on a Conscrypt app, or Java hooks on a Cronet app, both look
"armed" and change nothing. The evidence is cheap and unambiguous.

## 1. Ask the kernel, not the source

Trace only the anchor path and the handshake:

```
frida-strace -H 127.0.0.1:PORT -p <pid> --limit 40000 \
  -i openat -i openat2 -i newfstatat -i statx -i faccessat -i faccessat2 \
  -i getdents64 -i read -i pread64 -i close -i sendto -i sendmsg
```

Whitelist, never blacklist: with no `-i` the `/proc/self/task/*/comm` RASP sweep
eats the whole event budget. Keep the capture to one handshake and stop at the
first failure.

What the sequence means:

- `faccessat /apex/com.android.conscrypt/cacerts/<hash>.0` — the platform store is
the trust source, and `<hash>` is the alias it wants (MD5 `subject_hash_old` of
the issuer). A following `openat` of the same file means the anchor loaded.
- `faccessat` succeeded but **no `openat`** — the anchor was found and rejected
  later (pin, key pin, hostname), not missing.
- `faccessat` returns `-2` (ENOENT) on a file that exists when you `cat` it — see
  the store-layering section; the lookup never reaches your certificate.
- `/data/misc/keychain/pubkey_blacklist.txt`, `pubkey_sha256_blocklist.txt`,
  `serial_blacklist.txt` right before the handshake — `TrustManagerImpl` init, so
  the Java/Conscrypt path is in use.
- Nothing under any `cacerts` path at all, while handshakes happen — bundled
  anchors (`.bks`/`.p12` in assets, a vendor manager), so store edits cannot help.
- `sendto` of a 30-byte record right after the probe is the alert. Payload byte 1
  names the reason: `2e` certificate_unknown, `30` unknown_ca, `02`
  bad_certificate, `28` hostname mismatch. mitm's own log line already says which
  ("Client TLS handshake failed … (OpenSSL Error … alert certificate unknown)") —
  read it before inventing a theory.

## 2. Rule out Cronet quickly

A mapped `/apex/com.android.tethering/lib64/libhttpengine.so` or
`libcrypto_httpengine.so` only means the library is loaded, not that the app
verifies through it. Cronet's classes (`X509Util.verifyServerCertificates`,
`AndroidCertVerifyResult`) never firing in a Java trace, plus
`getdents64`/`getdents`-free store access, means the traffic is plain Conscrypt.
Both `libhttpengine.so` and `libcrypto_httpengine.so` are stripped of `X509_*`
symbols, so a native symbol sweep finds nothing there.

## 3. See the Java verify path at all (eBPF, no Frida)

Java-layer tracing on ART needs `ExecuteNterpImpl` (x0 = `ArtMethod*`) — the
interpreter used for anything without compiled code, which includes boot-image
classes like `TrustManagerImpl` and `RootTrustManager`. `DoCall` alone only sees
interpreted code and misses them entirely.

- Locate `ExecuteNterpImpl` by dynsym, then by its prologue signature when the
  symbol is stripped (it usually is); `-Xint` is the last resort and puts the
  whole system in the interpreter — PackageManager then needs ~2 minutes to
  resolve activities again after the zygote restart.
- On nterp entry the argument vregs live in the caller's `ShadowFrame` (x2);
  slot 0 is `this` for instance methods. A `jvalue` slot is 8 bytes wide, but a
  `jobject` payload is a 32-bit heap reference — read the slot as 64 bit and
  un-compress only the low half, otherwise pointers come back as half a value.
- `X509Certificate.getEncoded/hashCode/getPublicKey` firing in bulk with
  `CertBlocklistImpl.isPublicKeyBlockListed` is the platform **blocklist**, not
  app pinning. Do not read it as a pin check.

## 4. Pinning provided by DI over a database

A pinner built as `provideCertificatePinner(PublicKeysDao)` means the pins are
rows, not literals: no `sha256/…` string exists in the APK or the trace, and a
Room database under `databases/` is often encrypted (grep for a table name finds
nothing). Do not conclude "no pins" from a missing string.

The discriminator is whether the pin check *runs*: `okhttp3.CertificatePinner.check`
appearing means pins exist for that host; only `<clinit>`, the DI factory and
repeated `CertificatePinner.hashCode()` (connection-pool keying) mean the traffic
never went through the pinned client. Hook `check` and
`CertificatePinner$Builder.add` to see the pinned hosts as they are added.

## 5. Store layering on Android 14+ — why a correct CA still ENOENTs

`/apex/com.android.conscrypt/cacerts` is EROFS. A CA module built on the
`CustomCACert` pattern mounts a **tmpfs** over it at `post-fs-data`, copies the
real store plus its own certs in, `chcon`s to the target's context and binds it
into `init`'s namespace so zygote children inherit it. Consequences that cost
hours:

- Writing a DER into the EROFS apex dir, or `mount --bind /apex/… /system/etc/security/cacerts`
  from a shell, is invisible to already-running and later-forked app processes.
  The app then probes the alias and gets `ENOENT` while `ls`/`cat` from the shell
  shows the file.
- The bind has to be applied through `su -c 'nsenter -t 1 -m -- mount --bind …'`
  plus a zygote restart, or left entirely to the module.
- Prove what the app sees from its own namespace, not the shell's:
  `su -c 'nsenter -t <app-pid> -m -- ls -l /apex/com.android.conscrypt/cacerts/<hash>.0'`
  and `… ls | wc -l`. A count that differs from the shell view is the bug.
- If a CA module owns the store, disable *your* extra binds rather than the
  module — its merged tree is the one that carries the correct label
  (`system_security_cacerts_file`) and the module's own copy of your CA.
- `faccessat(AT_FDCWD, path, F_OK)` returning ENOENT for a path that resolves from
  the app's namespace is still possible under heavy multi-module setups; fall
  back to a native `faccessat`/`openat` hook that answers 0 for the alias rather
  than debugging the mount further.
