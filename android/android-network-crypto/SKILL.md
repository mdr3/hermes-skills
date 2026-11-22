---
name: android-network-crypto
description: "Analyze Android TLS, certificate validation, pinning, crypto boundaries, request signing, tokens, and local network protocol evidence in an authorized lab."
metadata:
  category: Android
  short-description: "Analyze Android TLS, certificate validation, pinning, crypto boundaries, request signing, tokens, and local network protocol evidence in an "
---

# Android Network and Crypto

Use this to explain how an Android app constructs, protects, or validates a request. Capture only authorized traffic and avoid replaying mutations against production or third-party systems.

## When to Use

- Mapping how a request is built, signed, encrypted, or validated.
- The app resists frida/RASP and needs kernel-side observation instead of injection.
- You need keys, IVs, algorithms, or pre-encryption plaintext, not just ciphertext on the wire.


## Static first

Search for network stacks, URL construction, interceptors, protobuf/MessagePack codecs, nonce/timestamp logic, signing helpers, and key material. Check the network security config and any custom trust manager. Treat hard-coded secrets as findings, not as proof that a server accepts a forged client.

## Observe the trust boundary

Prefer hooking the app's request builder/signer over globally disabling TLS validation. If a controlled proxy is required, install a test CA only in the isolated lab and document that mutation. For pinning investigation, identify the exact verifier and inputs rather than applying a broad universal bypass.

For each request record method, path shape, content type, body encoding, nonce/timestamp fields, signer inputs, signer output, header placement, and session state. Redact real credentials and unrelated personal data.

## Installing a CA into the system store

The APEX store (`/apex/com.android.conscrypt/cacerts`) is read-only and `remount` is refused on many
builds, so trust goes into `/system/etc/security/cacerts`, which CA modules replace with a tmpfs in
`post-fs-data`. Those modules bind each of their own cert files read-only over the target, so the
module directory is the source of truth and the mounted copy answers `Device or resource busy` to
`rm`/`cp`: `umount <path>` first and delete, or edit the module directory and reboot. Filenames use
the **old** subject hash (`openssl x509 -subject_hash_old`), but proxy apps commonly probe the
**new** hash (`-subject_hash`) to decide whether to show "installed as system" — install the cert
under both names or the app keeps reporting it missing while trust is actually fine. The user store
(`/data/misc/user/0/cacerts-added`) only feeds the user list and is ignored by targetSdk >= 24;
put the system copy in the module directory, keep the user copy only to satisfy in-app indicators,
and remember that disabling the module removes every cert it carries.

## Kernel-level capture (eBPF uprobes)

When frida is detected, the app is unpacked/obfuscated, or you need pre-encryption plaintext plus key material, hook the crypto library from the kernel instead of injecting. Uprobes on `SSL_write`/`SSL_read` give TLS plaintext and uprobes on `EVP_CipherInit_ex`/`EVP_CipherUpdate`/`EVP_Digest*`/`HMAC_*` give keys, IVs, algorithms and cipher input/output. Tag calls whose return address falls inside `libjavacrypto.so` as java-level: Conscrypt's JNI symbols are not exported, so the JNI entry points cannot be hooked by name.

Before promising capture on a target, check the symbol table of the exact library it maps (`readelf -sW`): the Conscrypt APEX libs export `SSL_*`/`EVP_*`, Chromium's `libchrome.so` is stripped and resolves nothing by name.

Root plus a kernel with `CONFIG_UPROBES`/BPF is required; verify with `/sys/kernel/btf/vmlinux`, `zcat /proc/config.gz | grep UPROBE`, and `ls /sys/kernel/tracing/uprobe_events` before building anything.

Build procedure, wire format, verifier constraints, MTE pointer handling, tail-call de-duplication and the APK/APEX attach paths are in `references/ebpf-uprobe-crypto.md`.

## Crypto review

Map cipher, mode, padding, IV/nonce source, key derivation, key storage API, and authentication tag handling. Common findings include fixed IVs, reused nonces, ECB, absent integrity, weak randomness, or keys protected only by obfuscation. Confirm reachable code paths before reporting.

## Replay boundaries

A replayable request must reproduce the same authorized lab state: account, nonce, tokens, device identifiers, computed signature, and server-side time assumptions. Do not infer server acceptance from a locally valid signature; observe the lab response or server test explicitly.

## Cronet targets the Java layer cannot reach

If no `TrustManager`, `CertificatePinner` or `X509Util` hook ever fires, the app is on Cronet
(`libhttpengine.so` + `libcrypto_httpengine.so`). Its BoringSSL is statically linked and stripped:
those libraries export no `X509*`/`SSL*` names, so a name-based verify patch lands on unused system
copy and changes nothing. Escalate by seam, not by adding more Java hooks — full ladder in the
`frida` skill, `~/.hermes/skills/android/frida/references/cronet-and-stripped-libs.md` (exports →
`enumerateSymbols` → base+offset → `RegisterNatives` capture → `SSL_*_set_custom_verify`
replacement → trusted CA).

Prove a bypass only against an **untrusted** CA: with a throwaway CA every handshake fails, so
successful requests after the patch are the signal. A CA already in the system store proves nothing.

## Sources

- Android network security configuration: https://developer.android.com/privacy-and-security/security-config
- OWASP MASVS network communication: https://mas.owasp.org/MASVS/08-MASVS-NETWORK/
- Frida JavaScript API: https://frida.re/docs/javascript-api/

## Lessons: Cronet / BoringSSL on Android 16 (2026-11)
- Cronet TLS lives in `libhttpengine.so`, which zygote64 preloads; `libcrypto_httpengine.so` holds only crypto. The library is stripped: no `SSL_*` dynsym. Its `.gnu_debugdata` minisymtab contains only FIPS crypto symbols.
- Do not assume the Java `X509TrustManager` (`SecureX509TrustManager`) is on the decision path: Cronet verification is native, Java TM hooks never fire. Patching the dex method also does nothing while the app is AOT-compiled (`usejit=false`); `cmd package compile -m verify -f` (interpreter) makes dex patches effective, at the price of a very slow start.
- `ssl_log_secret` can exist and even be the correct address per BoringSecretHunter voting, yet never execute (raw uprobe 0 hits). friTap's `SSL_CTX_set_keylog_callback` hook is the reliable key source; ecapture's hook text source needs no keys at all.
- Cronet attaches TLS to BIO pairs: there are no `SSL_set_fd` calls. Map SSL*->fd by uprobing `SSL_set0_wbio` and reading `bio->num` (offset 0x20 on this build).
- Kernel DNAT of the app uid to a local listener is a stable shortcut around proxy settings and per-app proxy ignoring.

