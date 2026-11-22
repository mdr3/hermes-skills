%# On-device debugging fallbacks: eDBG and ceserver

For when Frida cannot attach at all but the process still needs to be inspected.

## eDBG (MCP mode)

- eDBG exposes an MCP server; point the client at it and use breakpoints plus a
  backtrace to find a caller that Frida hooks cannot reach.
- Breakpoints survive across a payload being absent — useful when the payload is
  exactly what kills the app.
- Resolve the faulting `pc` as `module+offset` from `/proc/<pid>/maps` before
  setting anything; ASLR makes raw addresses single-use.

## ceserver (root memory reads)

- With root, `ceserver` reads and writes memory of a process that refuses ptrace,
  including pages marked read-only through `/proc/<pid>/mem`.
- Read a foreign page with `adb exec-out su -c 'dd if=/proc/<pid>/mem bs=4096
  skip=<addr>>12 count=1'` — `adb exec-out`, not `adb shell >`, or CRLF corrupts it.
- Compute the page index from the address; eyeballing it is where the off-by-one
  comes from.

## Which TLS functions are actually on the path

- conscrypt verifies natively: `X509_verify_cert`, `X509_check_host`,
  `X509_check_ip_asc` are the levers, with `SSL_get_verify_result` for the result.
- The Java `checkServerTrusted` of `TrustManagerImpl`/`PlatformTrustManager` is
  **not** guaranteed to run — if no `HIT` prints, the verification happened below
  Java and only the crypto layer matters.
- `SSL_CTX_set_custom_verify` is frequently absent from the apex `libcrypto`
  (`unable to find export`); do not build a strategy around it.
