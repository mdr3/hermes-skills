# friTap as an offsets-based cross-check (libhttpengine)

friTap hooks the same stripped BoringSSL by **offsets** instead of names and can emit keylogs/plaintext pcap. It is Frida-based, so an anti-Frida RASP will kill it; use it when the app is unprotected, or to validate that a lib/offset set is right before blaming ecapture.

## Setup
- Install into a throwaway venv from a clone: `python3 -m venv --system-site-packages /tmp/ftvenv && /tmp/ftvenv/bin/pip -e /home/kali/Desktop/friTap` (`fritap --version` confirms).
- Device frida-server must run; expose it with `adb forward`, then pass `-H 127.0.0.1:<port>`.

## Pointing it at a stripped Cronet lib
`--offsets <json>` takes per-module, base-relative (`absolute:false`) entries; validate an address first with the repo locator `dev/find_ssl_log_secret_offset.py <lib.so>` (label call-site voting, expects `votes>=3` and a valid prologue).
```json
{ "libhttpengine.so": {
  "ssl_log_secret": { "address": "0x543ed4", "absolute": false },
  "SSL_read":       { "address": "0x545968", "absolute": false },
  "SSL_write":      { "address": "0x545cfc", "absolute": false },
  "SSL_do_handshake": { "address": "0x545620", "absolute": false } } }
```
Offsets are per app build; re-derive rather than reusing them.

## Run
```
adb shell 'am start -n <pkg>/<activity>'; sleep 4; p=$(adb shell pidof -s <pkg> | tr -d '\r')
/tmp/ftvenv/bin/fritap -H 127.0.0.1:<port> -p /tmp/cap.pcap -k /tmp/cap.keys \
  --offsets /tmp/off.json --force-scan 'libhttpengine\.so' -v "$p"
```
Then check `cap.keys` line count and `cap.pcap` size — nonzero means hooks fired.
- `-m` plus `-H` is a trap: bare `-m` calls `get_usb_device()` and ignores the host; drop `-m`, target the **pid** (a stealth frida-server hides app names from the process list), read the pid right before invoking.
- `-c <script>` resolves relative paths inside the package's plugin dir; pass an absolute path.
- Without symbols in the lib, pass both `--force-scan <regex>` and `--offsets`; `-s` (spawn) survives longer than attach on RASP apps but still dies at resume.
