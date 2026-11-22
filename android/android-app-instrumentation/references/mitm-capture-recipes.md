# Capture recipes for apps that ignore the system proxy

`settings put global http_proxy` is the control, not the method: hardened apps use
stacks (Cronet, pinned OkHttp) that never read it. Verify the plumbing with
`curl -sk https://<host>/` through the same redirect *before* blaming the app.

## First choice over USB: explicit proxy mode, not a redirect

`adb reverse tcp:8080 tcp:8080` + `settings put global http_proxy 127.0.0.1:8080`
+ `mitmdump --listen-port 8080 -w flows.mitm` (no `--mode`). The app connects to
`127.0.0.1:8080`, adb forwards it to the host, and mitm runs as a normal proxy with
a CONNECT target. Enough OkHttp apps honour the global setting this way, and it needs
no CA-store work, no netfilter and no host IP — which matters when the host's network
changes under you. Re-read the setting after writing it (`settings get global
http_proxy`); it silently reverts to `:0`.

**Do not DNAT to loopback while using `adb reverse`.** A DNAT to `127.0.0.1:<port>`
(including a *different* loopback port than the listener) makes mitm see its own listen
socket as the destination and reprocess itself — `Request destination unknown`, HTTP 502,
flow file at 0 bytes — and `--set connection_strategy=lazy` does **not** rescue it,
because the destination is wrong before the ClientHello exists. That is the case the
`<host-lan-ip>` recipe below is for: DNAT only pays off against a routable address.

## uid-scoped redirect

```
adb shell "iptables -t nat -A OUTPUT -d <resolved-ip>/32 -p tcp --dport 443 \
  -j REDIRECT --to-ports 9091"
mitmdump --mode reverse:https://<host>:443@9091 -w flows.mitm \
  --set confdir=~/.mitmproxy --set ssl_insecure=true --set upstream_cert=true
```

Pin the rule to the resolved IP (`dig +short <host>`), not a port-wide rule, so
the device's own traffic stays readable. Re-resolve after any DNS change and
remove the rule with `-D`; a stale rule is the usual cause of "everything times
out".

Limits, in order of how often they bite:

- **reverse mode serves one certificate.** Any other SNI arriving on the redirected
  port (Firebase, GMS, a CDN) gets a cert for the target host and the handshake is
  refused, so the flow file stays at 0 bytes while the app is clearly talking. Use
  per-host reverse listeners, or TPROXY, when more than one host matters.
- **transparent mode needs a destination, and `adb reverse` cannot supply one.**
  With `-j REDIRECT --to-ports` the accepted socket's destination is `127.0.0.1`,
  so mitm reprocesses its own listener: `Request destination unknown` and HTTP 502
  while the flow file stays at 0 bytes. `-j DNAT --to-destination <host-lan-ip>:<port>`
  fixes it — the destination is a routable address and mitm starts
  `--mode transparent --set connection_strategy=lazy`, which defers the upstream
  until the ClientHello and takes the host from the SNI. Any port-wide rule then
  needs no per-host listener either, so the reverse-mode limit above stops
  mattering. Prove the loop is gone with `curl` **without** `-k` and expect 200.
- **uid filtering is not applied by the app, it is enforced by netfilter** — scope
  with `-m owner --uid-owner <uid>` when you must not catch other apps, and remember
  the uid is per-install and changes on reinstall. On KernelSU, `adb shell` is already
  **uid 0**, so a `--uid-owner 2000` test rule never matches your own `curl` and its
  counters stay at 0 — add a uid-0 rule while testing and read
  `iptables -t nat -vnL OUTPUT` to see which rule actually fired.

## What the flow file does and does not prove

A decrypted request with host, path and body in `flows.mitm` proves the app accepted
replacement crypto material. `SSL_read`/`SSL_write` hooks printing the same request
prove only that the hooks fired — they work with pinning fully intact. Report which
one you have, by name.

## Signing with the CA you installed

`targetSdk` ≥ 24 ignores user certs, so the trust anchor has to be a platform CA:
install `<subject_hash_old>.0` of the CA's DER under
`/system/etc/security/cacerts` (bind-mounted, `root:root`, `644`,
`u:object_r:system_security_cacerts_file:s0`). mitm must sign with *that* CA or the
chain the app checks is not the chain you installed — materialise key and cert out
of the provisioning `.p12` (`openssl pkcs12 -in x.p12 -passin pass:… -nodes`) into
`<confdir>/mitmproxy-ca.pem` and run with `--set confdir=<confdir>`.

Then verify with `curl` **without** `-k`: `-k` skips the very verification being
tested, and a 200 only means something once the app's own anchor accepts the
chain. Re-check the bind mount per launch — an APK install or a reboot drops it.

Read the capture without the TUI: `mitmdump -nr flows.mitm` prints nothing useful
for binary files, so parse with `mitmproxy.io.FlowReader` in Python.
