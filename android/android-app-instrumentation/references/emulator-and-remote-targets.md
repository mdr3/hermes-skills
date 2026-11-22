# Choosing an emulator target, and driving one on another machine

## ABI decides everything

Check what the APK actually ships before recommending a host:

```
unzip -l app.apk | grep -oE 'lib/[a-z0-9_-]+/' | sort -u
```

`lib/arm64-v8a/` only means an x86_64 image cannot run the app natively, and any
agent whose offsets were derived from arm64 `libart.so` is invalid on x86_64 — the
ART offsets are per-ABI and per-build, and must be re-derived from that image's own
`libart.so`. A published x86_64 split is what makes the x86_64 route viable at all;
the merged APK pulled off an arm64 handset will not contain it.

## Host capability, before anything

- `/dev/kvm` present and `vmx`/`svm` in `/proc/cpuinfo` → KVM, fast.
- Neither (a VM without nested virtualisation) → QEMU TCG for *both* ABIs; the
  emulator is still usable for hook validation, not for timing-sensitive soaks.
- Windows host: `emulator -accel-check` reports WHPX or nothing. Enabling WHPX, and
  HAXM install, both need admin; without admin expect TCG.

## Image choice

Images exist for arm64-v8a and x86_64 up to API 36+ (`sdkmanager --list | grep
arm64-v8a`). Prefer API 30 or 31 — closer to the era most pinning/RASP code was
written for.

- `google_apis` = **userdebug**: `adb root` + `adb remount` work, so the CA installs
  with a plain `push` to `/system/etc/security/cacerts/` and frida-server runs as root
  with no Magisk/KernelSU and no root-manager detection. No Play Store, so the app's
  splits have to come from elsewhere.
- `google_apis_playstore` = user build: Play installs the app for you, but root needs
  rootAVD and the CA needs the Magisk module route.
- `*_atd` images are for automated tests, headless-oriented; fine as a smoke target.

## Driving an emulator that runs on another machine

Host firewalls are often locked down by policy, and the emulator binds 5555 to
loopback only. Do not try to forward emulator ports outward — point the adb **client**
at the remote adb **server** over an SSH reverse tunnel, which needs only an outbound
connection from the Windows box and no admin rights and no firewall rule:

```
# Windows box (OpenSSH client is built in). Password or key auth, no admin needed.
ssh -N -R 5037:127.0.0.1:5037 kali@<kali-ip>

# Kali side
ADB_SERVER_SOCKET=tcp:127.0.0.1:5037 adb devices
```

Client and server should be the same platform-tools major version; a mismatch shows
up as a protocol handshake failure, not as "no devices". Start sshd on the Kali side
first (`sudo systemctl start ssh` — usually not enabled at boot, so say so rather
than leaving the user to discover it).

## Windows shell trap

`%USERPROFILE%` is expanded by cmd.exe only; in PowerShell it stays literal and you
create a directory actually named `%USERPROFILE%`. Use `$env:USERPROFILE` and a
`$sdk` variable there, and remember a bare quoted path is not executed in PowerShell
— prefix with `&`.

## Package install without admin

`sdkmanager` cannot fetch over a TLS-intercepting proxy: it fails with `Failed to
download any source lists` / `IO exception while downloading manifest` because Java's
truststore lacks the corporate CA. The browser does trust it, so download the three
archives directly and unpack by hand — everything stays in the user profile:

```
platform-tools_r<N>-win.zip          (repository2-3.xml)
emulator-windows_x64-<build>.zip     (repository2-3.xml)
sys-img/google_apis/x86_64-30_r<N>.zip
```

all under `https://dl.google.com/android/repository/`; unpack with `tar -xf <zip> -C
<dest>` (Windows ships bsdtar). Verify the result with `dir /b` — a zip that nests a
second directory level leaves the tree one level deep and every downstream tool then
says the path is wrong.

Traps in that flow, each measured:

- The command-line-tools zip unpacks as `cmdline-tools\` with **no** `latest` level, and
  sdkmanager aborts with `Could not determine SDK root`. Rename it into place
  (`move cmdline-tools ct`, `mkdir cmdline-tools`, `move ct cmdline-tools\latest`) and
  also pass `--sdk_root=<sdk>`.
- The emulator zip carries **no** `package.xml`, so `avdmanager create avd` stops with
  `Error: "emulator" package must be installed!`. Either write a minimal
  `emulator\package.xml` (`localPackage path="emulator"`, `genericDetailsType`, a
  revision) or skip avdmanager entirely.
- Writing that XML from Notepad leaves a BOM and the repository loader reports
  `Content is not allowed in prolog`. Write it with cmd `echo` and escaped `^<` `^>`.
- An AVD is only two ini files, and the emulator reads them without avdmanager:
  `%USERPROFILE%\.android\avd\<name>.ini` (`path=`, `path.rel=`, `target=android-30`)
  and `<name>.avd\config.ini` (`AvdId`, `abi.type`, `hw.cpu.arch`,
  `image.sysdir.1=system-images\android-30\google_apis\x86_64`, `hw.ramSize`,
  `hw.gpu.enabled`, `hw.gpu.mode`, `disk.dataPartition.size`).
- A hand-built AVD has no device profile and boots at a tiny resolution that is then
  upscaled — soft, blurry UI that reads like a GPU fault. It is not: set
  `hw.lcd.width/height/density` (1080/1920/440) in `config.ini`, or live with
  `adb shell wm size 1080x1920` + `wm density 440`.

## What an emulator costs you

The RASP sees an emulator: `ro.kernel.qemu=1`, ranchu hardware, no baseband, no SIM,
so SMS OTP has to be read on the physical phone and integrity checks can fail.
Screenshot and `uiautomator dump` still work headless. Treat an emulator as a second
target to validate hooks and offsets, not as a substitute for the handset the app was
written for.
