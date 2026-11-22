# Rigging a host GUI to a device capture tool

Pattern for driving an on-device `ecapture` from a host consumer (ecaptureQ) with one
command, after the consumer learned to spawn a `--ecapture-bin` child and inject
`--eventaddr ws://127.0.0.1:<port>/ingest?token=…`:

1. **Shim, not direct spawn.** Point `--ecapture-bin` at a shell wrapper. It reads the
   argv it was handed, extracts the port from `--eventaddr`, and runs
   `adb reverse tcp:<port> tcp:<port>`; the device's own `127.0.0.1:<port>` then reaches
   the host relay. Remove the reverse on exit.
2. **Ship the command as a file, not `su -c "<joined>"`.** Quote each argv element with
   `printf '%q'`, write `#!/system/bin/sh\nexec <bin> <args>` to a temp file, `adb push`
   it, then `adb shell 'su -c sh /data/local/tmp/ecap-cmd.sh'`. Passing one long argv
   through `su -c` mangles quoting and splits flags.
3. **Exports stay manual.** If the supervisor also appends `--harfile`/`--xmlfile`, the
   device writes them under a device path and the wrapper has to rewrite and pull — extra
   moving parts. Leaving exports out (and passing them through an `EXTRA_ARGS`/`ECAP_ARGS`
   env instead) keeps the rig about liveness and lets the operator pull files when wanted.
4. **Host build compiler.** The launcher script must build the host server with
   `/usr/bin/gcc` (overridable), never the ambient `CC` — on an Android workstation that
   points at the NDK clang and fails on `runtime/cgo`.
5. **Gate before starting.** Require `adb get-state` = device, `su -c id` = uid 0 and the
   device binary present/executable; trap EXIT/INT/TERM to kill the supervisor and clear
   reverses.

Warning signs that the capture leg (not the rig) is broken: the source stays
`reconnecting`, exports stay 0 bytes, yet the device process is alive and `dmesg` shows
`Packet captured` — packets arrive but the SSL uprobes never fire.
