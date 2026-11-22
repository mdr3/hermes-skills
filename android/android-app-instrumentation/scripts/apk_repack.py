#!/usr/bin/env python3
"""Rewrite an APK with replacement entries, keeping it installable.

Replaced and library entries are STORED (required for extractNativeLibs=false),
stale META-INF signature files are dropped, adjacency order is preserved.
Alignment and signing are separate steps -- run the printed commands.

usage: apk_repack.py in.apk classes6.dex=/tmp/new.dex [name=path ...] -o out.apk
"""
import argparse
import os
import sys
import zipfile

SIG = ("META-INF/CERT.SF", "META-INF/CERT.RSA", "META-INF/MANIFEST.MF",
       "META-INF/ANDROIDD.SF", "META-INF/ANDROIDD.RSA")


def stored(name):
    return name.endswith(".so") or name == "resources.arsc"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("repl", nargs="+", help="name=path entries to replace")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    repl = {}
    for r in a.repl:
        name, path = r.split("=", 1)
        repl[name] = open(path, "rb").read()

    src = zipfile.ZipFile(a.apk)
    names = set(src.namelist())
    for n in repl:
        if n not in names:
            sys.exit("not in apk: " + n)

    with zipfile.ZipFile(a.out, "w", allowZip64=True) as out:
        for zi in src.infolist():
            if zi.filename in SIG and zi.filename not in repl:
                continue
            blob = repl.get(zi.filename)
            data = blob if blob is not None else src.read(zi.filename)
            nzi = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
            nzi.external_attr = zi.external_attr
            compress = stored(zi.filename) or zi.filename in repl
            nzi.compress_type = zipfile.ZIP_STORED if compress else zipfile.ZIP_DEFLATED
            out.writestr(nzi, data, compress_type=nzi.compress_type)

    print("wrote", a.out, os.path.getsize(a.out))
    print("next:")
    print(f"  zipalign -f -p 4 {a.out} {a.out}.a")
    print(f"  apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android "
          f"--key-pass pass:android --min-sdk-version <minSdk> {a.out}.a")
    print(f"  apksigner verify {a.out}.a && zipalign -c -p 4 {a.out}.a")


if __name__ == "__main__":
    main()
