// Hide the agent from the two cheapest RASP probes: per-thread /comm names
// (gum-js-loop, gmain, pool-frida) and the /system/xbin/su root probe.
//
// When these are defeated the detector never flips the runtime into instrumented
// mode, so ART is never repainted and the libart patches become unnecessary.
// Verify survival, then build the real payload on top.
//
// Same-uid only: the agent runs inside the app, so the decoy is written to the
// app's own files dir (adb push + chown is the alternative when scripting a run).

'use strict';

const PKG = 'sa.gov.nic.twkhayat';                 // adjust
const DECOY = '/data/data/' + PKG + '/files/.comm';
const DECOY_TEXT = 'binder:1_1';                   // any benign, non-frida name

const libc = Process.getModuleByName('libc.so');
const openat = libc.findExportByName('openat');
const open = libc.findExportByName('open');
const access = libc.findExportByName('access');
const dup = new NativeFunction(libc.findExportByName('dup'), 'int', ['int']);

let fakeFd = -1;
function ensureDecoy() {
    if (fakeFd >= 0) return;
    const fo = new NativeFunction(libc.findExportByName('fopen'), 'pointer', ['pointer', 'pointer']);
    const fw = new NativeFunction(libc.findExportByName('fwrite'), 'int', ['pointer', 'int', 'int', 'pointer']);
    const fc = new NativeFunction(libc.findExportByName('fclose'), 'int', ['pointer']);
    const fh = fo(Memory.allocUtf8String(DECOY), Memory.allocUtf8String('w'));
    if (fh.isNull()) throw new Error('decoy write failed');
    fw(Memory.allocUtf8String(DECOY_TEXT), 1, DECOY_TEXT.length, fh);
    fc(fh);
    fakeFd = openat
        ? new NativeFunction(openat, 'int', ['int', 'pointer', 'int', 'int'])(-100, Memory.allocUtf8String(DECOY), 0, 0)
        : new NativeFunction(open, 'int', ['pointer', 'int'])(Memory.allocUtf8String(DECOY), 0);
    console.log('[stealth] decoy fd ' + fakeFd);
}

const isComm = s => !!s && s.indexOf('/proc/self/task/') === 0 && s.endsWith('/comm');

if (openat) {
    Interceptor.attach(openat, {
        onEnter(a) { let s = null; try { s = a[1].readUtf8String(); } catch (e) {} this.hit = isComm(s); },
        onLeave(r) { if (!this.hit) return; ensureDecoy(); if (fakeFd >= 0) r.replace(ptr(dup(fakeFd))); }
    });
}
if (open) {
    Interceptor.attach(open, {
        onEnter(a) { let s = null; try { s = a[0].readUtf8String(); } catch (e) {} this.hit = isComm(s); },
        onLeave(r) { if (!this.hit) return; ensureDecoy(); if (fakeFd >= 0) r.replace(ptr(dup(fakeFd))); }
    });
}

// Root verdict: make every su candidate disappear.
for (const fn of [access, libc.findExportByName('stat'), libc.findExportByName('stat64'), libc.findExportByName('lstat')]) {
    if (!fn) continue;
    Interceptor.attach(fn, {
        onEnter(a) { let s = null; try { s = a[0].readUtf8String(); } catch (e) {} this.su = !!s && /(^|\/)su$/.test(s); },
        onLeave(r) { if (this.su) r.replace(ptr(-1)); }
    });
}

console.log('[stealth] armed');
