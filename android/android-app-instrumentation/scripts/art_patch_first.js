/*
 * Pre-load patch script for a protected app whose ART aborts on entrypoint
 * instrumentation. Size matters: this must stay small enough that create_script +
 * load finishes while the process is still starting, so the real payload goes in a
 * second script on the SAME session, after this one has logged.
 *
 * Offsets are libart-build specific (arm64, this device's APEX). Re-derive them from
 * the build's .dynsym as described in the skill before reusing on another device:
 *   0x55dfac  bl abort inside ResetQuickAllocEntryPoints' UNIMPLEMENTED tail
 *   0x2e31e0  ThreadList::RunCheckpoint      (holds thread_list_lock_)
 *   0x411d58  AddNativeDebugInfoForDex
 *   0x3b53d0  AddNativeDebugInfoForJit
 *
 * NOP is 0xd503201f, RET is 0xd65f03c0. libart's text segment is vaddr == file
 * offset, so the same numbers can be applied to an on-disk copy when a protector
 * hashes the file.
 */

var OFFSETS = [
  [0x55dfac, 0xd503201f],
  [0x2e31e0, 0xd65f03c0],
  [0x411d58, 0xd65f03c0],
  [0x3b53d0, 0xd65f03c0]
];

var art = Process.findModuleByName('libart.so');
if (art) {
  OFFSETS.forEach(function (o) {
    try {
      Memory.patchCode(art.base.add(o[0]), 4, function (d) { d.writeU32(o[1]); });
    } catch (e) {
      console.log('[mini] patch ' + o[0].toString(16) + ': ' + e);
    }
  });
  console.log('[mini] art patched ' + OFFSETS.length);
} else {
  console.log('[mini] libart not mapped yet - attach later, do not spawn blind');
}
