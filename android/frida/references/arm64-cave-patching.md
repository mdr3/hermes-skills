# ARM64 cave patching (patching a body that must keep running)

Use when a hook has to run native code (repair a value, call a helper) instead of a plain
`mov w0,#imm; ret`. Every rule here is a crash that cost time; the encodings are the parts that
guess wrong.

## Allocate and keep the cave

- `Memory.alloc(size, { near: base, maxDistance: 0x6000000 })` — `near` is **rejected without
  `maxDistance`** (“missing maxDistance option”), and `size` must be a page multiple
  (“size must be a multiple of page size”). A rejected alloc inside a `forEach` aborts the whole
  loop, so the module silently installs nothing: wrap the loop body in try/catch and log the error.
- Keep every cave in a module-level array (`KEEP.push(c)`). The JS object is only a handle; once it
  is garbage the page is unmapped and the next hit faults `SEGV_MAPERR` **at the cave address**.
- `Memory.protect(c, 0x1000, 'rwx')` after allocating — Frida pages are not executable.
- Prefer a `bl` into the cave (range ±128 MB, satisfied by `maxDistance`) over an inline copy of the
  code, so the cave can just `ret` and needs no branch back.

## Encodings

- Verify every word with `rasm2 -a arm -b 64 -d <hex>` using **file byte order** (reverse the u32),
  and round-trip each instruction. `rasm2`’s *assembler* happily emits a different form than you
  meant (`str x11,[x0],8` → `stur`, `cmp x10,0x100` → `cmp x10,0`) — trust the disassembly, not the
  assembly.
- Literal-pool loads: `ldr x9,[pc,#8]` reads from `instr+8`, so the quad must be at that offset and
  execution needs an explicit branch past the literal. Off-by-one here is `SIGILL` at the data.
- `b.cond` / `b` immediate is **19 bits**: sign-extend the word delta, then mask to `0x7ffff` before
  shifting. `0x1FFFFC<<5` looks right and is not — it needs `0x7FFFC<<5`.
- `writeU32` takes unsigned: any literal above `0x7fffffff` (`0xd65f03c0`, `0xf940012b | k<<10`)
  needs `>>> 0`, otherwise “expected an unsigned integer”.
- Post-index `stp/ldp` with a register offset was unreliable in practice; unrolling immediate-offset
  `ldr`/`str` pairs with a fixed count is easier to get right.

## Recursion when re-implementing a stub

Before replacing a stubbed function, check where it ends: if the entry you patch (or the helper you
call) *tail-branches back into the same function*, a plain call recurses and the main thread burns
CPU (visible as a rising `utm` in `debuggerd`/ANR traces). Options, in order: `ret` if the table it
was supposed to fill is already valid; otherwise a depth guard. A process-wide flag only ever blocks
one level and then sticks — clear a stale flag on entry so a long-jumped callee cannot wedge the
patch off.

## Confirming what a site receives, without a debugger

`Interceptor.attach(ptr)` works on an arbitrary instruction, not just a function entry. Attach to
`module.base.add(offset)`, print `this.context.x0…x15`, and remove the patch first — that showed
within one run that the site’s `x0` was a `LogMessage` buffer rather than the argument, which no
amount of static reading had made obvious. Deeper dumps: `debuggerd -b <pid>` or `kill -3 <pid>` +
`/data/anr/trace_00` (Java frames).
