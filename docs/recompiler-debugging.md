# Recompiler Debugging: Lessons Learned

Notes from integrating the PVM recompiler into block processing and achieving
parity with the interpreter across all tests and conformance traces.

## Debugging Method: Per-Instruction Comparison

The most effective technique was a **per-instruction comparison mode** (`GREY_PVM=compare`)
that runs both the interpreter and recompiler in lockstep, one instruction at a time,
and reports the first point of divergence.

### How it works

1. Save each backend's current gas
2. Set gas to 1 on both backends
3. Run both — each executes exactly one instruction then exits with OutOfGas
4. Restore gas by subtracting what was consumed: `gas_after = gas_before - (1 - remaining)`
5. Compare all 13 registers, PC, and exit reason
6. If they match and the exit was OOG, continue to the next instruction
7. If they match and the exit was real (host call, halt, panic), return it
8. On mismatch, log the divergence and return

This narrows bugs to a single instruction, making root cause analysis trivial.
The approach lives in `crates/grey-state/src/pvm_backend.rs` in the `Backend::Compare`
arm of `PvmInstance::run()`.

### Key insight: entry_pc must be updated on OOG

The recompiler uses a dispatch table keyed by PC for re-entry after host calls
and exits. When the compare mode sets gas=1 and the recompiler exits with OOG,
`entry_pc` must be set to the current `pc` so the next `run()` call re-enters
at the right instruction. Without this, the recompiler re-enters at the previous
entry point and re-executes from there.

## Bug Categories Found

### 1. Three-register aliasing (rd == rb)

**Pattern:** For three-register instructions like `add rd, ra, rb`, the codegen does:
```
mov rd, ra    // clobbers rb if rd == rb!
op  rd, rb    // reads stale value
```

**Fix:** When `rd == rb`, save `rb` to SCRATCH (RDX) before the mov:
```
mov SCRATCH, rb
mov rd, ra
op  rd, SCRATCH
```

**Affected:** ~20 instructions — Or, And, Xor, Mul32/64, Sub64, all shifts
(ShloL/ShloR/SharR 32/64), all rotates (RotL/RotR 32/64), Min/Max/MinU/MaxU, Xnor.

**Lesson:** Any time a destination register is written before all source operands
are read, check for aliasing. This is the most common class of recompiler bug.

### 2. ImmAlt aliasing (ra == rb)

**Pattern:** ImmAlt variants encode `op ra, imm, rb` as:
```
mov ra, imm   // clobbers rb if ra == rb!
op  ra, rb    // reads stale value
```

Same fix: save `rb` to SCRATCH when `ra == rb`.

**Affected:** ShloLImmAlt32/64, ShloRImmAlt32/64, SharRImmAlt32/64,
RotR64ImmAlt, RotR32ImmAlt, NegAddImm32/64.

### 3. Flags clobber from xor-zeroing

**Root cause:** `mov_ri64(reg, 0)` is optimized to `xor reg, reg`, which
clobbers CPU flags. If this appears between a `cmp` and a `setcc`, the
condition code is destroyed.

**Original buggy pattern:**
```
cmp   rb, imm
mov   ra, 0      // xor ra, ra — clobbers flags!
setcc ra
```

**Fix:** Remove the zero-initialization entirely; use `setcc` + `movzx` to
zero-extend the byte result to 64 bits:
```
cmp    rb, imm
setcc  ra_byte
movzx  ra_64, ra_byte
```

**Affected:** SetGtUImm, SetLtUImm, SetGtSImm, SetLtSImm, SetLtU (3-reg),
SetLtS (3-reg).

**Lesson:** Never assume `mov reg, 0` is side-effect-free on x86-64. The xor
optimization is great for performance but dangerous between flag-setting and
flag-consuming instructions.

### 4. x86-64 immediate sign extension in 64-bit CMP

**Bug:** `cmp r64, 0xFFFF0000` encodes as a 64-bit compare with a 32-bit
immediate. The CPU **sign-extends** the immediate, so it actually compares
against `0xFFFFFFFFFFFF0000`, not `0x00000000FFFF0000`.

**Fix:** Use a 32-bit compare (`cmp r32, imm32`) when comparing 32-bit address
values. This was needed in `emit_dynamic_jump` for the halt-address check.

**Lesson:** Always consider how x86-64 handles 32-bit immediates in 64-bit
operations — they are sign-extended, not zero-extended.

### 5. sbrk semantics (pages vs bytes)

The recompiler's `sbrk_helper` was treating the argument as a page count and
multiplying by PAGE_SIZE. The Gray Paper specifies sbrk takes a byte count.
Fixed by rewriting `sbrk_helper` to match the interpreter exactly.

**Lesson:** Always cross-reference the interpreter implementation when writing
recompiler helpers.

### 6. Stack cleanup clobbering mapped registers

**Bug:** `pop(RAX); pop(RAX)` to discard two stack slots overwrites φ[11]
(which is mapped to RAX).

**Fix:** Use `add RSP, 16` to discard stack slots without touching any register.

**Lesson:** Remember that RAX and RCX are mapped to PVM registers (φ[11] and
φ[12]). Any instruction that implicitly uses RAX (mul, div, pop, etc.) must
save/restore it.

### 7. Missing signed load extension

LoadIndI8, LoadIndI16, LoadIndI32 (and their non-indirect variants) load raw
bytes from memory but must sign-extend the result to 64 bits. The unsigned
variants (LoadIndU8, etc.) were fine because zero-extension happens naturally,
but signed variants need explicit `movsx` / `movsxd` after the load.

### 8. MulUpper stack offset errors

`emit_mul_upper` pushes RAX and RDX to save them, then pushes the result.
The stack offsets for restoring the originals were wrong (16,24 instead of 8,16)
because they didn't account for the push order correctly. Also needed special
handling when `rb == RAX` (the multiply source is the register we just saved).

## General Lessons

1. **Per-instruction comparison is the best debugging tool.** It reduces the
   search space from "entire program execution" to "single instruction." Worth
   the implementation effort.

2. **Register aliasing is the #1 source of codegen bugs.** Every instruction
   that writes a destination before reading all sources needs aliasing checks
   for all combinations (rd==ra, rd==rb, ra==rb).

3. **x86-64 has many implicit behaviors** — flag clobber from xor, immediate
   sign extension, implicit RAX usage in mul/div. Each one is a potential bug.

4. **Match the interpreter exactly.** Don't reinterpret the spec independently
   for the recompiler — compare against the interpreter's behavior, which is
   already tested against conformance traces.

5. **Fix forward, not backward.** Each bug fix pushes the divergence point
   further into execution. Track progress by the step/instruction number where
   comparison first fails.
