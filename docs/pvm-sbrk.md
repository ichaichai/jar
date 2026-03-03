# PVM `sbrk` — Spec Ambiguity and Debugging Notes

This documents a conformance bug in Grey's PVM that took five debugging sessions
to find. The root cause was a 4-gas discrepancy (4 extra instructions executed)
caused by an ambiguity in the Gray Paper's definition of `sbrk`.

## The Bug

Grey's JAM conformance target was producing `gas_used = 7720` for the first
accumulation in the test trace, while the reference implementations (jamzig,
polkavm) produce `gas_used = 7716`. Every PVM instruction costs 1 gas, so this
was exactly 4 extra instructions.

## Gray Paper Definition (v0.7.2, opcode 101)

The specification defines `sbrk` as:

```
φ'_D ≡ min(x ∈ N_R):
    x ≥ h
    N_{x...+φ_A} ⊄ V_μ
    N_{x...+φ_A} ⊆ V*_μ'
```

In prose: set the destination register to the smallest address `x ≥ h` (the heap
base) such that the range `[x, x + φ_A)` is *not* currently accessible but
*becomes* accessible (newly mapped as read-write) in the post-state.

The note below the instruction table says:

> *h* refers to the beginning of the heap, the second major section of memory as
> defined in equation eq:memlayout as `2·Z_Z + Z(|o|)`.

## The Problem: `sbrk(0)` Is Undefined

When the argument `φ_A = 0`, the range `N_{x...+0}` is the empty set `∅`.

- `∅ ⊄ V_μ` is **false** (the empty set is a subset of everything)
- So the constraint `N_{x...+φ_A} ⊄ V_μ` is never satisfied
- Therefore `min(∅)` is undefined

The Gray Paper does not define what happens when `sbrk` is called with size 0.

## What the Reference Implementations Do

Guest programs (compiled via polkavm-linker) use `sbrk(0)` as a **heap query**:
"tell me where the heap pointer currently is, without allocating anything." This
is the standard POSIX convention — `sbrk(0)` returns the current program break.

### polkavm (Rust reference)

From the polkavm source (module `api.rs`):

```rust
fn sbrk(&mut self, size: u32) -> Option<u32> {
    if size == 0 {
        return Some(self.heap_top);
    }
    // ...allocate...
}
```

Where `heap_top` is initialized to `heap_base + initial_heap_size` and advances
monotonically as allocations occur.

polkavm trace output confirms this:
```
sbrk: +0 (heap size: 0 -> 0)
a0 = 0x33000
```

`sbrk(0)` returns `0x33000` (the current heap top), not `0`.

### jamzig (Zig reference)

The Go reference (`strawberry`) similarly uses a `current_heap_pointer` field
and returns it directly for `sbrk(0)`.

## How This Caused a 4-Instruction Delta

The guest program's allocator initialization calls `sbrk(0)` to query available
heap space. With the typical tiny-config memory layout:

- `heap_top = 0x33000` (end of pre-mapped rw+heap region)
- The allocator checks: is `heap_top >= needed_size`?

**In polkavm**: `sbrk(0)` returns `0x33000`. The check `0x33000 >= 0x32780`
passes. The allocator skips the allocation path (branch taken).

**In Grey (before fix)**: `sbrk(0)` returned `0` (our naive "find unmapped
region from h" logic found nothing, so we returned the heap base). The check
`0 >= 0x32780` fails. The allocator falls through to an unnecessary allocation
path, executing 4 extra instructions.

This pattern happens exactly once per accumulation, explaining the consistent
delta of exactly 4.

## The Fix

Grey now tracks a `heap_top` counter in the PVM struct, initialized during
standard program initialization `Y(p, a)` to:

```
heap_top = heap_base + page_round(rw_size + heap_pages * PAGE_SIZE)
```

The `sbrk` implementation becomes:

- **`sbrk(0)`**: return `heap_top` (query mode)
- **`sbrk(n)`**: return old `heap_top`, advance it by `n`, map any new pages
- **`sbrk(n)` overflow**: return `0` if `heap_top + n > 2^32`

This is the heap-pointer tracking model used by all reference implementations.

## Additional Bug: Return Value Semantics

The Gray Paper's formulation returns the start of the *newly mapped* region,
which is the first address ≥ h that isn't currently accessible. This is
conceptually different from what allocators expect.

POSIX `sbrk(n)` returns the **old break** (the start of the newly allocated
region), which is the current `heap_top` *before* advancing. All PVM reference
implementations follow POSIX semantics, not the literal spec formulation:

- Return value = old `heap_top` (start of new allocation)
- Side effect = advance `heap_top` by `n`, mapping pages as needed

Our initial implementation returned `heap_base + new_heap_size` (the *end* of
the allocation), which is also wrong. The correct return value is the *old*
heap pointer.

## Recommendation for the Gray Paper

The `sbrk` definition should:

1. **Explicitly define `sbrk(0)`** as returning the current heap pointer without
   side effects. The current formulation yields `min(∅)` which is undefined.

2. **Introduce a heap pointer** `p` (or similar) into the PVM state, initialized
   to `h + page_round(|w| + z·PAGE_SIZE)` per the standard program layout.
   The current definition is stateless — it searches for unmapped memory each
   time — but all implementations track state.

3. **State the return value semantics explicitly**: `sbrk(n)` returns the old
   heap pointer (the start of the allocated region), matching POSIX convention.

The current formulation is mathematically elegant but leaves `sbrk(0)` undefined
and obscures the stateful nature of the operation. Every implementation we
examined (polkavm, jamzig, strawberry) uses a heap-pointer tracking model that
is semantically different from the spec's "find the first unmapped region"
definition.

## Debugging Timeline

This bug survived four debugging sessions because:

1. **Trace file overwrite**: Our PVM trace dumper used a fixed filename
   (`/tmp/pvm_trace.txt`). When multiple accumulations ran, later accumulations
   overwrote the trace. Three sessions of analysis were based on the wrong
   trace data.

2. **Small delta**: 4 instructions out of 7716 is a 0.05% difference. The
   traces *looked* correct at a glance.

3. **Correct final state**: Despite the gas difference, the accumulation
   produced the correct state root for blocks 1-6. The bug only manifested
   as a gas delta because the extra instructions were in the allocator's
   initialization — they allocated memory that was already available, producing
   the same end result.

4. **Spec-level ambiguity**: We initially assumed our implementation matched
   the spec (it did, for the defined cases). The bug was in an *undefined* case
   (`sbrk(0)`) where the spec gives no guidance.

Lesson: when debugging gas deltas, ensure your tracing infrastructure captures
the *right* execution. Use unique filenames keyed on distinguishing parameters
(service ID, gas used, etc.) to avoid overwrite bugs.
