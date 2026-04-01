//! Stub recompiler for non-Linux/x86-64 platforms.
//!
//! Exposes the same public API as `recompiler/mod.rs` but backs execution
//! with the interpreter, so all callers compile and run on any platform.
//! On supported platforms (Linux x86-64) the real JIT recompiler is used instead.

pub use crate::ExitReason;
use crate::vm::Pvm;
use crate::{Gas, PVM_REGISTER_COUNT, program};

// Make predecode available at the same path callers expect
// (crate::recompiler::predecode). The file has no platform-specific code.
#[path = "recompiler/predecode.rs"]
pub mod predecode;

/// Interpreter-backed stub that mirrors the `RecompiledPvm` API.
pub struct RecompiledPvm(Pvm);

/// Initialize from a standard program blob (same signature as the real recompiler).
pub fn initialize_program_recompiled(
    code_blob: &[u8],
    args: &[u8],
    gas: Gas,
) -> Option<RecompiledPvm> {
    program::initialize_program(code_blob, args, gas).map(RecompiledPvm)
}

impl RecompiledPvm {
    /// Run until the next exit point (halt, panic, OOG, host call, page fault).
    pub fn run(&mut self) -> ExitReason {
        self.0.run().0
    }

    pub fn registers(&self) -> &[u64; PVM_REGISTER_COUNT] {
        &self.0.registers
    }

    pub fn registers_mut(&mut self) -> &mut [u64; PVM_REGISTER_COUNT] {
        &mut self.0.registers
    }

    pub fn gas(&self) -> Gas {
        self.0.gas
    }

    pub fn set_gas(&mut self, gas: Gas) {
        self.0.gas = gas;
    }

    pub fn pc(&self) -> u32 {
        self.0.pc
    }

    pub fn set_pc(&mut self, pc: u32) {
        self.0.pc = pc;
    }

    pub fn set_register(&mut self, idx: usize, val: u64) {
        self.0.registers[idx] = val;
    }

    pub fn heap_top(&self) -> u32 {
        self.0.heap_top
    }

    pub fn set_heap_top(&mut self, top: u32) {
        self.0.heap_top = top;
    }

    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        self.0.read_u8(addr)
    }

    /// Returns `true` on success, `false` on page fault (matches real recompiler).
    pub fn write_byte(&mut self, addr: u32, value: u8) -> bool {
        self.0.write_u8(addr, value)
    }

    /// Returns `None` on page fault (matches real recompiler).
    pub fn read_bytes(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let a = addr as usize;
        let end = a + len as usize;
        self.0.flat_mem.get(a..end).map(|s| s.to_vec())
    }

    /// No native code on this platform — returns an empty slice.
    pub fn native_code_bytes(&self) -> &[u8] {
        &[]
    }

    /// Returns `true` on success, `false` on page fault (matches real recompiler).
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> bool {
        for (i, &byte) in data.iter().enumerate() {
            if !self.0.write_u8(addr.wrapping_add(i as u32), byte) {
                return false;
            }
        }
        true
    }
}
