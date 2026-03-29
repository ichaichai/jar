//! Pixels authorizer — ed25519 signature verification for work packages.
//!
//! Runs in Ψ_I (Is-Authorized) at PC=0.
//!
//! Receives: `auth_token ++ encoded_work_package` as argument.
//! auth_token = pubkey(32) + signature(64) = 96 bytes.
//! The signature covers the encoded work package bytes.
//!
//! Halts on success (valid signature), panics on failure.

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;
    use ed25519_compact::{PublicKey, Signature};

    // Entry point: _start jumps to authorize_impl.
    // PVM sets a0 = arg_ptr, a1 = arg_len before execution.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "j authorize_impl",
    );

    /// Authorize a work package by verifying an ed25519 signature.
    #[no_mangle]
    extern "C" fn authorize_impl(arg_ptr: *const u8, arg_len: usize) {
        if arg_ptr.is_null() || arg_len < 97 {
            panic_trap();
        }

        unsafe {
            let pk_bytes = core::slice::from_raw_parts(arg_ptr, 32);
            let pk = match PublicKey::from_slice(pk_bytes) {
                Ok(pk) => pk,
                Err(_) => panic_trap(),
            };

            let sig_bytes = core::slice::from_raw_parts(arg_ptr.add(32), 64);
            let sig = match Signature::from_slice(sig_bytes) {
                Ok(sig) => sig,
                Err(_) => panic_trap(),
            };

            let msg = core::slice::from_raw_parts(arg_ptr.add(96), arg_len - 96);

            match pk.verify(msg, &sig) {
                Ok(_) => {}
                Err(_) => panic_trap(),
            }
        }
    }

    #[inline(never)]
    fn panic_trap() -> ! {
        unsafe {
            core::arch::asm!("unimp", options(noreturn));
        }
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        unsafe {
            core::arch::asm!("unimp", options(noreturn));
        }
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
