//! Fuzz target: random bytes into WorkPackage decode.
//!
//! Verifies that decoding arbitrary bytes as a WorkPackage never panics.

#![no_main]

use grey_codec::Decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = grey_types::work::WorkPackage::decode(data);
});
