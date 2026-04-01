//! Fuzz target: random bytes into Block decode.
//!
//! Verifies that decoding arbitrary bytes as a Block never panics.

#![no_main]

use grey_codec::DecodeWithConfig;
use grey_types::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = Config::tiny();
    let _ = grey_types::header::Block::decode_with_config(data, &config);

    let config_full = Config::full();
    let _ = grey_types::header::Block::decode_with_config(data, &config_full);
});
