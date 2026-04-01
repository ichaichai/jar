# Grey Fuzz Targets

Fuzz testing for the Grey protocol node using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Setup

```bash
cargo install cargo-fuzz
```

## Running

```bash
cd grey/fuzz

# Run a specific target (runs until interrupted with Ctrl-C)
cargo fuzz run fuzz_codec_decode

# Run for a fixed duration (e.g., 60 seconds)
cargo fuzz run fuzz_codec_decode -- -max_total_time=60

# Run with a specific number of iterations
cargo fuzz run fuzz_block_decode -- -runs=10000
```

## Targets

| Target | Description |
|--------|-------------|
| `fuzz_codec_decode` | Random bytes into Decode impls (Hash, Signature, Header, compact ints) |
| `fuzz_block_decode` | Random bytes into Block decode (tiny and full configs) |
| `fuzz_work_package_decode` | Random bytes into WorkPackage decode |

## Adding a New Target

1. Create `fuzz_targets/fuzz_my_target.rs`
2. Add a `[[bin]]` entry in `Cargo.toml`
3. Use `libfuzzer_sys::fuzz_target!` macro
