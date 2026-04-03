//! Memory cache pressure benchmark.
//!
//! Measures how PVM load instruction throughput degrades as the working set
//! grows beyond L1 → L2 → L3 → DRAM. Two access patterns:
//!   - `mem_seq`: sequential sweep (prefetch-friendly, best case)
//!   - `mem_rand`: pseudo-random xorshift stride (cache-hostile, worst case)
//!
//! Run: `cargo bench -p grey-bench --features javm/signals -- 'mem_seq/|mem_rand/'`

use criterion::{Criterion, criterion_group, criterion_main};
use grey_bench::mem::*;

/// Compute gas limit proportional to working set size.
/// Each u32 element needs ~10 gas per load (BB overhead + instruction cost),
/// times 15 sweeps, plus init overhead.
fn gas_for_size(size_bytes: u32) -> u64 {
    let n_elems = size_bytes as u64 / 4;
    let loads = n_elems * 15; // SWEEPS
    loads * 100 + 10_000_000 // generous: ~100 gas per load iteration in BB model
}

const SIZES: &[(&str, u32)] = &[
    ("4K", 4 * 1024),
    ("32K", 32 * 1024),
    ("256K", 256 * 1024),
    ("1M", 1024 * 1024),
    ("8M", 8 * 1024 * 1024),
    ("32M", 32 * 1024 * 1024),
    ("128M", 128 * 1024 * 1024),
    ("256M", 65535 * 4096), // max heap: u16::MAX pages × 4096 ≈ 256MB
];

fn bench_mem_seq(c: &mut Criterion) {
    for &(label, size) in SIZES {
        let blob = grey_mem_seq_blob(size);

        let mut group = c.benchmark_group(format!("mem_seq/{label}"));
        if size >= 8 * 1024 * 1024 {
            group.sample_size(10);
        }
        group.bench_function("grey-recompiler-exec", |b| {
            b.iter_batched(
                || {
                    javm::recompiler::initialize_program_recompiled(&blob, &[], gas_for_size(size))
                        .unwrap()
                },
                |mut pvm| {
                    loop {
                        match pvm.run() {
                            javm::ExitReason::Halt => break,
                            javm::ExitReason::HostCall(_) => continue,
                            other => panic!("unexpected exit: {:?}", other),
                        }
                    }
                    pvm.registers()[7]
                },
                criterion::BatchSize::LargeInput,
            );
        });
        group.finish();
    }
}

fn bench_mem_rand(c: &mut Criterion) {
    for &(label, size) in SIZES {
        let blob = grey_mem_rand_blob(size);

        let mut group = c.benchmark_group(format!("mem_rand/{label}"));
        if size >= 8 * 1024 * 1024 {
            group.sample_size(10);
        }
        group.bench_function("grey-recompiler-exec", |b| {
            b.iter_batched(
                || {
                    javm::recompiler::initialize_program_recompiled(&blob, &[], gas_for_size(size))
                        .unwrap()
                },
                |mut pvm| {
                    loop {
                        match pvm.run() {
                            javm::ExitReason::Halt => break,
                            javm::ExitReason::HostCall(_) => continue,
                            other => panic!("unexpected exit: {:?}", other),
                        }
                    }
                    pvm.registers()[7]
                },
                criterion::BatchSize::LargeInput,
            );
        });
        group.finish();
    }
}

criterion_group!(mem_benches, bench_mem_seq, bench_mem_rand);
criterion_main!(mem_benches);
