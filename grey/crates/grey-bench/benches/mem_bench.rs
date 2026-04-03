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

/// High gas limit — large working sets need many instructions.
const MEM_GAS: u64 = 10_000_000_000;

const SIZES: &[(&str, u32)] = &[
    ("4K", 4 * 1024),
    ("32K", 32 * 1024),
    ("256K", 256 * 1024),
    ("1M", 1024 * 1024),
    ("8M", 8 * 1024 * 1024),
    ("32M", 32 * 1024 * 1024),
    // 128M omitted: requires ~128MB contiguous allocation, may OOM in constrained environments
];

fn bench_mem_seq(c: &mut Criterion) {
    for &(label, size) in SIZES {
        let blob = grey_mem_seq_blob(size);

        let mut group = c.benchmark_group(format!("mem_seq/{label}"));
        group.bench_function("grey-recompiler-exec", |b| {
            b.iter_batched(
                || javm::recompiler::initialize_program_recompiled(&blob, &[], MEM_GAS).unwrap(),
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
        group.bench_function("grey-recompiler-exec", |b| {
            b.iter_batched(
                || javm::recompiler::initialize_program_recompiled(&blob, &[], MEM_GAS).unwrap(),
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
