use grey_bench::*;

fn main() {
    let blob = grey_fib_blob(grey_bench::FIB_N);
    let gas: u64 = i64::MAX as u64;
    let mut pvm = javm::program::initialize_program(&blob, &[], gas).unwrap();
    loop {
        let (exit, _) = pvm.run();
        match exit {
            javm::ExitReason::Halt | javm::ExitReason::Panic => break,
            javm::ExitReason::HostCall(_) => continue,
            _ => break,
        }
    }
    eprintln!("gas_used={}", gas - pvm.gas);
}
