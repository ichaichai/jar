fn main() {
    // When cross-compiling for RISC-V (as the guest), don't recurse.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("riscv") {
        return;
    }

    let blob = build_javm::build(".", "javm-guest-tests");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/guest_blob.rs"),
        format!(
            "const GUEST_TESTS_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            blob.display(),
        ),
    )
    .unwrap();
}
