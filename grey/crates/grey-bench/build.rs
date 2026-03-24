fn main() {
    let javm_blob = build_javm::build("../../services/bench-ecrecover", "bench-ecrecover");
    let pvm_blob = build_pvm::build("../../services/bench-ecrecover");
    let service_blob =
        build_javm::build_service("../../services/sample-service", "sample-service");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/guest_blobs.rs"),
        format!(
            "const GREY_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const SAMPLE_SERVICE_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            javm_blob.display(),
            pvm_blob.display(),
            service_blob.display(),
        ),
    )
    .unwrap();
}
