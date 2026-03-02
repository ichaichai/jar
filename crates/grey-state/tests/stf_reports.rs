//! STF test vectors for reports (guarantees) sub-transition (Section 11).

use grey_state::reports::{
    process_reports, AvailAssignment, CoreStats, GuaranteeInput, RecentBlockEntry, ReportsState,
    ServiceInfo, ServiceStats,
};
use grey_types::config::Config;
use grey_types::validator::ValidatorKey;
use grey_types::work::{AvailabilitySpec, RefinementContext, WorkDigest, WorkReport, WorkResult};
use grey_types::{
    BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey, Ed25519Signature, Hash, ServiceId,
};
use std::collections::{BTreeMap, BTreeSet};

fn hash_from_hex(s: &str) -> Hash {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex");
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn ed25519_from_hex(s: &str) -> Ed25519PublicKey {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex");
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ed25519PublicKey(k)
}

fn sig_from_hex(s: &str) -> Ed25519Signature {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex");
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Ed25519Signature(sig)
}

fn parse_validator(v: &serde_json::Value) -> ValidatorKey {
    let bandersnatch_bytes =
        hex::decode(v["bandersnatch"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
    let mut bandersnatch = [0u8; 32];
    bandersnatch.copy_from_slice(&bandersnatch_bytes);

    let ed25519 = ed25519_from_hex(v["ed25519"].as_str().unwrap());

    let bls_bytes =
        hex::decode(v["bls"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
    let mut bls = [0u8; 144];
    bls.copy_from_slice(&bls_bytes);

    let metadata_bytes =
        hex::decode(v["metadata"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
    let mut metadata = [0u8; 128];
    metadata.copy_from_slice(&metadata_bytes);

    ValidatorKey {
        bandersnatch: BandersnatchPublicKey(bandersnatch),
        ed25519,
        bls: BlsPublicKey(bls),
        metadata,
    }
}

fn parse_work_result(r: &serde_json::Value) -> WorkResult {
    if let Some(ok_val) = r.get("ok") {
        let data_hex = ok_val.as_str().unwrap();
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap();
        WorkResult::Ok(data)
    } else if r.get("out_of_gas").is_some() {
        WorkResult::OutOfGas
    } else if r.get("panic").is_some() {
        WorkResult::Panic
    } else if r.get("bad_exports").is_some() {
        WorkResult::BadExports
    } else if r.get("bad_code").is_some() {
        WorkResult::BadCode
    } else if r.get("code_oversize").is_some() {
        WorkResult::CodeOversize
    } else {
        panic!("Unknown work result: {:?}", r);
    }
}

fn parse_work_report(r: &serde_json::Value) -> WorkReport {
    let ps = &r["package_spec"];
    let package_spec = AvailabilitySpec {
        package_hash: hash_from_hex(ps["hash"].as_str().unwrap()),
        bundle_length: ps["length"].as_u64().unwrap() as u32,
        erasure_root: hash_from_hex(ps["erasure_root"].as_str().unwrap()),
        exports_root: hash_from_hex(ps["exports_root"].as_str().unwrap()),
        exports_count: ps["exports_count"].as_u64().unwrap() as u16,
    };

    let ctx = &r["context"];
    let context = RefinementContext {
        anchor: hash_from_hex(ctx["anchor"].as_str().unwrap()),
        state_root: hash_from_hex(ctx["state_root"].as_str().unwrap()),
        beefy_root: hash_from_hex(ctx["beefy_root"].as_str().unwrap()),
        lookup_anchor: hash_from_hex(ctx["lookup_anchor"].as_str().unwrap()),
        lookup_anchor_timeslot: ctx["lookup_anchor_slot"].as_u64().unwrap() as u32,
        prerequisites: ctx["prerequisites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hash_from_hex(h.as_str().unwrap()))
            .collect(),
    };

    let mut segment_root_lookup = BTreeMap::new();
    for entry in r["segment_root_lookup"].as_array().unwrap() {
        let pkg_hash = hash_from_hex(entry["work_package_hash"].as_str().unwrap());
        let seg_root = hash_from_hex(entry["segment_tree_root"].as_str().unwrap());
        segment_root_lookup.insert(pkg_hash, seg_root);
    }

    let results: Vec<WorkDigest> = r["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let refine = &d["refine_load"];
            WorkDigest {
                service_id: d["service_id"].as_u64().unwrap() as ServiceId,
                code_hash: hash_from_hex(d["code_hash"].as_str().unwrap()),
                payload_hash: hash_from_hex(d["payload_hash"].as_str().unwrap()),
                accumulate_gas: d["accumulate_gas"].as_u64().unwrap(),
                result: parse_work_result(&d["result"]),
                gas_used: refine["gas_used"].as_u64().unwrap(),
                imports_count: refine["imports"].as_u64().unwrap() as u16,
                extrinsics_count: refine["extrinsic_count"].as_u64().unwrap() as u16,
                extrinsics_size: refine["extrinsic_size"].as_u64().unwrap() as u32,
                exports_count: refine["exports"].as_u64().unwrap() as u16,
            }
        })
        .collect();

    WorkReport {
        package_spec,
        context,
        core_index: r["core_index"].as_u64().unwrap() as u16,
        authorizer_hash: hash_from_hex(r["authorizer_hash"].as_str().unwrap()),
        auth_gas_used: r["auth_gas_used"].as_u64().unwrap(),
        auth_output: hex::decode(
            r["auth_output"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap_or(""),
        )
        .unwrap_or_default(),
        segment_root_lookup,
        results,
    }
}

fn parse_avail_assignment(v: &serde_json::Value) -> Option<AvailAssignment> {
    if v.is_null() {
        None
    } else {
        Some(AvailAssignment {
            report: parse_work_report(&v["report"]),
            timeout: v["timeout"].as_u64().unwrap() as u32,
        })
    }
}

fn parse_recent_block(b: &serde_json::Value) -> RecentBlockEntry {
    RecentBlockEntry {
        header_hash: hash_from_hex(b["header_hash"].as_str().unwrap()),
        state_root: hash_from_hex(b["state_root"].as_str().unwrap()),
        beefy_root: hash_from_hex(b["beefy_root"].as_str().unwrap()),
        reported: b["reported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    hash_from_hex(r["hash"].as_str().unwrap()),
                    hash_from_hex(r["exports_root"].as_str().unwrap()),
                )
            })
            .collect(),
    }
}

fn parse_core_stats(v: &serde_json::Value) -> CoreStats {
    CoreStats {
        da_load: v["da_load"].as_u64().unwrap(),
        popularity: v["popularity"].as_u64().unwrap(),
        imports: v["imports"].as_u64().unwrap(),
        extrinsic_count: v["extrinsic_count"].as_u64().unwrap(),
        extrinsic_size: v["extrinsic_size"].as_u64().unwrap(),
        exports: v["exports"].as_u64().unwrap(),
        bundle_size: v["bundle_size"].as_u64().unwrap(),
        gas_used: v["gas_used"].as_u64().unwrap(),
    }
}

fn parse_service_stats(v: &serde_json::Value) -> ServiceStats {
    ServiceStats {
        provided_count: v["provided_count"].as_u64().unwrap() as u32,
        provided_size: v["provided_size"].as_u64().unwrap(),
        refinement_count: v["refinement_count"].as_u64().unwrap() as u32,
        refinement_gas_used: v["refinement_gas_used"].as_u64().unwrap(),
        imports: v["imports"].as_u64().unwrap(),
        extrinsic_count: v["extrinsic_count"].as_u64().unwrap(),
        extrinsic_size: v["extrinsic_size"].as_u64().unwrap(),
        exports: v["exports"].as_u64().unwrap(),
        accumulate_count: v["accumulate_count"].as_u64().unwrap() as u32,
        accumulate_gas_used: v["accumulate_gas_used"].as_u64().unwrap(),
    }
}

fn run_reports_test(path: &str) {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("failed to read {}", path));
    let json: serde_json::Value =
        serde_json::from_str(&content).unwrap_or_else(|_| panic!("failed to parse {}", path));

    let input_json = &json["input"];
    let pre = &json["pre_state"];
    let output = &json["output"];
    let post = &json["post_state"];

    // Parse input
    let current_slot = input_json["slot"].as_u64().unwrap() as u32;

    let known_packages: BTreeSet<Hash> = input_json["known_packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hash_from_hex(h.as_str().unwrap()))
        .collect();

    let guarantees: Vec<GuaranteeInput> = input_json["guarantees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            let report = parse_work_report(&g["report"]);
            let slot = g["slot"].as_u64().unwrap() as u32;
            let signatures: Vec<(u16, Ed25519Signature)> = g["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    (
                        s["validator_index"].as_u64().unwrap() as u16,
                        sig_from_hex(s["signature"].as_str().unwrap()),
                    )
                })
                .collect();
            GuaranteeInput {
                report,
                slot,
                signatures,
            }
        })
        .collect();

    // Parse pre-state
    let avail_assignments: Vec<Option<AvailAssignment>> = pre["avail_assignments"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_avail_assignment)
        .collect();

    let curr_validators: Vec<ValidatorKey> = pre["curr_validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_validator)
        .collect();

    let prev_validators: Vec<ValidatorKey> = pre["prev_validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_validator)
        .collect();

    let entropy_arr = pre["entropy"].as_array().unwrap();
    let entropy: [Hash; 4] = [
        hash_from_hex(entropy_arr[0].as_str().unwrap()),
        hash_from_hex(entropy_arr[1].as_str().unwrap()),
        hash_from_hex(entropy_arr[2].as_str().unwrap()),
        hash_from_hex(entropy_arr[3].as_str().unwrap()),
    ];

    let offenders: BTreeSet<Ed25519PublicKey> = pre["offenders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| ed25519_from_hex(h.as_str().unwrap()))
        .collect();

    let recent_blocks: Vec<RecentBlockEntry> = pre["recent_blocks"]["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_recent_block)
        .collect();

    let auth_pools: Vec<Vec<Hash>> = pre["auth_pools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pool| {
            pool.as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect()
        })
        .collect();

    let accounts: BTreeMap<ServiceId, ServiceInfo> = pre["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let id = a["id"].as_u64().unwrap() as ServiceId;
            let svc = &a["data"]["service"];
            let info = ServiceInfo {
                code_hash: hash_from_hex(svc["code_hash"].as_str().unwrap()),
                min_item_gas: svc["min_item_gas"].as_u64().unwrap(),
            };
            (id, info)
        })
        .collect();

    let cores_statistics: Vec<CoreStats> = pre["cores_statistics"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_core_stats)
        .collect();

    let mut services_statistics: BTreeMap<ServiceId, ServiceStats> = pre["services_statistics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let id = s["id"].as_u64().unwrap() as ServiceId;
            (id, parse_service_stats(&s["record"]))
        })
        .collect();

    let mut state = ReportsState {
        avail_assignments,
        curr_validators,
        prev_validators,
        entropy,
        offenders,
        recent_blocks,
        auth_pools,
        accounts,
        cores_statistics,
        services_statistics: services_statistics.clone(),
    };

    let config = Config::tiny();
    let result = process_reports(&config, &mut state, &guarantees, current_slot, &known_packages);

    // Check output
    if let Some(err_str) = output.get("err") {
        let err_str = err_str.as_str().unwrap();
        match result {
            Ok(_) => panic!("{}: expected error '{}', got Ok", path, err_str),
            Err(e) => {
                assert_eq!(
                    e.as_str(),
                    err_str,
                    "{}: error mismatch: got '{}', expected '{}'",
                    path,
                    e.as_str(),
                    err_str
                );
            }
        }
    } else {
        let ok_output = &output["ok"];
        let result = result.unwrap_or_else(|e| {
            panic!("{}: expected Ok, got Err({:?})", path, e);
        });

        // Check reported packages
        let expected_reported: Vec<(Hash, Hash)> = ok_output["reported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    hash_from_hex(r["work_package_hash"].as_str().unwrap()),
                    hash_from_hex(r["segment_tree_root"].as_str().unwrap()),
                )
            })
            .collect();

        assert_eq!(
            result.reported.len(),
            expected_reported.len(),
            "{}: reported count mismatch",
            path
        );
        for (i, (got, exp)) in result
            .reported
            .iter()
            .zip(expected_reported.iter())
            .enumerate()
        {
            assert_eq!(
                got.work_package_hash, exp.0,
                "{}: reported[{}] work_package_hash mismatch",
                path, i
            );
            assert_eq!(
                got.segment_tree_root, exp.1,
                "{}: reported[{}] segment_tree_root mismatch",
                path, i
            );
        }

        // Check reporters
        let mut expected_reporters: Vec<Ed25519PublicKey> = ok_output["reporters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| ed25519_from_hex(h.as_str().unwrap()))
            .collect();
        expected_reporters.sort();

        let mut got_reporters = result.reporters.clone();
        got_reporters.sort();

        assert_eq!(
            got_reporters, expected_reporters,
            "{}: reporters mismatch",
            path
        );

        // Check post_state avail_assignments
        let expected_avail: Vec<Option<u32>> = post["avail_assignments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                if v.is_null() {
                    None
                } else {
                    Some(v["timeout"].as_u64().unwrap() as u32)
                }
            })
            .collect();

        for (i, exp) in expected_avail.iter().enumerate() {
            match (exp, &state.avail_assignments[i]) {
                (None, None) => {}
                (Some(exp_timeout), Some(got)) => {
                    assert_eq!(
                        got.timeout, *exp_timeout,
                        "{}: avail_assignments[{}] timeout mismatch",
                        path, i
                    );
                }
                (None, Some(_)) => {
                    panic!(
                        "{}: avail_assignments[{}] expected None, got Some",
                        path, i
                    );
                }
                (Some(_), None) => {
                    panic!(
                        "{}: avail_assignments[{}] expected Some, got None",
                        path, i
                    );
                }
            }
        }

        // Check post_state cores_statistics
        let expected_cores_stats: Vec<CoreStats> = post["cores_statistics"]
            .as_array()
            .unwrap()
            .iter()
            .map(parse_core_stats)
            .collect();

        for (i, (got, exp)) in state
            .cores_statistics
            .iter()
            .zip(expected_cores_stats.iter())
            .enumerate()
        {
            assert_eq!(
                got, exp,
                "{}: cores_statistics[{}] mismatch",
                path, i
            );
        }

        // Check post_state services_statistics
        let expected_svc_stats: BTreeMap<ServiceId, ServiceStats> = post["services_statistics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let id = s["id"].as_u64().unwrap() as ServiceId;
                (id, parse_service_stats(&s["record"]))
            })
            .collect();

        assert_eq!(
            state.services_statistics, expected_svc_stats,
            "{}: services_statistics mismatch",
            path
        );
    }
}

macro_rules! report_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_reports_test(&format!(
                "../../res/testvectors/stf/reports/tiny/{}",
                $file
            ));
        }
    };
}

report_test!(test_anchor_not_recent, "anchor_not_recent-1.json");
report_test!(test_bad_beefy_mmr, "bad_beefy_mmr-1.json");
report_test!(test_bad_code_hash, "bad_code_hash-1.json");
report_test!(test_bad_core_index, "bad_core_index-1.json");
report_test!(test_bad_service_id, "bad_service_id-1.json");
report_test!(test_bad_signature, "bad_signature-1.json");
report_test!(test_bad_state_root, "bad_state_root-1.json");
report_test!(test_bad_validator_index, "bad_validator_index-1.json");
report_test!(test_banned_validator, "banned_validator_guarantee-1.json");
report_test!(test_big_work_report_output, "big_work_report_output-1.json");
report_test!(test_core_engaged, "core_engaged-1.json");
report_test!(test_dependency_missing, "dependency_missing-1.json");
report_test!(
    test_different_core_same_guarantors,
    "different_core_same_guarantors-1.json"
);
report_test!(
    test_duplicate_package_in_recent_history,
    "duplicate_package_in_recent_history-1.json"
);
report_test!(
    test_duplicated_package_in_report,
    "duplicated_package_in_report-1.json"
);
report_test!(test_future_report_slot, "future_report_slot-1.json");
report_test!(test_high_work_report_gas, "high_work_report_gas-1.json");
report_test!(test_many_dependencies, "many_dependencies-1.json");
report_test!(test_multiple_reports, "multiple_reports-1.json");
report_test!(test_no_enough_guarantees, "no_enough_guarantees-1.json");
report_test!(test_not_authorized, "not_authorized-1.json");
report_test!(test_not_authorized_2, "not_authorized-2.json");
report_test!(test_not_sorted_guarantor, "not_sorted_guarantor-1.json");
report_test!(
    test_out_of_order_guarantees,
    "out_of_order_guarantees-1.json"
);
report_test!(
    test_report_before_last_rotation,
    "report_before_last_rotation-1.json"
);
report_test!(test_report_curr_rotation, "report_curr_rotation-1.json");
report_test!(test_report_prev_rotation, "report_prev_rotation-1.json");
report_test!(
    test_report_with_no_results,
    "report_with_no_results-1.json"
);
report_test!(
    test_reports_with_dependencies_1,
    "reports_with_dependencies-1.json"
);
report_test!(
    test_reports_with_dependencies_2,
    "reports_with_dependencies-2.json"
);
report_test!(
    test_reports_with_dependencies_3,
    "reports_with_dependencies-3.json"
);
report_test!(
    test_reports_with_dependencies_4,
    "reports_with_dependencies-4.json"
);
report_test!(
    test_reports_with_dependencies_5,
    "reports_with_dependencies-5.json"
);
report_test!(
    test_reports_with_dependencies_6,
    "reports_with_dependencies-6.json"
);
report_test!(
    test_segment_root_lookup_invalid_1,
    "segment_root_lookup_invalid-1.json"
);
report_test!(
    test_segment_root_lookup_invalid_2,
    "segment_root_lookup_invalid-2.json"
);
report_test!(
    test_service_item_gas_too_low,
    "service_item_gas_too_low-1.json"
);
report_test!(
    test_too_big_work_report_output,
    "too_big_work_report_output-1.json"
);
report_test!(
    test_too_high_work_report_gas,
    "too_high_work_report_gas-1.json"
);
report_test!(test_too_many_dependencies, "too_many_dependencies-1.json");
report_test!(
    test_with_avail_assignments,
    "with_avail_assignments-1.json"
);
report_test!(test_wrong_assignment, "wrong_assignment-1.json");
