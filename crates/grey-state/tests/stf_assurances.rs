//! STF test vectors for assurances sub-transition (Section 11.2).

use grey_state::assurances::process_assurances;
use grey_types::config::Config;
use grey_types::header::Assurance;
use grey_types::state::PendingReport;
use grey_types::validator::ValidatorKey;
use grey_types::work::*;
use grey_types::{Ed25519Signature, Hash};

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex")
}

fn hash_from_hex(s: &str) -> Hash {
    let bytes = decode_hex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn sig64_from_hex(s: &str) -> Ed25519Signature {
    let bytes = decode_hex(s);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Ed25519Signature(sig)
}

fn parse_work_report(json: &serde_json::Value) -> WorkReport {
    let ps = &json["package_spec"];
    let ctx = &json["context"];

    WorkReport {
        package_spec: AvailabilitySpec {
            package_hash: hash_from_hex(ps["hash"].as_str().unwrap()),
            bundle_length: ps["length"].as_u64().unwrap() as u32,
            erasure_root: hash_from_hex(ps["erasure_root"].as_str().unwrap()),
            exports_root: hash_from_hex(ps["exports_root"].as_str().unwrap()),
            exports_count: ps["exports_count"].as_u64().unwrap() as u16,
        },
        context: RefinementContext {
            anchor: hash_from_hex(ctx["anchor"].as_str().unwrap()),
            state_root: hash_from_hex(ctx["state_root"].as_str().unwrap()),
            beefy_root: hash_from_hex(ctx["beefy_root"].as_str().unwrap()),
            lookup_anchor: hash_from_hex(ctx["lookup_anchor"].as_str().unwrap()),
            lookup_anchor_timeslot: ctx["lookup_anchor_slot"].as_u64().unwrap() as u32,
            prerequisites: ctx["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hash_from_hex(v.as_str().unwrap()))
                .collect(),
        },
        core_index: json["core_index"].as_u64().unwrap() as u16,
        authorizer_hash: hash_from_hex(json["authorizer_hash"].as_str().unwrap()),
        auth_gas_used: json["auth_gas_used"].as_u64().unwrap(),
        auth_output: decode_hex(json["auth_output"].as_str().unwrap()),
        segment_root_lookup: json["segment_root_lookup"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    hash_from_hex(item["work_package_hash"].as_str().unwrap()),
                    hash_from_hex(item["segment_tree_root"].as_str().unwrap()),
                )
            })
            .collect(),
        results: json["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let result = &r["result"];
                let work_result = if let Some(data) = result.get("ok") {
                    WorkResult::Ok(decode_hex(data.as_str().unwrap()))
                } else if result.get("out_of_gas").is_some() {
                    WorkResult::OutOfGas
                } else if result.get("panic").is_some() {
                    WorkResult::Panic
                } else {
                    WorkResult::Panic
                };

                let rl = &r["refine_load"];
                WorkDigest {
                    service_id: r["service_id"].as_u64().unwrap() as u32,
                    code_hash: hash_from_hex(r["code_hash"].as_str().unwrap()),
                    payload_hash: hash_from_hex(r["payload_hash"].as_str().unwrap()),
                    accumulate_gas: r["accumulate_gas"].as_u64().unwrap(),
                    result: work_result,
                    gas_used: rl["gas_used"].as_u64().unwrap(),
                    imports_count: rl["imports"].as_u64().unwrap() as u16,
                    extrinsics_count: rl["extrinsic_count"].as_u64().unwrap() as u16,
                    extrinsics_size: rl["extrinsic_size"].as_u64().unwrap() as u32,
                    exports_count: rl["exports"].as_u64().unwrap() as u16,
                }
            })
            .collect(),
    }
}

fn parse_pending_reports(json: &serde_json::Value) -> Vec<Option<PendingReport>> {
    json.as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if v.is_null() {
                None
            } else {
                Some(PendingReport {
                    report: parse_work_report(&v["report"]),
                    timeslot: v["timeout"].as_u64().unwrap() as u32,
                })
            }
        })
        .collect()
}

fn run_assurances_test(path: &str) {
    let content = std::fs::read_to_string(path).expect("failed to read test vector");
    let json: serde_json::Value = serde_json::from_str(&content).expect("failed to parse JSON");

    let input = &json["input"];
    let pre = &json["pre_state"];
    let output = &json["output"];

    // Parse input
    let assurances: Vec<Assurance> = input["assurances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| Assurance {
            anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
            bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
            validator_index: a["validator_index"].as_u64().unwrap() as u16,
            signature: sig64_from_hex(a["signature"].as_str().unwrap()),
        })
        .collect();

    let current_timeslot = input["slot"].as_u64().unwrap() as u32;
    let parent_hash = hash_from_hex(input["parent"].as_str().unwrap());

    // Parse pre-state
    let mut pending_reports = parse_pending_reports(&pre["avail_assignments"]);
    let current_validators: Vec<ValidatorKey> = pre["curr_validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("failed to parse ValidatorKey"))
        .collect();

    let config = Config::tiny();

    // Apply transition
    let result = process_assurances(
        &config,
        &mut pending_reports,
        &assurances,
        current_timeslot,
        parent_hash,
        &current_validators,
    );

    // Check output
    if let Some(err_val) = output.get("err") {
        let expected_err = err_val.as_str().unwrap();
        match result {
            Err(e) => assert_eq!(
                e.as_str(),
                expected_err,
                "wrong error in {}: got {:?}",
                path,
                e
            ),
            Ok(_) => panic!("expected error '{}' but got Ok in {}", expected_err, path),
        }
    } else if let Some(ok_val) = output.get("ok") {
        match result {
            Ok(assurance_output) => {
                let expected_reported_count = ok_val["reported"].as_array().unwrap().len();
                assert_eq!(
                    assurance_output.reported.len(),
                    expected_reported_count,
                    "reported count mismatch in {}",
                    path
                );

                // Verify post-state pending reports
                let expected_pending = parse_pending_reports(&json["post_state"]["avail_assignments"]);
                assert_eq!(
                    pending_reports.len(),
                    expected_pending.len(),
                    "pending reports length mismatch in {}",
                    path
                );
                for (i, (got, exp)) in pending_reports
                    .iter()
                    .zip(expected_pending.iter())
                    .enumerate()
                {
                    match (got, exp) {
                        (None, None) => {}
                        (Some(g), Some(e)) => {
                            assert_eq!(
                                g.report.core_index, e.report.core_index,
                                "core_index mismatch at {} in {}",
                                i, path
                            );
                        }
                        _ => panic!(
                            "pending report mismatch at core {} in {}: got {:?}, expected {:?}",
                            i,
                            path,
                            got.is_some(),
                            exp.is_some()
                        ),
                    }
                }
            }
            Err(e) => panic!("expected Ok but got error {:?} in {}", e, path),
        }
    }
}

#[test]
fn test_assurances_no_assurances() {
    run_assurances_test("../../res/testvectors/stf/assurances/tiny/no_assurances-1.json");
}

#[test]
fn test_assurances_some() {
    run_assurances_test("../../res/testvectors/stf/assurances/tiny/some_assurances-1.json");
}

#[test]
fn test_assurances_stale_report() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/no_assurances_with_stale_report-1.json",
    );
}

#[test]
fn test_assurances_for_stale() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurances_for_stale_report-1.json",
    );
}

#[test]
fn test_assurances_bad_signature() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurances_with_bad_signature-1.json",
    );
}

#[test]
fn test_assurances_bad_validator_index() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurances_with_bad_validator_index-1.json",
    );
}

#[test]
fn test_assurances_not_engaged_core() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurance_for_not_engaged_core-1.json",
    );
}

#[test]
fn test_assurances_bad_attestation_parent() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurance_with_bad_attestation_parent-1.json",
    );
}

#[test]
fn test_assurances_not_sorted_1() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurers_not_sorted_or_unique-1.json",
    );
}

#[test]
fn test_assurances_not_sorted_2() {
    run_assurances_test(
        "../../res/testvectors/stf/assurances/tiny/assurers_not_sorted_or_unique-2.json",
    );
}
