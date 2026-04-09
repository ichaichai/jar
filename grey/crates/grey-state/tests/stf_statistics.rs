//! STF test vectors for statistics sub-transition (Section 13).

mod common;

use common::parse_extrinsic;
use grey_state::statistics;
use grey_types::state::{ValidatorRecord, ValidatorStatistics};
use std::collections::BTreeMap;

/// Parse ValidatorRecord from JSON.
fn validator_record_from_json(json: &serde_json::Value) -> ValidatorRecord {
    serde_json::from_value(json.clone()).expect("failed to parse ValidatorRecord")
}

/// Run a single statistics STF test vector.
fn run_statistics_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];

    // Parse input
    let new_slot = input["slot"].as_u64().unwrap() as u32;
    let author_index = input["author_index"].as_u64().unwrap() as u16;
    let extrinsic = parse_extrinsic(&input["extrinsic"]);

    // Parse pre-state
    let prior_slot = pre["slot"].as_u64().unwrap() as u32;
    let pre_curr: Vec<ValidatorRecord> = pre["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(validator_record_from_json)
        .collect();
    let pre_last: Vec<ValidatorRecord> = pre["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(validator_record_from_json)
        .collect();

    let mut stats = ValidatorStatistics {
        current: pre_curr,
        last: pre_last,
        core_stats: vec![],
        service_stats: BTreeMap::new(),
    };

    // Apply transition using tiny config
    let config = grey_types::config::Config::full();
    let incoming_reports: Vec<&grey_types::work::WorkReport> =
        extrinsic.guarantees.iter().map(|g| &g.report).collect();
    statistics::update_statistics(
        &config,
        &mut stats,
        prior_slot,
        new_slot,
        author_index,
        &extrinsic,
        &incoming_reports,
        &[],
        &std::collections::BTreeMap::new(),
    );

    // Parse expected post-state
    let expected_curr: Vec<ValidatorRecord> = post["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(validator_record_from_json)
        .collect();
    let expected_last: Vec<ValidatorRecord> = post["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(validator_record_from_json)
        .collect();

    // Compare
    assert_eq!(
        stats.current, expected_curr,
        "current stats mismatch in {}",
        path
    );
    assert_eq!(stats.last, expected_last, "last stats mismatch in {}", path);
}

const DIR: &str = "../../../spec/tests/vectors/statistics";

stf_test!(
    test_stf_statistics_empty_extrinsic,
    "stats_with_empty_extrinsic-1",
    DIR,
    run_statistics_test
);
stf_test!(
    test_stf_statistics_some_extrinsic,
    "stats_with_some_extrinsic-1",
    DIR,
    run_statistics_test
);
stf_test!(
    test_stf_statistics_epoch_change,
    "stats_with_epoch_change-1",
    DIR,
    run_statistics_test
);

discover_all_test!(DIR, run_statistics_test);
