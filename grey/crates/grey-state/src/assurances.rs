//! Availability assurances sub-transition (Section 11.2, eq 11.10-11.17).
//!
//! Processes availability assurances to determine which pending work reports
//! have become available.

use grey_types::Hash;
use grey_types::config::Config;
use grey_types::header::Assurance;
use grey_types::state::PendingReport;
use grey_types::validator::ValidatorKey;
use grey_types::work::WorkReport;

stf_error! {
    /// Error type for assurances validation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AssuranceError {
        NotSortedOrUniqueAssurers => "not_sorted_or_unique_assurers",
        BadSignature => "bad_signature",
        BadValidatorIndex => "bad_validator_index",
        CoreNotEngaged => "core_not_engaged",
        BadAttestationParent => "bad_attestation_parent",
    }
}

/// Output of successful assurances processing.
#[derive(Debug, Clone)]
pub struct AssuranceOutput {
    /// Work reports that became available.
    pub reported: Vec<WorkReport>,
}

/// Apply the assurances sub-transition.
///
/// Returns the list of newly available work reports, or an error.
pub fn process_assurances(
    config: &Config,
    pending_reports: &mut [Option<PendingReport>],
    assurances: &[Assurance],
    current_timeslot: u32,
    parent_hash: Hash,
    current_validators: &[ValidatorKey],
) -> Result<AssuranceOutput, AssuranceError> {
    let super_majority = Config::super_majority_of(current_validators.len()) as u16;
    let num_cores = config.core_count as usize;

    // Validate validator indices (must be valid before other checks)
    for a in assurances {
        if a.validator_index as usize >= current_validators.len() {
            return Err(AssuranceError::BadValidatorIndex);
        }
    }

    // eq 11.12: Assurances must be sorted by validator index, no duplicates
    if !crate::is_strictly_sorted_by_key(assurances, |a| a.validator_index) {
        return Err(AssuranceError::NotSortedOrUniqueAssurers);
    }

    // eq 11.11: All assurance anchors must equal parent hash
    for a in assurances {
        if a.anchor != parent_hash {
            return Err(AssuranceError::BadAttestationParent);
        }
    }

    // eq 11.13: Verify signatures
    // Message: X_A ⌢ H(E(H_P, a_f))  where X_A = "jam_available"
    for a in assurances {
        let idx = a.validator_index as usize;
        let ed25519_key = &current_validators[idx].ed25519;

        // Encode (parent_hash, bitfield) and hash
        let message = grey_crypto::build_assurance_message(&parent_hash.0, &a.bitfield);
        if !grey_crypto::ed25519_verify(ed25519_key, &message, &a.signature) {
            return Err(AssuranceError::BadSignature);
        }
    }

    // eq 11.15: Bits may only be set for cores with pending reports
    for a in assurances {
        for core in 0..num_cores {
            if a.has_bit(core) && (core >= pending_reports.len() || pending_reports[core].is_none())
            {
                return Err(AssuranceError::CoreNotEngaged);
            }
        }
    }

    // eq 11.16: Count assurances per core, determine available reports
    let assurance_counts = crate::count_assurance_bits(assurances, num_cores);

    // eq 11.17: Collect available reports and clear available/timed-out slots
    let available = crate::collect_and_clear_available(
        pending_reports,
        &assurance_counts,
        super_majority as u32,
        current_timeslot,
        config.availability_timeout,
    );

    Ok(AssuranceOutput {
        reported: available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::config::Config;
    use grey_types::{Ed25519Signature, Hash};

    fn tiny_config_and_validators() -> (Config, Vec<ValidatorKey>) {
        let config = Config::tiny();
        // Create dummy validators (only ed25519 key matters for assurance checks)
        let validators: Vec<ValidatorKey> = (0..config.validators_count)
            .map(|_| ValidatorKey::default())
            .collect();
        (config, validators)
    }

    #[test]
    fn test_empty_assurances() {
        let (config, validators) = tiny_config_and_validators();
        let mut pending = vec![None; config.core_count as usize];
        let output = process_assurances(&config, &mut pending, &[], 1, Hash::ZERO, &validators)
            .expect("empty assurances should succeed");
        assert!(output.reported.is_empty());
    }

    #[test]
    fn test_bad_validator_index() {
        let (config, validators) = tiny_config_and_validators();
        let mut pending = vec![None; config.core_count as usize];
        let bad = Assurance {
            anchor: Hash::ZERO,
            bitfield: vec![0],
            validator_index: 999, // out of range
            signature: Ed25519Signature([0u8; 64]),
        };
        let result = process_assurances(&config, &mut pending, &[bad], 1, Hash::ZERO, &validators);
        assert!(matches!(result, Err(AssuranceError::BadValidatorIndex)));
    }

    #[test]
    fn test_not_sorted_assurers() {
        let (config, validators) = tiny_config_and_validators();
        let mut pending = vec![None; config.core_count as usize];
        // Two assurances with validator indices in wrong order
        let a1 = Assurance {
            anchor: Hash::ZERO,
            bitfield: vec![0],
            validator_index: 2,
            signature: Ed25519Signature([0u8; 64]),
        };
        let a2 = Assurance {
            anchor: Hash::ZERO,
            bitfield: vec![0],
            validator_index: 1, // out of order
            signature: Ed25519Signature([0u8; 64]),
        };
        let result =
            process_assurances(&config, &mut pending, &[a1, a2], 1, Hash::ZERO, &validators);
        assert!(matches!(
            result,
            Err(AssuranceError::NotSortedOrUniqueAssurers)
        ));
    }

    #[test]
    fn test_duplicate_assurers() {
        let (config, validators) = tiny_config_and_validators();
        let mut pending = vec![None; config.core_count as usize];
        let a = Assurance {
            anchor: Hash::ZERO,
            bitfield: vec![0],
            validator_index: 1,
            signature: Ed25519Signature([0u8; 64]),
        };
        let result = process_assurances(
            &config,
            &mut pending,
            &[a.clone(), a],
            1,
            Hash::ZERO,
            &validators,
        );
        assert!(matches!(
            result,
            Err(AssuranceError::NotSortedOrUniqueAssurers)
        ));
    }

    #[test]
    fn test_bad_attestation_parent() {
        let (config, validators) = tiny_config_and_validators();
        let mut pending = vec![None; config.core_count as usize];
        let a = Assurance {
            anchor: Hash([0xFF; 32]), // wrong parent
            bitfield: vec![0],
            validator_index: 0,
            signature: Ed25519Signature([0u8; 64]),
        };
        let result = process_assurances(
            &config,
            &mut pending,
            &[a],
            1,
            Hash::ZERO, // expected parent
            &validators,
        );
        assert!(matches!(result, Err(AssuranceError::BadAttestationParent)));
    }

    #[test]
    fn test_error_as_str() {
        assert_eq!(
            AssuranceError::NotSortedOrUniqueAssurers.as_str(),
            "not_sorted_or_unique_assurers"
        );
        assert_eq!(AssuranceError::BadSignature.as_str(), "bad_signature");
        assert_eq!(
            AssuranceError::BadValidatorIndex.as_str(),
            "bad_validator_index"
        );
        assert_eq!(AssuranceError::CoreNotEngaged.as_str(), "core_not_engaged");
        assert_eq!(
            AssuranceError::BadAttestationParent.as_str(),
            "bad_attestation_parent"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use grey_types::config::Config;
    use grey_types::validator::ValidatorKey;
    use grey_types::{Ed25519Signature, Hash};
    use proptest::prelude::*;

    fn tiny_config_and_validators() -> (Config, Vec<ValidatorKey>) {
        let config = Config::tiny();
        let validators: Vec<ValidatorKey> = (0..config.validators_count)
            .map(|_| ValidatorKey::default())
            .collect();
        (config, validators)
    }

    proptest! {
        /// Empty assurances always succeed regardless of state.
        #[test]
        fn empty_assurances_always_ok(
            timeslot in 0u32..1000,
            parent_hash in prop::array::uniform32(any::<u8>()).prop_map(Hash),
        ) {
            let (config, validators) = tiny_config_and_validators();
            let mut pending = vec![None; config.core_count as usize];
            let result = process_assurances(
                &config, &mut pending, &[], timeslot, parent_hash, &validators,
            );
            prop_assert!(result.is_ok());
            prop_assert!(result.unwrap().reported.is_empty());
        }

        /// Any assurance with validator_index >= validators.len() → BadValidatorIndex.
        #[test]
        fn bad_validator_index_rejected(
            bad_index in 6u16..1000, // V=6 for tiny
            parent_hash in prop::array::uniform32(any::<u8>()).prop_map(Hash),
        ) {
            let (config, validators) = tiny_config_and_validators();
            let mut pending = vec![None; config.core_count as usize];
            let a = Assurance {
                anchor: parent_hash,
                bitfield: vec![0],
                validator_index: bad_index,
                signature: Ed25519Signature([0u8; 64]),
            };
            let result = process_assurances(
                &config, &mut pending, &[a], 1, parent_hash, &validators,
            );
            prop_assert!(matches!(result, Err(AssuranceError::BadValidatorIndex)));
        }

        /// Unsorted validator indices → NotSortedOrUniqueAssurers.
        #[test]
        fn unsorted_assurances_rejected(
            higher in 1u16..6,
            lower in 0u16..5,
        ) {
            prop_assume!(higher > lower);
            let (config, validators) = tiny_config_and_validators();
            let mut pending = vec![None; config.core_count as usize];
            // Place higher index first → unsorted
            let assurances = vec![
                Assurance {
                    anchor: Hash::ZERO,
                    bitfield: vec![0],
                    validator_index: higher,
                    signature: Ed25519Signature([0u8; 64]),
                },
                Assurance {
                    anchor: Hash::ZERO,
                    bitfield: vec![0],
                    validator_index: lower,
                    signature: Ed25519Signature([0u8; 64]),
                },
            ];
            let result = process_assurances(
                &config, &mut pending, &assurances, 1, Hash::ZERO, &validators,
            );
            prop_assert!(matches!(result, Err(AssuranceError::NotSortedOrUniqueAssurers)));
        }

        /// Duplicate validator indices → NotSortedOrUniqueAssurers.
        #[test]
        fn duplicate_assurances_rejected(
            idx in 0u16..6,
        ) {
            let (config, validators) = tiny_config_and_validators();
            let mut pending = vec![None; config.core_count as usize];
            let a = Assurance {
                anchor: Hash::ZERO,
                bitfield: vec![0],
                validator_index: idx,
                signature: Ed25519Signature([0u8; 64]),
            };
            let result = process_assurances(
                &config, &mut pending, &[a.clone(), a], 1, Hash::ZERO, &validators,
            );
            prop_assert!(matches!(result, Err(AssuranceError::NotSortedOrUniqueAssurers)));
        }

        /// Wrong anchor hash → BadAttestationParent (when sorted and valid index).
        #[test]
        fn wrong_parent_rejected(
            parent_hash in prop::array::uniform32(any::<u8>()).prop_map(Hash),
            wrong_parent in prop::array::uniform32(any::<u8>()).prop_map(Hash),
        ) {
            prop_assume!(parent_hash != wrong_parent);
            let (config, validators) = tiny_config_and_validators();
            let mut pending = vec![None; config.core_count as usize];
            let a = Assurance {
                anchor: wrong_parent,
                bitfield: vec![0],
                validator_index: 0,
                signature: Ed25519Signature([0u8; 64]),
            };
            let result = process_assurances(
                &config, &mut pending, &[a], 1, parent_hash, &validators,
            );
            prop_assert!(matches!(result, Err(AssuranceError::BadAttestationParent)));
        }
    }
}
