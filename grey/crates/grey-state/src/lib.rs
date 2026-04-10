//! Chain state and block-level state transitions (Sections 4-13).
//!
//! Implements the state transition function Υ(σ, B) → σ' (eq 4.1).

/// Define an STF error enum with an `as_str()` method for test-vector output.
///
/// Each variant maps to a snake_case string. Variants are listed once;
/// the macro generates both the enum and the `as_str()` match.
macro_rules! stf_error {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $variant:ident => $str:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $( $variant, )+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( Self::$variant => $str, )+
                }
            }
        }
    };
}

pub mod accumulate;
pub mod assurances;
pub mod authorizations;
pub mod disputes;
pub mod history;
pub mod preimages;
pub mod pvm_backend;
pub mod refine;
pub mod reports;
pub mod safrole;
pub mod statistics;
pub mod transition;

#[cfg(test)]
pub(crate) mod test_helpers {
    use grey_types::validator::ValidatorKey;
    use grey_types::{BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey, Hash};

    pub fn make_hash(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    pub fn make_validator(byte: u8) -> ValidatorKey {
        ValidatorKey {
            ed25519: Ed25519PublicKey([byte; 32]),
            bandersnatch: BandersnatchPublicKey([byte; 32]),
            bls: BlsPublicKey([byte; 144]),
            metadata: [byte; 128],
        }
    }

    pub fn make_validators(n: usize) -> Vec<ValidatorKey> {
        (0..n).map(|i| make_validator(i as u8)).collect()
    }
}

/// Count how many assurances have their bit set for each core.
///
/// Returns a vector of length `num_cores` where element `i` is the number of
/// assurances that have bit `i` set in their bitfield.
pub fn count_assurance_bits(
    assurances: &[grey_types::header::Assurance],
    num_cores: usize,
) -> Vec<u32> {
    let mut counts = vec![0u32; num_cores];
    for a in assurances {
        for (core, count) in counts.iter_mut().enumerate() {
            if a.has_bit(core) {
                *count += 1;
            }
        }
    }
    counts
}

/// Collect available work reports and clear resolved pending report slots.
///
/// A pending report is "available" if its assurance count meets the threshold.
/// A pending report is cleared if it is available OR timed out.
/// Returns the list of newly available work reports.
pub fn collect_and_clear_available(
    pending_reports: &mut [Option<grey_types::state::PendingReport>],
    assurance_counts: &[u32],
    threshold: u32,
    current_timeslot: grey_types::Timeslot,
    timeout: u32,
) -> Vec<grey_types::work::WorkReport> {
    let mut available = Vec::new();
    for (core, slot) in pending_reports.iter_mut().enumerate() {
        if let Some(pending) = slot {
            let is_available = assurance_counts.get(core).copied().unwrap_or(0) >= threshold;
            if is_available {
                available.push(pending.report.clone());
            }
            let is_timed_out = current_timeslot >= pending.timeslot + timeout;
            if is_available || is_timed_out {
                *slot = None;
            }
        }
    }
    available
}

/// Check that a slice is strictly sorted by the given key (no duplicates).
///
/// Returns `true` if `key(items[i]) < key(items[i+1])` for all consecutive pairs.
/// Empty and single-element slices are trivially sorted.
pub fn is_strictly_sorted_by_key<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|w| key(&w[0]) < key(&w[1]))
}

use grey_types::header::Block;
use grey_types::state::State;
use thiserror::Error;

/// Errors that can occur during block state transition.
#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("invalid parent hash: expected {expected}, got {got}")]
    InvalidParentHash {
        expected: grey_types::Hash,
        got: grey_types::Hash,
    },

    #[error("timeslot {block_slot} is not after prior timeslot {prior_slot}")]
    InvalidTimeslot {
        block_slot: grey_types::Timeslot,
        prior_slot: grey_types::Timeslot,
    },

    #[error("invalid block author index: {0}")]
    InvalidAuthorIndex(u16),

    #[error("invalid seal signature")]
    InvalidSeal,

    #[error("invalid extrinsic: {0}")]
    InvalidExtrinsic(String),
}

/// Apply a block to the current state, producing a new state (eq 4.1).
///
/// Υ(σ, B) → σ'
pub fn apply_block(state: &State, block: &Block) -> Result<State, TransitionError> {
    transition::apply(state, block)
}

#[cfg(test)]
mod proptests {
    use super::*;
    use grey_types::header::Assurance;
    use grey_types::state::PendingReport;
    use grey_types::work::WorkReport;
    use grey_types::{Ed25519Signature, Hash};
    use proptest::prelude::*;

    // --- is_strictly_sorted_by_key ---

    proptest! {
        /// Sorting and deduplicating always produces a strictly sorted sequence.
        #[test]
        fn sorted_deduped_is_strictly_sorted(mut values in proptest::collection::vec(any::<u32>(), 0..50)) {
            values.sort();
            values.dedup();
            prop_assert!(is_strictly_sorted_by_key(&values, |v| *v));
        }

        /// A sequence with adjacent duplicates is never strictly sorted (unless len ≤ 1).
        #[test]
        fn duplicates_are_not_strictly_sorted(
            prefix in proptest::collection::vec(any::<u32>(), 0..10),
            dup in any::<u32>(),
            suffix in proptest::collection::vec(any::<u32>(), 0..10),
        ) {
            let mut values = prefix;
            values.push(dup);
            values.push(dup);
            values.extend(suffix);
            prop_assert!(!is_strictly_sorted_by_key(&values, |v| *v));
        }

        /// Empty and single-element slices are trivially sorted.
        #[test]
        fn trivial_slices_are_sorted(value in any::<u32>()) {
            prop_assert!(is_strictly_sorted_by_key(&[] as &[u32], |v| *v));
            prop_assert!(is_strictly_sorted_by_key(&[value], |v| *v));
        }

        // --- count_assurance_bits ---

        /// Result length always equals num_cores.
        #[test]
        fn assurance_counts_length_matches_cores(
            num_assurances in 0usize..10,
            num_cores in 1usize..20,
        ) {
            // Build assurances with random-ish bitfields
            let assurances: Vec<Assurance> = (0..num_assurances)
                .map(|i| {
                    let bytes_needed = num_cores.div_ceil(8);
                    let bitfield = vec![0xFF; bytes_needed]; // all bits set
                    Assurance {
                        anchor: Hash::ZERO,
                        bitfield,
                        validator_index: i as u16,
                        signature: Ed25519Signature([0u8; 64]),
                    }
                })
                .collect();

            let counts = count_assurance_bits(&assurances, num_cores);
            prop_assert_eq!(counts.len(), num_cores);
        }

        /// Each count is at most the number of assurances.
        #[test]
        fn assurance_counts_bounded_by_assurance_count(
            num_assurances in 0usize..10,
            num_cores in 1usize..20,
        ) {
            let bytes_needed = num_cores.div_ceil(8);
            let assurances: Vec<Assurance> = (0..num_assurances)
                .map(|i| Assurance {
                    anchor: Hash::ZERO,
                    bitfield: vec![0xFF; bytes_needed],
                    validator_index: i as u16,
                    signature: Ed25519Signature([0u8; 64]),
                })
                .collect();

            let counts = count_assurance_bits(&assurances, num_cores);
            for (core, &count) in counts.iter().enumerate() {
                prop_assert!(
                    count <= num_assurances as u32,
                    "core {core}: count {count} > num_assurances {num_assurances}"
                );
            }
        }

        /// With all-zero bitfields, every count is zero.
        #[test]
        fn zero_bitfield_yields_zero_counts(
            num_assurances in 0usize..10,
            num_cores in 1usize..20,
        ) {
            let bytes_needed = num_cores.div_ceil(8);
            let assurances: Vec<Assurance> = (0..num_assurances)
                .map(|i| Assurance {
                    anchor: Hash::ZERO,
                    bitfield: vec![0x00; bytes_needed],
                    validator_index: i as u16,
                    signature: Ed25519Signature([0u8; 64]),
                })
                .collect();

            let counts = count_assurance_bits(&assurances, num_cores);
            for &count in counts.iter() {
                prop_assert_eq!(count, 0);
            }
        }

        // --- collect_and_clear_available ---

        /// Available reports are collected and their slots cleared.
        /// Returned count never exceeds the number of occupied slots.
        #[test]
        fn available_count_bounded_by_occupied(
            num_slots in 1usize..10,
            threshold in 0u32..5,
            current_timeslot in 0u32..1000,
            timeout in 1u32..100,
        ) {
            let occupied = num_slots; // all slots occupied
            let mut pending: Vec<Option<PendingReport>> = (0..num_slots)
                .map(|_| {
                    Some(PendingReport {
                        report: WorkReport::default(),
                        timeslot: current_timeslot,
                    })
                })
                .collect();

            // All counts at threshold → all available
            let counts = vec![threshold; num_slots];
            let available =
                collect_and_clear_available(&mut pending, &counts, threshold, current_timeslot, timeout);

            prop_assert!(
                available.len() <= occupied,
                "available {} > occupied {occupied}",
                available.len()
            );
        }

        /// After collect_and_clear_available, available slots are set to None.
        #[test]
        fn available_slots_cleared(
            num_slots in 1usize..10,
            current_timeslot in 100u32..1000,
            timeout in 1u32..50,
        ) {
            let threshold = 1u32;
            let mut pending: Vec<Option<PendingReport>> = (0..num_slots)
                .map(|_| {
                    Some(PendingReport {
                        report: WorkReport::default(),
                        timeslot: current_timeslot,
                    })
                })
                .collect();

            // counts all >= threshold → all available → all cleared
            let counts = vec![threshold; num_slots];
            let _ = collect_and_clear_available(&mut pending, &counts, threshold, current_timeslot, timeout);

            for (i, slot) in pending.iter().enumerate() {
                prop_assert!(slot.is_none(), "slot {i} should be cleared after being available");
            }
        }

        /// Timed-out slots are cleared even if not available.
        #[test]
        fn timed_out_slots_cleared(
            num_slots in 1usize..10,
            report_timeslot in 0u32..100,
            timeout in 1u32..50,
        ) {
            let threshold = 100u32; // unreachable threshold
            let current_timeslot = report_timeslot + timeout; // exactly at timeout
            let mut pending: Vec<Option<PendingReport>> = (0..num_slots)
                .map(|_| {
                    Some(PendingReport {
                        report: WorkReport::default(),
                        timeslot: report_timeslot,
                    })
                })
                .collect();

            let counts = vec![0u32; num_slots]; // no assurances → not available
            let available =
                collect_and_clear_available(&mut pending, &counts, threshold, current_timeslot, timeout);

            // Not available (threshold not met), but timed out → cleared, not returned
            prop_assert_eq!(available.len(), 0, "timed-out reports should not be returned as available");
            for (i, slot) in pending.iter().enumerate() {
                prop_assert!(slot.is_none(), "slot {i} should be cleared after timeout");
            }
        }
    }
}
