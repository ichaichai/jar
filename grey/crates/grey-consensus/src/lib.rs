//! Safrole block production and GRANDPA finality (Sections 6, 19).
//!
//! Safrole is the block production mechanism combining:
//! - Ticket-based slot assignment (anonymous lottery)
//! - Fallback slot assignment (when tickets are insufficient)
//! - Epoch-based key rotation
//! - On-chain entropy accumulation

pub mod authoring;
pub mod genesis;
pub mod safrole;

pub use safrole::{
    SafroleError, SafroleOutput, accumulate_entropy, apply_safrole, fallback_key_sequence,
    filter_offenders, is_ticket_sealed, merge_tickets, outside_in_sequence,
};

/// Compute the epoch index for a given timeslot (eq 4.8).
pub fn epoch_index(timeslot: grey_types::Timeslot) -> u32 {
    timeslot / grey_types::constants::EPOCH_LENGTH
}

/// Compute the slot within an epoch for a given timeslot.
pub fn slot_in_epoch(timeslot: grey_types::Timeslot) -> u32 {
    timeslot % grey_types::constants::EPOCH_LENGTH
}

/// Check if a timeslot is within the ticket submission period (slot < Y).
pub fn is_ticket_submission_open(timeslot: grey_types::Timeslot) -> bool {
    slot_in_epoch(timeslot) < grey_types::constants::TICKET_SUBMISSION_END
}

/// Compute the rotation index for validator-core assignments.
pub fn rotation_index(timeslot: grey_types::Timeslot) -> u32 {
    timeslot / grey_types::constants::ROTATION_PERIOD
}

/// Best-chain scoring: count of ticket-sealed blocks (eq 19.4).
///
/// Prefers chains with more ticket-sealed blocks over fallback-sealed blocks.
pub fn chain_ticket_score(sealed_with_tickets: &[bool]) -> u32 {
    sealed_with_tickets.iter().filter(|&&t| t).count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_index() {
        assert_eq!(epoch_index(0), 0);
        assert_eq!(epoch_index(599), 0);
        assert_eq!(epoch_index(600), 1);
        assert_eq!(epoch_index(1200), 2);
    }

    #[test]
    fn test_slot_in_epoch() {
        assert_eq!(slot_in_epoch(0), 0);
        assert_eq!(slot_in_epoch(599), 599);
        assert_eq!(slot_in_epoch(600), 0);
        assert_eq!(slot_in_epoch(601), 1);
    }

    #[test]
    fn test_ticket_submission() {
        assert!(is_ticket_submission_open(0));
        assert!(is_ticket_submission_open(499));
        assert!(!is_ticket_submission_open(500));
        assert!(!is_ticket_submission_open(599));
    }

    #[test]
    fn test_chain_ticket_score() {
        assert_eq!(chain_ticket_score(&[true, true, false, true]), 3);
        assert_eq!(chain_ticket_score(&[false, false, false]), 0);
        assert_eq!(chain_ticket_score(&[]), 0);
    }

    #[test]
    fn test_rotation_index() {
        // R=10 (ROTATION_PERIOD)
        assert_eq!(rotation_index(0), 0);
        assert_eq!(rotation_index(9), 0);
        assert_eq!(rotation_index(10), 1);
        assert_eq!(rotation_index(25), 2);
    }

    #[test]
    fn test_ticket_submission_across_epochs() {
        // Submission window resets each epoch (E=600, Y=500)
        assert!(is_ticket_submission_open(0)); // epoch 0, slot 0
        assert!(is_ticket_submission_open(499)); // epoch 0, slot 499
        assert!(!is_ticket_submission_open(500)); // epoch 0, slot 500 (closed)
        assert!(is_ticket_submission_open(600)); // epoch 1, slot 0 (reopened)
        assert!(is_ticket_submission_open(1099)); // epoch 1, slot 499
        assert!(!is_ticket_submission_open(1100)); // epoch 1, slot 500 (closed)
    }

    #[test]
    fn test_epoch_boundary_consistency() {
        // Last slot of epoch N and first slot of epoch N+1
        let last_slot_e0 = 599;
        let first_slot_e1 = 600;
        assert_eq!(epoch_index(last_slot_e0), 0);
        assert_eq!(epoch_index(first_slot_e1), 1);
        assert_eq!(slot_in_epoch(last_slot_e0), 599);
        assert_eq!(slot_in_epoch(first_slot_e1), 0);
    }
}
