import Jar.Consensus

/-!
# Consensus Proofs

Properties of the Safrole consensus constructions: outside-in sequencer
boundary cases, length preservation, and fallback key sequence.
-/

namespace Jar.Proofs
variable [JarConfig]

-- ============================================================================
-- Outside-in sequencer boundary cases
-- ============================================================================

/-- Outside-in sequencer of an empty array is empty. -/
theorem outsideInSequencer_empty :
    Jar.Consensus.outsideInSequencer (#[] : Array Ticket) = #[] := by
  rfl

-- ============================================================================
-- Outside-in sequencer length preservation
-- ============================================================================

/-- The outside-in sequencer preserves the length of the input array. -/
theorem outsideInSequencer_size (tickets : Array Ticket) :
    (Jar.Consensus.outsideInSequencer tickets).size = tickets.size := by
  unfold Jar.Consensus.outsideInSequencer
  simp [Array.size_ofFn]

-- ============================================================================
-- Fallback key sequence length
-- ============================================================================

/-- The fallback key sequence always produces exactly E keys. -/
theorem fallbackKeySequence_size (entropy : Hash) (validators : Array ValidatorKey) :
    (Jar.Consensus.fallbackKeySequence entropy validators).size = E := by
  unfold Jar.Consensus.fallbackKeySequence
  simp only []
  split
  · simp [Array.size_replicate]
  · simp [Array.size_ofFn]

end Jar.Proofs
