import Jar.Types.Accounts
import Jar.Proofs.Codec
import Jar.Proofs.QuotaEcon  -- for byteArray_append_size

/-!
# BalanceEcon Proofs — gp072 token-based economic model

Contrast proofs showing BalanceEcon ≠ QuotaEcon semantically:
- setQuota always fails (unsupported)
- debitTransfer can fail (insufficient balance)
- Same serialization size invariants hold
-/

namespace Jar.Proofs

-- ============================================================================
-- Semantic contrast with QuotaEcon
-- ============================================================================

/-- setQuota is unsupported for BalanceEcon — always returns none.
    This means the set_quota hostcall always returns RESULT_WHAT in gp072 mode. -/
theorem balanceEcon_setQuota_always_none (e : BalanceEcon) (mi mb : UInt64) :
    @EconModel.setQuota BalanceEcon BalanceTransfer _ e mi mb = none := by
  rfl

/-- debitTransfer can fail with insufficient balance — unlike QuotaEcon.
    Witness: balance=0, amount=1. -/
theorem balanceEcon_debitTransfer_can_fail :
    ∃ (e : BalanceEcon) (amount : UInt64),
      @EconModel.debitTransfer BalanceEcon BalanceTransfer _ e amount = none := by
  exact ⟨{ balance := 0, gratis := 0 }, 1, rfl⟩

-- ============================================================================
-- creditTransfer ∘ debitTransfer partial inverse
-- ============================================================================

/-- creditTransfer undoes debitTransfer when balance is sufficient.
    If debitTransfer succeeds (balance ≥ amount), crediting the same amount
    recovers the original economic state. -/
theorem balanceEcon_credit_debit_roundtrip (e e' : BalanceEcon) (amount : UInt64)
    (h : @EconModel.debitTransfer BalanceEcon BalanceTransfer _ e amount = some e') :
    @EconModel.creditTransfer BalanceEcon BalanceTransfer _ e' { amount := amount } = e := by
  simp only [EconModel.debitTransfer, EconModel.creditTransfer] at h ⊢
  split at h
  next hge =>
    simp only [Option.some.injEq] at h; subst h
    have : e.balance - amount + amount = e.balance := UInt64.sub_add_cancel e.balance amount
    cases e; simp_all
  next => simp_all

-- ============================================================================
-- debitTransfer with zero amount
-- ============================================================================

/-- debitTransfer with zero amount always succeeds and preserves state.
    This follows from balance ≥ 0 for any UInt64. -/
theorem balanceEcon_debitTransfer_zero (e : BalanceEcon) :
    @EconModel.debitTransfer BalanceEcon BalanceTransfer _ e 0 = some e := by
  show (if e.balance ≥ 0 then some { e with balance := e.balance - 0 } else none) = some e
  have h0 : e.balance ≥ 0 := Nat.zero_le _
  simp only [h0, ↓reduceIte, UInt64.sub_zero]

-- ============================================================================
-- absorbEjected adds balance
-- ============================================================================

/-- absorbEjected adds the ejected service's balance to the absorber. -/
theorem balanceEcon_absorbEjected_balance (e ejected : BalanceEcon) :
    (@EconModel.absorbEjected BalanceEcon BalanceTransfer _ e ejected).balance
    = e.balance + ejected.balance := by
  rfl

-- ============================================================================
-- newServiceEcon lifecycle (canAffordStorage after creation)
-- ============================================================================

/-- A newly created BalanceEcon service can afford its initial storage footprint.
    `newServiceEcon` sets balance = threshold (the minimum viable balance for the
    given storage parameters and gratis), so `canAffordStorage` returns true
    provided the threshold fits in UInt64 (< 2^64). -/
theorem balanceEcon_newServiceEcon_canAfford
    (items bytes bI bL bS : Nat) (gratis : UInt64)
    (hFit : bS + bI * items + bL * bytes - min gratis.toNat (bS + bI * items + bL * bytes) < UInt64.size) :
    @EconModel.canAffordStorage BalanceEcon BalanceTransfer _
      (@EconModel.newServiceEcon BalanceEcon BalanceTransfer _ items bytes gratis bI bL bS)
      items bytes bI bL bS = true := by
  show (let minBal := bS + bI * items + bL * bytes
        let threshold := minBal - min gratis.toNat minBal
        decide (threshold ≤ (UInt64.ofNat threshold).toNat)) = true
  simp only [UInt64.toNat_ofNat', Nat.mod_eq_of_lt hFit, Nat.le_refl, decide_true]

-- ============================================================================
-- Serialization roundtrip (deserializeEcon ∘ serializeEcon = id)
-- ============================================================================

/-- deserializeEcon (serializeEcon e) 0 recovers the original BalanceEcon.
    Combined with the codec roundtrip, this proves that the Merklization
    serialization format is lossless for BalanceEcon values. -/
theorem balanceEcon_deserialize_serialize_roundtrip [JarConfig] (e : BalanceEcon) :
    @EconModel.deserializeEcon BalanceEcon BalanceTransfer _
      (@EconModel.serializeEcon BalanceEcon BalanceTransfer _ e) 0 = some (e, 16) := by
  show (let data := Codec.encodeFixedNat 8 e.balance.toNat
                    ++ Codec.encodeFixedNat 8 e.gratis.toNat
        if 0 + 16 ≤ data.size then
          let balance := Codec.decodeFixedNat (data.extract 0 (0 + 8))
          let gratis := Codec.decodeFixedNat (data.extract (0 + 8) (0 + 16))
          some ({ balance := UInt64.ofNat balance, gratis := UInt64.ofNat gratis }, 0 + 16)
        else none) = some (e, 16)
  have hsz : (Codec.encodeFixedNat 8 e.balance.toNat
              ++ Codec.encodeFixedNat 8 e.gratis.toNat).size = 16 := by
    rw [byteArray_append_size, encodeFixedNat_size, encodeFixedNat_size]
  simp only [hsz, Nat.le_refl, ↓reduceIte]
  have hleft : (Codec.encodeFixedNat 8 e.balance.toNat
                ++ Codec.encodeFixedNat 8 e.gratis.toNat).extract 0 8
               = Codec.encodeFixedNat 8 e.balance.toNat := by
    exact ByteArray.extract_append_eq_left (encodeFixedNat_size 8 e.balance.toNat)
  have hright : (Codec.encodeFixedNat 8 e.balance.toNat
                 ++ Codec.encodeFixedNat 8 e.gratis.toNat).extract 8 16
                = Codec.encodeFixedNat 8 e.gratis.toNat := by
    exact ByteArray.extract_append_eq_right (encodeFixedNat_size 8 e.balance.toNat)
      (by rw [encodeFixedNat_size, encodeFixedNat_size])
  rw [hleft, hright, decodeFixedNat_encodeFixedNat, decodeFixedNat_encodeFixedNat]
  simp [UInt64.ofNat_toNat]

-- ============================================================================
-- Serialization size invariants (same as QuotaEcon — both models produce
-- 16-byte serializeEcon and 24-byte encodeInfo)
-- ============================================================================

/-- serializeEcon produces exactly 16 bytes (8 for balance + 8 for gratis). -/
theorem balanceEcon_serializeEcon_size [JarConfig] (e : BalanceEcon) :
    (@EconModel.serializeEcon BalanceEcon BalanceTransfer _ e).size = 16 := by
  show (Codec.encodeFixedNat 8 e.balance.toNat
        ++ Codec.encodeFixedNat 8 e.gratis.toNat).size = 16
  rw [byteArray_append_size, encodeFixedNat_size, encodeFixedNat_size]

/-- encodeTransferAmount always produces exactly 8 bytes for the transfer amount. -/
theorem balanceEcon_encodeTransferAmount_size [JarConfig] (t : BalanceTransfer) :
    (@EconModel.encodeTransferAmount BalanceEcon BalanceTransfer _ t).size = 8 := by
  show (Codec.encodeFixedNat 8 t.amount.toNat).size = 8
  rw [encodeFixedNat_size]

/-- encodeInfo produces exactly 24 bytes (8 balance + 8 threshold + 8 gratis). -/
theorem balanceEcon_encodeInfo_size [JarConfig] (e : BalanceEcon)
    (items bytes bI bL bS : Nat) :
    (@EconModel.encodeInfo BalanceEcon BalanceTransfer _ e items bytes bI bL bS).size = 24 := by
  show (Codec.encodeFixedNat 8 e.balance.toNat
        ++ Codec.encodeFixedNat 8 _
        ++ Codec.encodeFixedNat 8 e.gratis.toNat).size = 24
  rw [byteArray_append_size, byteArray_append_size,
      encodeFixedNat_size, encodeFixedNat_size, encodeFixedNat_size]

end Jar.Proofs
