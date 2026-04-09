import Jar.JAVM.Decode

/-!
# JAVM Decode Proofs

Properties of instruction decoding helpers: sign extension identity cases,
memory tier thresholds, and LE decoding boundary cases.
-/

namespace Jar.Proofs

-- ============================================================================
-- Sign extension identity cases
-- ============================================================================

/-- Sign-extending with 0 bytes is the identity. -/
theorem sext_zero_bytes (x : UInt64) :
    Jar.JAVM.sext 0 x = x := by
  rfl

/-- Sign-extending with 8 or more bytes is the identity (already 64-bit). -/
theorem sext_eight_bytes (x : UInt64) :
    Jar.JAVM.sext 8 x = x := by
  rfl

/-- sext32 is sext with 4 bytes. -/
theorem sext32_eq_sext4 (x : UInt64) :
    Jar.JAVM.sext32 x = Jar.JAVM.sext 4 x := by
  rfl

-- ============================================================================
-- LE decoding boundary cases
-- ============================================================================

/-- Decoding 0 bytes always returns 0 regardless of data or offset. -/
theorem decodeLEn_zero_bytes (data : ByteArray) (offset : Nat) :
    Jar.JAVM.decodeLEn data offset 0 = 0 := by
  rfl

-- ============================================================================
-- Memory tier thresholds
-- ============================================================================

/-- Small memory (≤ 2048 pages) costs 25 cycles per load/store. -/
theorem computeMemCycles_small :
    Jar.JAVM.computeMemCycles 0 = 25 := by rfl

/-- Medium memory (2049-8192 pages) costs 50 cycles. -/
theorem computeMemCycles_medium :
    Jar.JAVM.computeMemCycles 4096 = 50 := by rfl

/-- Large memory (8193-65536 pages) costs 75 cycles. -/
theorem computeMemCycles_large :
    Jar.JAVM.computeMemCycles 32768 = 75 := by rfl

/-- Very large memory (> 65536 pages) costs 100 cycles. -/
theorem computeMemCycles_xlarge :
    Jar.JAVM.computeMemCycles 100000 = 100 := by rfl

/-- Boundary: exactly 2048 pages is still in the small tier. -/
theorem computeMemCycles_boundary_2048 :
    Jar.JAVM.computeMemCycles 2048 = 25 := by rfl

/-- Boundary: 2049 pages enters the medium tier. -/
theorem computeMemCycles_boundary_2049 :
    Jar.JAVM.computeMemCycles 2049 = 50 := by rfl

-- ============================================================================
-- Gas per page constant
-- ============================================================================

/-- Gas cost per page is 1500. -/
theorem gasPerPage_value : Jar.JAVM.gasPerPage = 1500 := by rfl

end Jar.Proofs
