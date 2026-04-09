import Jar.Merkle

/-!
# Merkle Tree Proofs

Properties of Merkle tree constructions: boundary cases for binary Merkle
trees, constant-depth trees, and trie roots.
-/

namespace Jar.Proofs

-- ============================================================================
-- Binary Merkle tree boundary cases
-- ============================================================================

/-- Binary Merkle root of an empty array is the zero hash. -/
theorem binaryMerkleRoot_empty :
    Jar.Merkle.binaryMerkleRoot #[] = Hash.zero := by
  rfl

/-- Binary Merkle root of a single-element array is the element itself. -/
theorem binaryMerkleRoot_singleton (h : Hash) :
    Jar.Merkle.binaryMerkleRoot #[h] = h := by
  rfl

-- ============================================================================
-- Constant-depth Merkle tree
-- ============================================================================

/-- Constant-depth tree at depth 0 with empty input pads to one zero hash,
    which is the singleton Merkle root = Hash.zero. -/
theorem constDepthMerkleRoot_empty_depth0 :
    Jar.Merkle.constDepthMerkleRoot #[] 0 = Hash.zero := by
  rfl

/-- Constant-depth tree at depth 0 with a single element returns that element.
    2^0 = 1, so no padding occurs. -/
theorem constDepthMerkleRoot_singleton_depth0 (h : Hash) :
    Jar.Merkle.constDepthMerkleRoot #[h] 0 = h := by
  rfl

-- ============================================================================
-- stateRoot is trieRoot
-- ============================================================================

/-- stateRoot is exactly trieRoot (no additional logic). -/
theorem stateRoot_eq_trieRoot (entries : Array (OctetSeq 31 × ByteArray)) :
    Jar.Merkle.stateRoot entries = Jar.Merkle.trieRoot entries := by
  rfl

-- ============================================================================
-- Merkle node encoding
-- ============================================================================

/-- Encoding a branch node produces a 64-byte result. -/
theorem encodeBranch_size (l r : Hash) :
    (Jar.Merkle.encodeBranch l r).data.size = 64 :=
  (Jar.Merkle.encodeBranch l r).size_eq

/-- Encoding a leaf node produces a 64-byte result. -/
theorem encodeLeaf_size (k : OctetSeq 31) (v : ByteArray) :
    (Jar.Merkle.encodeLeaf k v).data.size = 64 :=
  (Jar.Merkle.encodeLeaf k v).size_eq

end Jar.Proofs
