//! Provides the `ObservedExecutionProofs` struct which allows for rejecting execution proofs
//! that we have already seen over the gossip network.
//!
//! This cache prevents DoS attacks where an attacker repeatedly gossips the same execution proof,
//! forcing expensive zkVM verification operations. Only proofs that have passed basic gossip
//! validation and proof verification should be added to this cache.
//!
//! TODO(zkproofs): we want the proofs to be signed and then we can just add them to the cache
//! once the signature has been verified like `observed_data_sidecars`

use std::collections::{HashMap, HashSet};
use types::{ExecutionProofId, Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided execution proof is prior to finalization.
    FinalizedExecutionProof { slot: Slot, finalized_slot: Slot },
}

/// Key for tracking observed execution proofs.
/// We track by (slot, block_root) to efficiently prune old entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProofKey {
    slot: Slot,
    block_root: Hash256,
}

impl ProofKey {
    fn new(slot: Slot, block_root: Hash256) -> Self {
        Self { slot, block_root }
    }
}

/// Maintains a cache of seen execution proofs that were received over gossip.
///
/// The cache tracks (slot, block_root, proof_id) tuples and prunes entries from finalized slots.
///
/// ## DoS Resistance
///
/// This cache is critical for preventing DoS attacks where an attacker repeatedly gossips
/// the same execution proof. zkVM verification is expensive (50-100ms), so we must avoid
/// re-verifying proofs we've already seen.
///
/// ## Pruning
///
/// Call `prune` on finalization to remove entries from finalized slots. This basically matches the
/// pattern used for observed blobs and data columns.
pub struct ObservedExecutionProofs {
    /// The finalized slot. Proofs at or below this slot are rejected.
    finalized_slot: Slot,
    /// Map from (slot, block_root) to the set of subnet IDs we've seen for that block.
    items: HashMap<ProofKey, HashSet<ExecutionProofId>>,
}

impl ObservedExecutionProofs {
    /// Create a new cache with the given finalized slot.
    ///
    /// Proofs at or below `finalized_slot` will be rejected.
    pub fn new(finalized_slot: Slot) -> Self {
        Self {
            finalized_slot,
            items: HashMap::new(),
        }
    }

    /// Observe an execution proof from gossip.
    ///
    /// Returns `true` if the proof was already observed (duplicate), `false` if it's new.
    ///
    /// Returns an error if the proof's slot is at or below the finalized slot.
    /// Note: This shouldn't happen because it means we've received a proof for
    /// a finalized block
    pub fn observe_proof(
        &mut self,
        slot: Slot,
        block_root: Hash256,
        proof_id: ExecutionProofId,
    ) -> Result<bool, Error> {
        // Reject finalized proofs
        if self.finalized_slot > 0 && slot <= self.finalized_slot {
            return Err(Error::FinalizedExecutionProof {
                slot,
                finalized_slot: self.finalized_slot,
            });
        }

        let key = ProofKey::new(slot, block_root);
        let proof_ids = self.items.entry(key).or_insert_with(HashSet::new);

        let was_duplicate = !proof_ids.insert(proof_id);

        Ok(was_duplicate)
    }

    /// Check if we have already observed this proof.
    ///
    /// Returns `true` if the proof has been seen, `false` if it's new.
    ///
    /// Returns an error if the proof's slot is at or below the finalized slot.
    pub fn is_known(
        &self,
        slot: Slot,
        block_root: Hash256,
        proof_id: ExecutionProofId,
    ) -> Result<bool, Error> {
        // Reject finalized proofs
        if self.finalized_slot > 0 && slot <= self.finalized_slot {
            return Err(Error::FinalizedExecutionProof {
                slot,
                finalized_slot: self.finalized_slot,
            });
        }

        let key = ProofKey::new(slot, block_root);
        let is_known = self
            .items
            .get(&key)
            .is_some_and(|proof_ids| proof_ids.contains(&proof_id));

        Ok(is_known)
    }

    /// Prune execution proof observations for slots less than or equal to the given slot.
    ///
    /// This matches the pruning behavior of observed blobs and data columns.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|key, _| key.slot > finalized_slot);
    }

    /// Get the current finalized slot boundary.
    ///
    /// Proofs at or below this slot will be rejected.
    pub fn finalized_slot(&self) -> Slot {
        self.finalized_slot
    }

    /// Get the number of unique (slot, block_root) keys being tracked.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all entries from the cache.
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl Default for ObservedExecutionProofs {
    fn default() -> Self {
        Self::new(Slot::new(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::FixedBytesExtended;

    fn test_proof_key(slot: u64) -> (Slot, Hash256, ExecutionProofId) {
        (
            Slot::new(slot),
            Hash256::from_low_u64_be(slot),
            ExecutionProofId::new(0).unwrap(),
        )
    }

    #[test]
    fn test_observe_new_proof() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));
        let (slot, block_root, subnet_id) = test_proof_key(10);

        // First observation should return false (not a duplicate)
        assert_eq!(
            cache.observe_proof(slot, block_root, subnet_id),
            Ok(false),
            "first observation should not be duplicate"
        );

        // Second observation should return true (is a duplicate)
        assert_eq!(
            cache.observe_proof(slot, block_root, subnet_id),
            Ok(true),
            "second observation should be duplicate"
        );
    }

    #[test]
    fn test_observe_different_subnets() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));
        let slot = Slot::new(10);
        let block_root = Hash256::from_low_u64_be(10);
        let proof_0 = ExecutionProofId::new(0).unwrap();
        let proof_1 = ExecutionProofId::new(1).unwrap();

        assert_eq!(
            cache.observe_proof(slot, block_root, proof_0),
            Ok(false),
            "proof 0 is new"
        );

        // Observe proof from subnet 1 (same block, different proofID)
        assert_eq!(
            cache.observe_proof(slot, block_root, proof_1),
            Ok(false),
            "proof 1 is new"
        );

        // Re-observe proof 0
        assert_eq!(
            cache.observe_proof(slot, block_root, proof_0),
            Ok(true),
            "proof 0 is duplicate"
        );

        assert!(cache.is_known(slot, block_root, proof_0).unwrap());
        assert!(cache.is_known(slot, block_root, proof_1).unwrap());
    }

    #[test]
    fn test_is_known() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));
        let (slot, block_root, proof_id) = test_proof_key(10);

        // Before observation
        assert_eq!(
            cache.is_known(slot, block_root, proof_id),
            Ok(false),
            "not yet observed"
        );

        // After observation
        cache.observe_proof(slot, block_root, proof_id).unwrap();
        assert_eq!(
            cache.is_known(slot, block_root, proof_id),
            Ok(true),
            "now observed"
        );
    }

    #[test]
    fn test_reject_finalized_proofs() {
        let finalized_slot = Slot::new(100);
        let mut cache = ObservedExecutionProofs::new(finalized_slot);

        let old_slot = Slot::new(100);
        let block_root = Hash256::from_low_u64_be(100);
        let proof_id = ExecutionProofId::new(0).unwrap();

        // Observing finalized proof should error
        assert_eq!(
            cache.observe_proof(old_slot, block_root, proof_id),
            Err(Error::FinalizedExecutionProof {
                slot: old_slot,
                finalized_slot,
            }),
            "finalized proofs should be rejected"
        );

        // Checking finalized proof should error
        assert_eq!(
            cache.is_known(old_slot, block_root, proof_id),
            Err(Error::FinalizedExecutionProof {
                slot: old_slot,
                finalized_slot,
            }),
            "finalized proofs should be rejected in is_known"
        );
    }

    #[test]
    fn test_pruning() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));

        // Add proofs at different slots
        for slot in 0..100 {
            let (s, br, pid) = test_proof_key(slot);
            cache.observe_proof(s, br, pid).unwrap();
        }

        assert_eq!(cache.len(), 100, "should have 100 entries");

        // Prune at finalized_slot = 50
        // Should remove slots <= 50, keep slots > 50
        let finalized_slot = Slot::new(50);
        cache.prune(finalized_slot);

        assert_eq!(
            cache.finalized_slot(),
            finalized_slot,
            "finalized slot should be updated"
        );

        // Check that finalized entries were removed
        let old_slot = Slot::new(50);
        let old_block_root = Hash256::from_low_u64_be(50);
        let proof_id = ExecutionProofId::new(0).unwrap();

        assert!(
            cache.is_known(old_slot, old_block_root, proof_id).is_err(),
            "finalized entries should be rejected after pruning"
        );

        // Check that non-finalized entries are still present
        let recent_slot = Slot::new(51);
        let recent_block_root = Hash256::from_low_u64_be(51);
        assert!(
            cache
                .is_known(recent_slot, recent_block_root, proof_id)
                .unwrap(),
            "non-finalized entries should still be present"
        );
    }

    #[test]
    fn test_prune_removes_exact_boundary() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));

        // Add proofs at slots 50, 51, 52
        for slot in 50..=52 {
            let (s, br, pid) = test_proof_key(slot);
            cache.observe_proof(s, br, pid).unwrap();
        }

        // Prune at finalized_slot = 50
        // Should remove slots <= 50, keep slots > 50
        cache.prune(Slot::new(50));

        assert_eq!(cache.finalized_slot(), Slot::new(50));

        let proof_id = ExecutionProofId::new(0).unwrap();

        // Slot 50 should be rejected (finalized)
        assert!(
            cache
                .is_known(Slot::new(50), Hash256::from_low_u64_be(50), proof_id)
                .is_err()
        );

        // Slot 51 should still be present (> finalized)
        assert!(
            cache
                .is_known(Slot::new(51), Hash256::from_low_u64_be(51), proof_id)
                .unwrap()
        );

        // Slot 52 should still be present
        assert!(
            cache
                .is_known(Slot::new(52), Hash256::from_low_u64_be(52), proof_id)
                .unwrap()
        );
    }

    #[test]
    fn test_different_blocks_same_slot() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));
        let slot = Slot::new(10);
        let block_root_a = Hash256::from_low_u64_be(100);
        let block_root_b = Hash256::from_low_u64_be(200);
        let proof_id = ExecutionProofId::new(0).unwrap();

        // Observe proof for block A
        cache.observe_proof(slot, block_root_a, proof_id).unwrap();

        // Proof for block B should be new (different block_root)
        assert_eq!(
            cache.observe_proof(slot, block_root_b, proof_id),
            Ok(false),
            "different block_root should not be duplicate"
        );

        assert!(cache.is_known(slot, block_root_a, proof_id).unwrap());
        assert!(cache.is_known(slot, block_root_b, proof_id).unwrap());
    }

    #[test]
    fn test_len_counts_blocks_not_subnets() {
        let mut cache = ObservedExecutionProofs::new(Slot::new(0));
        let slot = Slot::new(10);
        let block_root = Hash256::from_low_u64_be(10);

        // Add multiple proof IDs for same block
        for i in 0..8 {
            let proof_id = ExecutionProofId::new(i).unwrap();
            cache.observe_proof(slot, block_root, proof_id).unwrap();
        }

        // Length should be 1 (one unique (slot, block_root) key)
        assert_eq!(cache.len(), 1, "len counts unique keys, not proofIDs");
    }
}
