//! Provides the `ObservedExecutionProofs` struct which allows for ignoring `SignedExecutionProof`s
//! that we have already seen over the gossip network.
//! Only proofs that have completed signature verification can be added to this cache to reduce
//! DoS risks.

use std::collections::{HashMap, HashSet};
use types::execution::ProofType;
use types::{Hash256, Slot};

type ValidatorIndex = u64;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the referenced block is prior to finalization and should not have been
    /// provided to this function. This is an internal error.
    FinalizedProof { slot: Slot, finalized_slot: Slot },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofObservation {
    ProofAlreadySeen,
    ValidProofAlreadyKnown,
    DuplicateFromValidator,
    New,
}

#[derive(Debug, Default)]
struct BlockProofObservations {
    slot: Slot,
    /// Message roots of proofs already processed, regardless of outcome.
    seen_proof_roots: HashSet<Hash256>,
    /// Proof types for which a valid proof has been observed.
    valid_proof_types: HashSet<ProofType>,
    /// `(proof_type, validator_index)` pairs for which proofs have been observed.
    seen_validators: HashSet<(ProofType, ValidatorIndex)>,
}

/// Maintains a cache of proofs seen over gossip, implementing the IGNORE rules of the EIP-8025
/// `execution_proof` topic.
///
/// The cache supports pruning based upon the finalized epoch. It does not automatically prune, you
/// must call `Self::prune` manually.
#[derive(Debug, Default)]
pub struct ObservedExecutionProofs {
    finalized_slot: Slot,
    items: HashMap<Hash256, BlockProofObservations>,
}

impl ObservedExecutionProofs {
    /// Check the IGNORE rules without mutating the cache.
    pub fn check(
        &self,
        proof_root: Hash256,
        block_root: Hash256,
        proof_type: ProofType,
        validator_index: ValidatorIndex,
        slot: Slot,
    ) -> Result<ProofObservation, Error> {
        self.sanitize_slot(slot)?;

        let Some(entry) = self.items.get(&block_root) else {
            return Ok(ProofObservation::New);
        };
        let observation = if entry.seen_proof_roots.contains(&proof_root) {
            ProofObservation::ProofAlreadySeen
        } else if entry.valid_proof_types.contains(&proof_type) {
            ProofObservation::ValidProofAlreadyKnown
        } else if entry
            .seen_validators
            .contains(&(proof_type, validator_index))
        {
            ProofObservation::DuplicateFromValidator
        } else {
            ProofObservation::New
        };
        Ok(observation)
    }

    /// Record a proof whose signature has been verified. Returns `true` if the proof was not
    /// already observed.
    pub fn observe_signature_verified_proof(
        &mut self,
        proof_root: Hash256,
        block_root: Hash256,
        proof_type: ProofType,
        validator_index: ValidatorIndex,
        slot: Slot,
    ) -> Result<bool, Error> {
        self.sanitize_slot(slot)?;

        let entry = self
            .items
            .entry(block_root)
            .or_insert_with(|| BlockProofObservations {
                slot,
                ..Default::default()
            });
        let did_not_exist = entry.seen_proof_roots.insert(proof_root);
        entry.seen_validators.insert((proof_type, validator_index));
        Ok(did_not_exist)
    }

    /// Record that a proof for `(block_root, proof_type)` was verified by the proof engine.
    ///
    /// The entry always exists: a proof only reaches the proof engine after
    /// `observe_signature_verified_proof`.
    pub fn observe_valid_proof(&mut self, block_root: Hash256, proof_type: ProofType) {
        if let Some(entry) = self.items.get_mut(&block_root) {
            entry.valid_proof_types.insert(proof_type);
        }
    }

    /// Prune all entries for slots at or below `finalized_slot`.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 || finalized_slot <= self.finalized_slot {
            return;
        }
        self.finalized_slot = finalized_slot;
        self.items.retain(|_, entry| entry.slot > finalized_slot);
    }

    fn sanitize_slot(&self, slot: Slot) -> Result<(), Error> {
        if slot <= self.finalized_slot && self.finalized_slot > 0 {
            Err(Error::FinalizedProof {
                slot,
                finalized_slot: self.finalized_slot,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_observations() {
        let mut cache = ObservedExecutionProofs::default();
        let proof_root = Hash256::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);
        let slot = Slot::new(5);

        assert_eq!(
            cache.check(proof_root, block_root, 0, 0, slot),
            Ok(ProofObservation::New),
            "unknown proof is new"
        );
        assert_eq!(
            cache.observe_signature_verified_proof(proof_root, block_root, 0, 0, slot),
            Ok(true),
            "first observation indicates proof unobserved"
        );
        assert_eq!(
            cache.observe_signature_verified_proof(proof_root, block_root, 0, 0, slot),
            Ok(false),
            "second observation indicates proof observed"
        );
        assert_eq!(cache.items.len(), 1, "only one block should be present");

        assert_eq!(
            cache.check(proof_root, block_root, 0, 0, slot),
            Ok(ProofObservation::ProofAlreadySeen),
            "same proof root is a duplicate regardless of validator"
        );
        assert_eq!(
            cache.check(Hash256::repeat_byte(3), block_root, 0, 0, slot),
            Ok(ProofObservation::DuplicateFromValidator),
            "different proof from the same validator and type is a duplicate"
        );
        assert_eq!(
            cache.check(Hash256::repeat_byte(3), block_root, 0, 1, slot),
            Ok(ProofObservation::New),
            "different validator is new"
        );

        cache.observe_valid_proof(block_root, 0);
        assert_eq!(
            cache.check(Hash256::repeat_byte(3), block_root, 0, 1, slot),
            Ok(ProofObservation::ValidProofAlreadyKnown),
            "any proof for a type with a valid proof is ignored"
        );
        assert_eq!(
            cache.check(Hash256::repeat_byte(3), block_root, 1, 1, slot),
            Ok(ProofObservation::New),
            "other proof types are unaffected"
        );
    }

    #[test]
    fn pruning() {
        let mut cache = ObservedExecutionProofs::default();
        let proof_root = Hash256::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);
        let slot = Slot::new(5);

        cache
            .observe_signature_verified_proof(proof_root, block_root, 0, 0, slot)
            .expect("should observe proof");

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "one block should be present");

        /*
         * Check that a prune at the genesis slot does nothing.
         */

        cache.prune(Slot::new(0));
        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "one block should be present");

        /*
         * Check that a prune at the block's slot empties the cache.
         */

        cache.prune(slot);
        assert_eq!(cache.finalized_slot, slot, "finalized slot is updated");
        assert_eq!(cache.items.len(), 0, "no items left");

        assert_eq!(
            cache.observe_signature_verified_proof(proof_root, block_root, 0, 0, slot),
            Err(Error::FinalizedProof {
                slot,
                finalized_slot: slot,
            }),
            "observing at the finalized slot is an error"
        );

        /*
         * Check that a prune never regresses.
         */

        cache.prune(Slot::new(1));
        assert_eq!(cache.finalized_slot, slot, "finalized slot is unchanged");
    }
}
