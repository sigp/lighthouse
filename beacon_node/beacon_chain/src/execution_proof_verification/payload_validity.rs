//! Tracks the two gates on a Gloas payload's validity: the execution layer's verdict and its
//! EIP-8025 execution proofs. A payload with only one of them is optimistic in fork choice, and
//! whichever gate completes last promotes it to valid.
//!
//! ## Deadlock safety
//!
//! Every caller takes this lock while holding the fork choice write lock, which keeps a payload's
//! two gates and its fork choice status in step. Never hold this lock across an acquisition of any
//! other lock.

use hashlink::lru_cache::LruCache;
use std::collections::HashSet;
use types::Hash256;
use types::execution::ProofType;

/// Distinct proof systems that must prove a payload before fork choice calls it valid. More than
/// one means a soundness bug in a single prover isn't enough to fool us.
///
/// Which systems count is the engine's call, we only see its `VALID`. The count is ours because
/// we're the only ones who see the whole set.
///
/// TODO(9658): make configurable. https://github.com/sigp/lighthouse/issues/9658
pub const REQUIRED_EXECUTION_PROOFS: usize = 2;

/// Payloads tracked at once. Proofs follow their payload within a slot or two, so only the recent
/// chain matters and the oldest entries are evicted.
const CACHE_CAPACITY: usize = 64;

/// What is known about one payload's two gates.
#[derive(Default)]
struct PayloadGates {
    /// The execution layer has called this payload valid.
    execution_validated: bool,
    /// Proof types with a valid proof, so repeats from one prover count once.
    proof_types: HashSet<ProofType>,
}

/// Tracks both gates for recent payloads, keyed by beacon block root.
pub struct PayloadValidityCache {
    gates: LruCache<Hash256, PayloadGates>,
    /// Distinct proof systems required. Zero without a proof engine, which leaves payload validity
    /// to the execution layer alone.
    required_proofs: usize,
}

impl PayloadValidityCache {
    pub fn new(required_proofs: usize) -> Self {
        Self {
            gates: LruCache::new(CACHE_CAPACITY),
            required_proofs,
        }
    }

    /// Whether EIP-8025 execution proofs gate payload validity on this node, which they do only with
    /// a proof engine configured. Without one the execution layer's verdict is the whole of it.
    pub fn execution_proofs_required(&self) -> bool {
        self.required_proofs > 0
    }

    /// Record that the execution layer called `block_root`'s payload valid.
    ///
    /// Returns `true` if the payload is now fully verified, which is to say its proofs are in too.
    pub fn insert_execution_validated(&mut self, block_root: Hash256) -> bool {
        if self.required_proofs == 0 {
            return true;
        }

        let gates = self
            .gates
            .entry(block_root)
            .or_insert_with(PayloadGates::default);
        gates.execution_validated = true;
        gates.proof_types.len() >= self.required_proofs
    }

    /// Record a valid proof for `block_root`'s payload.
    ///
    /// Returns `true` if the payload is now fully verified, which is to say the execution layer has
    /// validated it too.
    pub fn insert_proof(&mut self, block_root: Hash256, proof_type: ProofType) -> bool {
        let gates = self
            .gates
            .entry(block_root)
            .or_insert_with(PayloadGates::default);
        gates.proof_types.insert(proof_type);
        gates.execution_validated && gates.proof_types.len() >= self.required_proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: usize = 2;

    #[test]
    fn the_last_proof_verifies_a_validated_payload() {
        let mut cache = PayloadValidityCache::new(REQUIRED);
        let block_root = Hash256::repeat_byte(1);

        assert!(
            !cache.insert_execution_validated(block_root),
            "the execution layer alone does not verify a payload"
        );
        assert!(
            !cache.insert_proof(block_root, 0),
            "one prover is not enough"
        );
        assert!(
            !cache.insert_proof(block_root, 0),
            "the same prover twice is still one prover"
        );
        assert!(
            cache.insert_proof(block_root, 1),
            "the proof that completes the requirement verifies the payload"
        );
    }

    #[test]
    fn the_execution_layer_verifies_an_already_proven_payload() {
        let mut cache = PayloadValidityCache::new(REQUIRED);
        let block_root = Hash256::repeat_byte(2);

        assert!(!cache.insert_proof(block_root, 0));
        assert!(
            !cache.insert_proof(block_root, 1),
            "proofs alone do not verify a payload the execution layer has not validated"
        );
        assert!(
            cache.insert_execution_validated(block_root),
            "the verdict completes the payload"
        );
    }

    #[test]
    fn no_proof_engine_leaves_validity_to_the_execution_layer() {
        let mut cache = PayloadValidityCache::new(0);

        assert!(cache.insert_execution_validated(Hash256::repeat_byte(3)));
    }
}
