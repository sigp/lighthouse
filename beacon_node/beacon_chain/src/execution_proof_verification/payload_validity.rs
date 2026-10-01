//! Tracks which Gloas payloads their EIP-8025 execution proofs have proven.
//!
//! With a proof engine the proofs are a payload's validity: the payload is never sent to the
//! execution layer, it is received optimistically, and the proof that completes the requirement
//! promotes it to valid.
//!
//! ## Deadlock safety
//!
//! Callers take this lock while holding the fork choice write lock, which keeps a payload's proofs
//! and its fork choice status in step. Never hold this lock across an acquisition of any other lock.

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

/// Proof types that have proven each recent payload, keyed by beacon block root.
pub struct PayloadValidityCache {
    /// Proof types with a valid proof, so repeats from one prover count once.
    proof_types: LruCache<Hash256, HashSet<ProofType>>,
    required_proofs: usize,
}

impl PayloadValidityCache {
    pub fn new(required_proofs: usize) -> Self {
        Self {
            proof_types: LruCache::new(CACHE_CAPACITY),
            required_proofs,
        }
    }

    /// Record a valid proof for `block_root`'s payload. Returns `true` if the payload is proven.
    pub fn insert_proof(&mut self, block_root: Hash256, proof_type: ProofType) -> bool {
        let proof_types = self
            .proof_types
            .entry(block_root)
            .or_insert_with(HashSet::new);
        proof_types.insert(proof_type);

        proof_types.len() >= self.required_proofs
    }

    /// Whether `block_root`'s payload has proofs from as many distinct proof systems as we require.
    ///
    /// Proofs are recursive, so a payload's own proofs are all we ask for, never its ancestors'.
    pub fn is_proven(&self, block_root: &Hash256) -> bool {
        self.proof_types
            .peek(block_root)
            .is_some_and(|proof_types| proof_types.len() >= self.required_proofs)
    }
}
