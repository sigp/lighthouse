use crate::observed_data_sidecars::{ObservationStrategy, Observe};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::{debug, error, warn};
use types::{ChainSpec, EthSpec, ExecutionProof, ExecutionProofId, Hash256, Slot};

/// An error occurred while validating a gossip execution proof.
#[derive(Debug)]
pub enum GossipExecutionProofError {
    /// There was an error whilst processing the execution proof. It is not known if it is
    /// valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this proof due to an internal error. It's unclear if the proof
    /// is valid.
    BeaconChainError(Box<BeaconChainError>),

    /// The execution proof is from a slot that is later than the current slot (with respect to
    /// the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },

    /// The proof corresponds to a slot older than the finalized head slot.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this proof is valid, but this proof is for a finalized slot and is
    /// therefore useless to us.
    PastFinalizedSlot {
        proof_slot: Slot,
        finalized_slot: Slot,
    },

    /// The proof's parent block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// We cannot process the proof without validating its parent, the peer isn't necessarily
    /// faulty.
    ParentUnknown { parent_root: Hash256 },

    /// The proof conflicts with finalization, no need to propagate.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this proof is valid, but it conflicts with finality and shouldn't be
    /// imported.
    NotFinalizedDescendant { block_parent_root: Hash256 },

    /// An execution proof has already been seen for the given `(proof.block_root,
    /// proof_id)` tuple over gossip or no gossip sources.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, but we do not forward it over gossip.
    PriorKnown {
        slot: Slot,
        block_root: Hash256,
        proof_id: ExecutionProofId,
    },

    /// An execution proof has already been processed from non-gossip source and has not yet been
    /// seen on the gossip network. This proof should be accepted and forwarded over gossip.
    PriorKnownUnpublished,

    /// The proof verification failed (invalid zkVM proof).
    ///
    /// ## Peer scoring
    ///
    /// The proof is invalid and the peer is faulty.
    ProofVerificationFailed(String),

    /// The proof size exceeds the maximum allowed size.
    ///
    /// ## Peer scoring
    ///
    /// The proof is invalid and the peer is faulty.
    ProofTooLarge { size: usize, max_size: usize },

    /// The block for this proof is not yet available.
    ///
    /// ## Peer scoring
    ///
    /// The peer may have sent a proof before we've seen the block. Not necessarily faulty.
    BlockNotAvailable { block_root: Hash256 },
}

impl From<BeaconChainError> for GossipExecutionProofError {
    fn from(e: BeaconChainError) -> Self {
        GossipExecutionProofError::BeaconChainError(Box::new(e))
    }
}

/// A wrapper around an `ExecutionProof` that has been verified for propagation on the gossip
/// network.
pub struct GossipVerifiedExecutionProof<T: BeaconChainTypes, O: ObservationStrategy = Observe> {
    block_root: Hash256,
    execution_proof: Arc<ExecutionProof>,
    _phantom: PhantomData<(T, O)>,
}

impl<T: BeaconChainTypes, O: ObservationStrategy> std::fmt::Debug
    for GossipVerifiedExecutionProof<T, O>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipVerifiedExecutionProof")
            .field("block_root", &self.block_root)
            .field("execution_proof", &self.execution_proof)
            .finish()
    }
}

impl<T: BeaconChainTypes, O: ObservationStrategy> Clone for GossipVerifiedExecutionProof<T, O> {
    fn clone(&self) -> Self {
        Self {
            block_root: self.block_root,
            execution_proof: self.execution_proof.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T: BeaconChainTypes, O: ObservationStrategy> GossipVerifiedExecutionProof<T, O> {
    pub fn new(
        execution_proof: Arc<ExecutionProof>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipExecutionProofError> {
        validate_execution_proof_for_gossip::<T, O>(execution_proof, chain)
    }

    pub fn slot(&self) -> Slot {
        self.execution_proof.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn execution_proof(&self) -> &Arc<ExecutionProof> {
        &self.execution_proof
    }

    pub fn subnet_id(&self) -> ExecutionProofId {
        self.execution_proof.proof_id
    }

    /// Get the block root for this proof.
    pub fn into_inner(self) -> Arc<ExecutionProof> {
        self.execution_proof
    }
}

/// Validate an execution proof for gossip
pub fn validate_execution_proof_for_gossip<T: BeaconChainTypes, O: ObservationStrategy>(
    execution_proof: Arc<ExecutionProof>,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedExecutionProof<T, O>, GossipExecutionProofError> {
    let block_root = execution_proof.block_root;
    let proof_slot = execution_proof.slot;

    // 1. Verify proof is not from the future
    verify_proof_not_from_future_slot(chain, proof_slot)?;

    // 2. Verify proof slot is greater than finalized slot
    verify_slot_greater_than_latest_finalized_slot(chain, proof_slot)?;

    // 3. Check if proof is already known via gossip
    verify_is_unknown_execution_proof(chain, &execution_proof)?;

    // 4. Check if the proof is already in the DA checker cache
    // If it exists in the cache, we know it has already passed validation.
    if chain
        .data_availability_checker
        .is_execution_proof_cached(&block_root, &execution_proof)
    {
        if O::observe() {
            observe_gossip_execution_proof(&execution_proof, chain)?;
        }
        return Err(GossipExecutionProofError::PriorKnownUnpublished);
    }

    // 5. Verify proof size limits
    verify_proof_size(&execution_proof, &chain.spec)?;

    // Note: We intentionally do NOT verify the block exists yet
    // Execution proofs can arrive via gossip before their corresponding blocks,
    // so we cache them in the DA checker and match them up when the block arrives.
    // This is kind of similar to how blob sidecars work.

    // 6. Run zkVM proof verification
    verify_zkvm_proof(&execution_proof, chain)?;

    // 7. Observe the proof to prevent reprocessing
    if O::observe() {
        observe_gossip_execution_proof(&execution_proof, chain)?;
    }

    Ok(GossipVerifiedExecutionProof {
        block_root,
        execution_proof,
        _phantom: PhantomData,
    })
}

/// Verify that this execution proof has not been seen before via gossip
fn verify_is_unknown_execution_proof<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    execution_proof: &ExecutionProof,
) -> Result<(), GossipExecutionProofError> {
    let block_root = execution_proof.block_root;
    let proof_id = execution_proof.proof_id;
    let slot = execution_proof.slot;

    if chain
        .observed_execution_proofs
        .read()
        .is_known(slot, block_root, proof_id)
        .map_err(|e| {
            GossipExecutionProofError::BeaconChainError(Box::new(
                BeaconChainError::ObservedExecutionProofError(format!("{:?}", e)),
            ))
        })?
    {
        return Err(GossipExecutionProofError::PriorKnown {
            slot,
            block_root,
            proof_id,
        });
    }

    Ok(())
}

/// Verify that the proof size is within acceptable limits.
fn verify_proof_size(
    execution_proof: &ExecutionProof,
    _spec: &ChainSpec,
) -> Result<(), GossipExecutionProofError> {
    use types::MAX_PROOF_DATA_BYTES;

    let proof_size = execution_proof.proof_data.len();
    if proof_size > MAX_PROOF_DATA_BYTES {
        return Err(GossipExecutionProofError::ProofTooLarge {
            size: proof_size,
            max_size: MAX_PROOF_DATA_BYTES,
        });
    }

    Ok(())
}

/// Mark this execution proof as observed in gossip, to prevet reprocessing
fn observe_gossip_execution_proof<T: BeaconChainTypes>(
    execution_proof: &ExecutionProof,
    chain: &BeaconChain<T>,
) -> Result<(), GossipExecutionProofError> {
    let block_root = execution_proof.block_root;
    let proof_id = execution_proof.proof_id;
    let slot = execution_proof.slot;

    chain
        .observed_execution_proofs
        .write()
        .observe_proof(slot, block_root, proof_id)
        .map_err(|e| {
            GossipExecutionProofError::BeaconChainError(Box::new(
                BeaconChainError::ObservedExecutionProofError(format!("{:?}", e)),
            ))
        })?;

    debug!(
        %block_root,
        %proof_id,
        %slot,
        "Marked execution proof as observed"
    );

    Ok(())
}

/// Verify that the execution proof is not from a future slot.
fn verify_proof_not_from_future_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    proof_slot: Slot,
) -> Result<(), GossipExecutionProofError> {
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(chain.spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;

    if proof_slot > latest_permissible_slot {
        return Err(GossipExecutionProofError::FutureSlot {
            message_slot: proof_slot,
            latest_permissible_slot,
        });
    }

    Ok(())
}

/// Verify that the execution proof slot is greater than the latest finalized slot.
fn verify_slot_greater_than_latest_finalized_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    proof_slot: Slot,
) -> Result<(), GossipExecutionProofError> {
    let latest_finalized_slot = chain
        .head()
        .finalized_checkpoint()
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());

    if proof_slot <= latest_finalized_slot {
        return Err(GossipExecutionProofError::PastFinalizedSlot {
            proof_slot,
            finalized_slot: latest_finalized_slot,
        });
    }

    Ok(())
}

/// Verify the zkVM proof.
///
/// Note: This is expensive
fn verify_zkvm_proof<T: BeaconChainTypes>(
    execution_proof: &ExecutionProof,
    chain: &BeaconChain<T>,
) -> Result<(), GossipExecutionProofError> {
    let block_root = execution_proof.block_root;
    let subnet_id = execution_proof.proof_id;

    match chain
        .data_availability_checker
        .verify_execution_proof_for_gossip(execution_proof)
    {
        Ok(true) => {
            debug!(%block_root, %subnet_id, "Proof verification succeeded");
            Ok(())
        }
        Ok(false) => {
            warn!(%block_root, %subnet_id, "Proof verification failed: proof is invalid");
            Err(GossipExecutionProofError::ProofVerificationFailed(format!(
                "zkVM proof verification failed for block_root={}, subnet_id={}",
                block_root, subnet_id
            )))
        }
        Err(e) => {
            error!(%block_root, %subnet_id, ?e, "Proof verification error");
            Err(GossipExecutionProofError::BeaconChainError(Box::new(
                e.into(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy};
    use types::{ExecutionBlockHash, ForkName, MainnetEthSpec};

    type E = MainnetEthSpec;

    /// Helper to create a test execution proof
    fn create_test_execution_proof(
        subnet_id: ExecutionProofId,
        slot: Slot,
        block_root: Hash256,
    ) -> ExecutionProof {
        let block_hash = ExecutionBlockHash::zero();
        let proof_data = vec![0u8; 32]; // Dummy proof data
        ExecutionProof::new(subnet_id, slot, block_hash, block_root, proof_data)
            .expect("Valid test proof")
    }

    #[tokio::test]
    async fn test_reject_future_slot() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        let current_slot = harness.get_current_slot();
        let future_slot = current_slot + 100;
        let proof_id = ExecutionProofId::new(0).expect("Valid proof id");
        let proof = create_test_execution_proof(proof_id, future_slot, Hash256::random());

        let result =
            validate_execution_proof_for_gossip::<_, Observe>(Arc::new(proof), &harness.chain);

        assert!(matches!(
            result.err(),
            Some(GossipExecutionProofError::FutureSlot { .. })
        ));
    }

    #[tokio::test]
    async fn test_reject_past_finalized_slot() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        // Advance to slot 1 first
        harness.advance_slot();

        // Advance chain to create finalized slot
        harness
            .extend_chain(
                32,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let finalized_slot = harness
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch());
        // Create proof for slot before finalized
        let old_slot = finalized_slot.saturating_sub(1u64);
        let proof_id = ExecutionProofId::new(0).expect("Valid proof id");
        let proof = create_test_execution_proof(proof_id, old_slot, Hash256::random());

        let result =
            validate_execution_proof_for_gossip::<_, Observe>(Arc::new(proof), &harness.chain);

        assert!(matches!(
            result.err(),
            Some(GossipExecutionProofError::PastFinalizedSlot { .. })
        ));
    }

    #[tokio::test]
    async fn test_successful_validation() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();
        let current_slot = harness.get_current_slot();
        let proof_id = ExecutionProofId::new(0).expect("Valid subnet id");

        // Use a realistic block root from the chain
        let block_root = harness.chain.head_beacon_block_root();
        let proof = create_test_execution_proof(proof_id, current_slot, block_root);

        let result =
            validate_execution_proof_for_gossip::<_, Observe>(Arc::new(proof), &harness.chain);

        match result {
            Ok(_) => {}
            Err(GossipExecutionProofError::FutureSlot { .. })
            | Err(GossipExecutionProofError::PastFinalizedSlot { .. }) => {
                panic!("Should not fail basic validation checks");
            }
            Err(_) => {}
        }
    }

    /// This test verifies that:
    /// 1. First gossip proof is accepted and marked as observed
    /// 2. Duplicate gossip proof is rejected with PriorKnown
    /// 3. DoS protection: Expensive verification only happens once
    #[tokio::test]
    async fn test_gossip_duplicate_proof_rejected() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .zkvm_with_dummy_verifiers()
            .build();

        harness.advance_slot();
        let current_slot = harness.get_current_slot();
        let proof_id = ExecutionProofId::new(0).expect("Valid proof id");
        let block_root = Hash256::random();
        let proof = Arc::new(create_test_execution_proof(
            proof_id,
            current_slot,
            block_root,
        ));

        let result1 =
            validate_execution_proof_for_gossip::<_, Observe>(proof.clone(), &harness.chain);
        assert!(result1.is_ok());

        // Should now be rejected as duplicate
        let result2 =
            validate_execution_proof_for_gossip::<_, Observe>(proof.clone(), &harness.chain);

        assert!(
            matches!(
                result2.err(),
                Some(GossipExecutionProofError::PriorKnown { slot, block_root: br, proof_id: sid })
                if slot == current_slot && br == block_root && sid == proof_id
            ),
            "Duplicate proof must be rejected with PriorKnown error"
        );

        assert!(
            harness
                .chain
                .observed_execution_proofs
                .read()
                .is_known(current_slot, block_root, proof_id)
                .unwrap(),
            "Proof should be marked as observed"
        );
    }

    /// Test that proofs in the DA checker cache are detected and marked as observed.
    ///
    /// When a proof arrives via gossip but is already in the DA checker cache (from RPC),
    /// we should:
    /// 1. Accept it for gossip propagation
    /// 2. Mark it as observed to prevent reprocessing
    /// 3. Return PriorKnownUnpublished
    #[tokio::test]
    async fn test_da_cached_proof_accepted_and_observed() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();
        let subnet_id = ExecutionProofId::new(0).expect("Valid subnet id");
        let current_slot = harness.get_current_slot();
        let block_root = Hash256::random();

        let proof = Arc::new(create_test_execution_proof(
            subnet_id,
            current_slot,
            block_root,
        ));

        // Put the proof directly into the DA checker cache (this can happen if it arritves via RPC)
        harness
            .chain
            .data_availability_checker
            .put_rpc_execution_proofs(block_root, vec![proof.clone()])
            .expect("Should put proof in DA cache");

        // Verify it's in the cache
        assert!(
            harness
                .chain
                .data_availability_checker
                .is_execution_proof_cached(&block_root, &proof),
            "Proof should be in DA cache"
        );

        // Verify it's NOT in observed cache yet
        assert!(
            !harness
                .chain
                .observed_execution_proofs
                .read()
                .is_known(current_slot, block_root, subnet_id)
                .unwrap(),
            "Proof should not be in observed cache initially"
        );

        // Now it arrives via gossip
        let result =
            validate_execution_proof_for_gossip::<_, Observe>(proof.clone(), &harness.chain);

        // Should be rejected with PriorKnownUnpublished (safe to propagate)
        assert!(
            matches!(
                result.as_ref().err(),
                Some(GossipExecutionProofError::PriorKnownUnpublished)
            ),
            "DA cached proof should return PriorKnownUnpublished, got: {:?}",
            result
        );

        // Should now be marked as observed
        assert!(
            harness
                .chain
                .observed_execution_proofs
                .read()
                .is_known(current_slot, block_root, subnet_id)
                .unwrap(),
            "Proof should be marked as observed after DA cache check"
        );

        // Second gossip attempt should be rejected as PriorKnown (not PriorKnownUnpublished)
        let result2 =
            validate_execution_proof_for_gossip::<_, Observe>(proof.clone(), &harness.chain);

        assert!(
            matches!(
                result2.err(),
                Some(GossipExecutionProofError::PriorKnown { .. })
            ),
            "Second gossip should be rejected as PriorKnown (already observed)"
        );
    }
}
