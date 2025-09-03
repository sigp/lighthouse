//! Verification of execution proofs received via gossip.
//!
//! This module provides gossip verification for execution proofs, similar to how
//! blob_verification.rs handles blob sidecars.

use derivative::Derivative;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes};
use crate::execution_proof_generation;
use crate::observed_data_sidecars::{DoNotObserve, ObservationStrategy, Observe};
use crate::BeaconChainError;
use slot_clock::SlotClock;
use tracing::debug;
use types::{
    EthSpec, ExecutionProof, Hash256, Slot,
};
use types::execution_proof_subnet_id::ExecutionProofSubnetId;

/// An error occurred while validating a gossip execution proof.
#[derive(Debug)]
pub enum GossipExecutionProofError {
    /// The execution proof is from a slot that is later than the current slot.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The execution proof is from a slot that is prior to the earliest permissible slot.
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The subnet ID does not match the proof's subnet ID.
    InvalidSubnetId { expected: u64, received: u64 },
    /// The execution proof failed cryptographic verification.
    InvalidProof { reason: String },
    /// The execution proof is structurally invalid.
    InvalidStructure { reason: String },
    /// Some other error occurred.
    BeaconChainError(BeaconChainError),
}

impl From<BeaconChainError> for GossipExecutionProofError {
    fn from(e: BeaconChainError) -> Self {
        Self::BeaconChainError(e)
    }
}

/// A wrapper around an `ExecutionProof` that has been verified for propagation on the gossip network.
#[derive(Derivative)]
#[derivative(Clone(bound = "T: Clone"))]
pub struct GossipVerifiedExecutionProof<T: BeaconChainTypes, O: ObservationStrategy = Observe> {
    block_root: Hash256,
    proof: VerifiedExecutionProof,
    _phantom: PhantomData<(T, O)>,
}

/// A wrapper around an `ExecutionProof` that has been cryptographically verified.
#[derive(Clone)]
pub struct VerifiedExecutionProof {
    proof: ExecutionProof,
    seen_timestamp: Duration,
}

impl VerifiedExecutionProof {
    /// Create a new verified execution proof with a seen timestamp.
    pub fn new(proof: ExecutionProof, seen_timestamp: Duration) -> Self {
        Self {
            proof,
            seen_timestamp,
        }
    }

    /// Get the inner execution proof.
    pub fn as_proof(&self) -> &ExecutionProof {
        &self.proof
    }

    /// Get the seen timestamp.
    pub fn seen_timestamp(&self) -> Duration {
        self.seen_timestamp
    }

    /// Convert into the inner execution proof.
    pub fn into_inner(self) -> ExecutionProof {
        self.proof
    }
}

impl<T: BeaconChainTypes, O: ObservationStrategy> GossipVerifiedExecutionProof<T, O> {
    /// Create a new `GossipVerifiedExecutionProof` after performing gossip verification.
    pub fn new(
        proof: Arc<ExecutionProof>,
        subnet_id: ExecutionProofSubnetId,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipExecutionProofError> {
        let seen_timestamp = chain
            .slot_clock
            .now_duration()
            .ok_or(BeaconChainError::UnableToReadSlot)?;

        validate_execution_proof_for_gossip::<T, O>(proof.clone(), subnet_id, chain)?;

        // Perform cryptographic verification
        if !execution_proof_generation::validate_proof(&proof) {
            return Err(GossipExecutionProofError::InvalidProof {
                reason: "Cryptographic verification failed".to_string(),
            });
        }

        Ok(Self {
            block_root: proof.block_root,
            proof: VerifiedExecutionProof::new((*proof).clone(), seen_timestamp),
            _phantom: PhantomData,
        })
    }

    /// Construct a `GossipVerifiedExecutionProof` that is assumed to be valid.
    ///
    /// This should ONLY be used for testing.
    pub fn __assumed_valid(proof: Arc<ExecutionProof>) -> Self {
        Self {
            block_root: proof.block_root,
            proof: VerifiedExecutionProof {
                proof: (*proof).clone(),
                seen_timestamp: Duration::from_secs(0),
            },
            _phantom: PhantomData,
        }
    }

    /// Get the block root of the beacon block this proof is for.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    /// Get the execution proof.
    pub fn as_proof(&self) -> &ExecutionProof {
        self.proof.as_proof()
    }

    /// Get the subnet ID.
    pub fn subnet_id(&self) -> ExecutionProofSubnetId {
        self.proof.proof.subnet_id
    }

    /// Get the slot of the proof (derived from block).
    pub fn slot(&self) -> Slot {
        // TODO: This would need to be derived from the block the proof references
        // For now, return a placeholder
        Slot::new(0)
    }

    /// Convert into the inner verified execution proof.
    pub fn into_inner(self) -> VerifiedExecutionProof {
        self.proof
    }
}

/// Validate an execution proof for gossip according to the rules defined in the consensus specs.
fn validate_execution_proof_for_gossip<T: BeaconChainTypes, O: ObservationStrategy>(
    proof: Arc<ExecutionProof>,
    subnet_id: ExecutionProofSubnetId,
    chain: &BeaconChain<T>,
) -> Result<(), GossipExecutionProofError> {
    // Check subnet ID matches
    if proof.subnet_id != subnet_id {
        return Err(GossipExecutionProofError::InvalidSubnetId {
            expected: *subnet_id,
            received: *proof.subnet_id,
        });
    }

    // Check structural validity
    if !proof.is_structurally_valid() {
        return Err(GossipExecutionProofError::InvalidStructure {
            reason: "Proof is structurally invalid".to_string(),
        });
    }

    // TODO: Add timing validation based on slot
    // TODO: Add duplicate proof detection
    // TODO: Add block existence validation

    Ok(())
}

/// List of `VerifiedExecutionProof` that can be converted to/from a list of `ExecutionProof`.
pub struct VerifiedExecutionProofList {
    verified_proofs: Vec<VerifiedExecutionProof>,
}

impl VerifiedExecutionProofList {
    /// Create a new list by verifying a collection of execution proofs.
    pub fn new<I: IntoIterator<Item = ExecutionProof>>(
        proofs: I,
        seen_timestamp: Duration,
    ) -> Result<Self, String> {
        let mut verified_proofs = Vec::new();
        
        for proof in proofs {
            // Perform cryptographic verification for each proof
            if execution_proof_generation::validate_proof(&proof) {
                verified_proofs.push(VerifiedExecutionProof::new(proof, seen_timestamp));
            } else {
                return Err(format!("Invalid execution proof for subnet {}", *proof.subnet_id));
            }
        }
        
        Ok(Self { verified_proofs })
    }

    /// Convert into a vector of verified execution proofs.
    pub fn into_vec(self) -> Vec<VerifiedExecutionProof> {
        self.verified_proofs
    }

    /// Get an iterator over the verified execution proofs.
    pub fn iter(&self) -> impl Iterator<Item = &VerifiedExecutionProof> {
        self.verified_proofs.iter()
    }
}

impl IntoIterator for VerifiedExecutionProofList {
    type Item = VerifiedExecutionProof;
    type IntoIter = std::vec::IntoIter<VerifiedExecutionProof>;

    fn into_iter(self) -> Self::IntoIter {
        self.verified_proofs.into_iter()
    }
}