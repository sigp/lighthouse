/// Keeping this here for now to see if we can encapsulate any behaviour into this. module.

use crate::proof_verification::DynProofVerifier;
// use crate::proof_cache::ProofCache;
use execution_layer::{PayloadStatus, Error as ExecutionLayerError, BlockProposalContentsType};
use std::sync::Arc;
use tokio::sync::RwLock;
use types::{EthSpec, ExecutionBlockHash, ExecPayload};

type PayloadId = [u8; 8];

pub struct ZkVmEngineApi<E: EthSpec> {
    /// Cache for storing and retrieving ZK proofs
    // TODO(zkproofs): Using the cache in the da_checker
    // proof_cache: Arc<RwLock<ProofCache>>,

    /// Verifier for ZK proofs
    proof_verifier: DynProofVerifier,

    /// Track the latest validated execution block hash
    /// TODO(zkproofs): I think we can get this from the beacon chain and it
    /// may not need to be here
    // latest_valid_hash: Arc<RwLock<Option<ExecutionBlockHash>>>,

    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> ZkVmEngineApi<E> {
    pub fn new(
        // proof_cache: Arc<RwLock<ProofCache>>,
        proof_verifier: DynProofVerifier,
    ) -> Self {
        Self {
            // proof_cache,
            proof_verifier,
            // latest_valid_hash: Arc::new(RwLock::new(None)),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Verify a new execution payload using ZK proof
    pub async fn new_payload<'a>(
        &self,
        _execution_payload: &'a impl ExecPayload<E>,
    ) -> Result<PayloadStatus, ExecutionLayerError> {
        // TODO(zkproofs): There are some engine_api checks that should be made, but these should be
        // done when we have the proof
        Ok(PayloadStatus::Syncing)
    }

    /// Update fork choice state
    pub async fn forkchoice_updated(
        &self,
        _head_block_hash: ExecutionBlockHash,
    ) -> Result<PayloadStatus, ExecutionLayerError> {
        // For now, just return Valid status
        Ok(PayloadStatus::Valid)
    }

    /// Get a payload for block production
    pub async fn get_payload(
        &self,
        _payload_id: PayloadId,
    ) -> Result<BlockProposalContentsType<E>, ExecutionLayerError> {
        // TODO(zkproofs): use mev-boost
        Err(ExecutionLayerError::CannotProduceHeader)
    }
}
