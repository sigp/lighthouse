use execution_layer::{BlockProposalContentsType, Error as ExecutionLayerError, PayloadStatus};
use types::{EthSpec, ExecPayload, ExecutionBlockHash};

type PayloadId = [u8; 8];

pub struct ZKVMEngineApi<E: EthSpec> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> Default for ZKVMEngineApi<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: EthSpec> ZKVMEngineApi<E> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Verify a new execution payload using ZK proof
    pub async fn new_payload(
        &self,
        _execution_payload: &impl ExecPayload<E>,
    ) -> Result<PayloadStatus, ExecutionLayerError> {
        // TODO(zkproofs): There are some engine_api checks that should be made, but these should be
        // done when we have the proof, check the EL newPayload method to see what these are
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
