use crate::{ConsensusStatus, ExecutionLayer};
use slog::crit;
use types::Hash256;

pub struct ExecutePayloadHandle {
    pub(crate) block_hash: Hash256,
    pub(crate) execution_layer: ExecutionLayer,
}

impl ExecutePayloadHandle {
    pub fn publish_consensus_valid(self) {
        self.publish(ConsensusStatus::Valid)
    }

    pub fn publish_consensus_invalid(self) {
        self.publish(ConsensusStatus::Invalid)
    }

    fn publish(&self, status: ConsensusStatus) {
        if let Err(e) = self.execution_layer.block_on(|execution_layer| {
            execution_layer.consensus_validated(self.block_hash, status)
        }) {
            // TODO(paul): consider how to recover when we are temporarily unable to tell a node
            // that the block was valid.
            crit!(
                self.execution_layer.log(),
                "Failed to update execution consensus status";
                "error" => ?e,
                "status" => ?status,
            );
        }
    }
}

impl Drop for ExecutePayloadHandle {
    fn drop(&mut self) {
        self.publish(ConsensusStatus::Invalid)
    }
}
