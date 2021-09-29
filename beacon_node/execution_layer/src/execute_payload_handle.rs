use crate::{ConsensusStatus, ExecutionLayer};
use slog::crit;
use types::Hash256;

pub struct ExecutePayloadHandle {
    pub(crate) block_hash: Hash256,
    pub(crate) execution_layer: ExecutionLayer,
    pub(crate) status: Option<ConsensusStatus>,
}

impl ExecutePayloadHandle {
    pub fn publish_consensus_valid(mut self) {
        self.publish(ConsensusStatus::Valid)
    }

    pub fn publish_consensus_invalid(mut self) {
        self.publish(ConsensusStatus::Invalid)
    }

    pub async fn publish_async(&self) {
        if let Err(e) =
            self.execution_layer.consensus_validated(self.block_hash, status).await {
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

    fn publish(&mut self, status: ConsensusStatus) {
        self.status = Some(status);

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
        if self.status.is_none() {
            self.publish(ConsensusStatus::Invalid)
        }
    }
}
