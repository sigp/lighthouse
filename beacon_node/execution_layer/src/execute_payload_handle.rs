use crate::{ConsensusStatus, ExecutionLayer};
use slog::{crit, error, Logger};
use types::Hash256;

pub struct ExecutePayloadHandle {
    pub(crate) block_hash: Hash256,
    pub(crate) execution_layer: Option<ExecutionLayer>,
    pub(crate) log: Logger,
}

impl ExecutePayloadHandle {
    pub fn publish_consensus_valid(mut self) {
        self.publish_blocking(ConsensusStatus::Valid)
    }

    pub fn publish_consensus_invalid(mut self) {
        self.publish_blocking(ConsensusStatus::Invalid)
    }

    pub async fn publish_async(&mut self, status: ConsensusStatus) {
        if let Some(execution_layer) = self.execution_layer() {
            publish(&execution_layer, self.block_hash, status, &self.log).await
        }
    }

    fn publish_blocking(&mut self, status: ConsensusStatus) {
        if let Some(execution_layer) = self.execution_layer() {
            let log = &self.log.clone();
            let block_hash = self.block_hash;
            if let Err(e) = execution_layer.block_on(|execution_layer| async move {
                publish(execution_layer, block_hash, status, log).await;
                Ok(())
            }) {
                error!(
                    self.log,
                    "Failed to spawn payload status task";
                    "error" => ?e,
                    "block_hash" => ?block_hash,
                    "status" => ?status,
                );
            }
        }
    }

    fn execution_layer(&mut self) -> Option<ExecutionLayer> {
        let execution_layer = self.execution_layer.take();
        if execution_layer.is_none() {
            crit!(
                self.log,
                "Double usage of ExecutePayloadHandle";
                "block_hash" => ?self.block_hash,
            );
        }
        execution_layer
    }
}

async fn publish(
    execution_layer: &ExecutionLayer,
    block_hash: Hash256,
    status: ConsensusStatus,
    log: &Logger,
) {
    if let Err(e) = execution_layer
        .consensus_validated(block_hash, status)
        .await
    {
        // TODO(paul): consider how to recover when we are temporarily unable to tell a node
        // that the block was valid.
        crit!(
            log,
            "Failed to update execution consensus status";
            "error" => ?e,
            "block_hash" => ?block_hash,
            "status" => ?status,
        );
    }
}

impl Drop for ExecutePayloadHandle {
    fn drop(&mut self) {
        if self.execution_layer.is_none() {
            self.publish_blocking(ConsensusStatus::Invalid)
        }
    }
}
