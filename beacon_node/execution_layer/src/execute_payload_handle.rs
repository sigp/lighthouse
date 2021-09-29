use crate::{ConsensusStatus, ExecutionLayer};
use slog::{crit, error, Logger};
use types::Hash256;

/// Provides a "handle" which should be returned after an `engine_executePayload` call.
///
/// This handle allows the holder to send a valid or invalid message to the execution nodes to
/// indicate the consensus verification status of `self.block_hash`.
///
/// Most notably, this `handle` will send an "invalid" message when it is dropped unless it has
/// already sent a "valid" or "invalid" message. This is to help ensure that any accidental
/// dropping of this handle results in an "invalid" message. Such dropping would be expected when a
/// block verification returns early with an error.
pub struct ExecutePayloadHandle {
    pub(crate) block_hash: Hash256,
    pub(crate) execution_layer: Option<ExecutionLayer>,
    pub(crate) log: Logger,
}

impl ExecutePayloadHandle {
    /// Publish a "valid" message to all nodes for `self.block_hash`.
    pub fn publish_consensus_valid(mut self) {
        self.publish_blocking(ConsensusStatus::Valid)
    }

    /// Publish an "invalid" message to all nodes for `self.block_hash`.
    pub fn publish_consensus_invalid(mut self) {
        self.publish_blocking(ConsensusStatus::Invalid)
    }

    /// Publish the `status` message to all nodes for `self.block_hash`.
    pub async fn publish_async(&mut self, status: ConsensusStatus) {
        if let Some(execution_layer) = self.execution_layer() {
            publish(&execution_layer, self.block_hash, status, &self.log).await
        }
    }

    /// Publishes a message, suitable for running in a non-async context.
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

    /// Takes `self.execution_layer`, it cannot be used to send another duplicate or conflicting
    /// message. Creates a log message if such an attempt is made.
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

/// Publish a `status`, creating a log message if it fails.
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

/// See the struct-level documentation for the reasoning for this `Drop` implementation.
impl Drop for ExecutePayloadHandle {
    fn drop(&mut self) {
        if self.execution_layer.is_some() {
            self.publish_blocking(ConsensusStatus::Invalid)
        }
    }
}
