//! Background task for broadcasting execution proofs when they become available.
//!
//! This module implements the background proof broadcaster that periodically checks for
//! unbroadcast proofs and broadcasts them to the gossip network. This ensures that
//! proofs generated asynchronously are eventually broadcast, even if they weren't
//! ready during initial block production.

use beacon_chain::execution_payload_proofs::ProofId;
use beacon_chain::{parking_lot::RwLock, BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::{EthSpec, ExecutionBlockHash, ExecutionProof};

/// Information about failed broadcast attempts
#[derive(Debug, Clone)]
struct FailedAttempt {
    /// Number of broadcast attempts made
    attempts: u32,
    /// Timestamp of the last broadcast attempt
    last_attempt: Instant,
}

impl FailedAttempt {
    /// Create a new failed attempt record
    fn new() -> Self {
        Self {
            attempts: 1,
            last_attempt: Instant::now(),
        }
    }

    /// Check if this can be retried based on delay and max attempts
    fn can_retry(&self, max_attempts: u32, retry_delay: Duration) -> bool {
        self.attempts < max_attempts && self.last_attempt.elapsed() >= retry_delay
    }

    /// Increment attempt count and update timestamp
    fn increment(&mut self) {
        self.attempts += 1;
        self.last_attempt = Instant::now();
    }
}

/// Manages broadcast state for execution proofs separately from proof storage
#[derive(Debug)]
struct ProofBroadcastManager {
    /// Proofs queued for broadcast (including retries)
    queued: RwLock<HashSet<(ExecutionBlockHash, ProofId)>>,
    /// Currently broadcasting
    broadcasting: RwLock<HashSet<(ExecutionBlockHash, ProofId)>>,
    /// Failed attempts for retry logic
    failed: RwLock<HashMap<(ExecutionBlockHash, ProofId), FailedAttempt>>,
}

impl ProofBroadcastManager {
    /// Create a new broadcast manager
    fn new() -> Self {
        Self {
            queued: RwLock::new(HashSet::new()),
            broadcasting: RwLock::new(HashSet::new()),
            failed: RwLock::new(HashMap::new()),
        }
    }

    /// Add new proofs to broadcast queue
    fn queue_proofs(&self, proofs: Vec<(ExecutionBlockHash, ProofId)>) {
        let mut queued = self.queued.write();

        for proof in proofs {
            queued.insert(proof);
        }
    }

    /// Get proofs ready to broadcast
    fn get_ready_proofs(
        &self,
        max_attempts: u32,
        retry_delay: Duration,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        let queued = self.queued.read();
        let broadcasting = self.broadcasting.read();
        let failed = self.failed.read();

        queued
            .iter()
            .filter(|p| !broadcasting.contains(p))
            .filter(|p| {
                // Check retry logic for failed proofs
                if let Some(attempt) = failed.get(p) {
                    attempt.can_retry(max_attempts, retry_delay)
                } else {
                    true // Not failed, ready to broadcast
                }
            })
            .cloned()
            .collect()
    }

    /// Mark proof as currently broadcasting
    fn start_broadcast(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) {
        let key = (block_hash, proof_id);

        // Move from queued to broadcasting
        let mut queued = self.queued.write();
        let mut broadcasting = self.broadcasting.write();

        queued.remove(&key);
        broadcasting.insert(key);
    }

    /// Mark proof as successfully broadcast
    fn mark_success(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) {
        let key = (block_hash, proof_id);

        let mut broadcasting = self.broadcasting.write();
        broadcasting.remove(&key);

        // Also remove from failed in case this was a retry
        let mut failed = self.failed.write();
        failed.remove(&key);
    }

    /// Mark proof broadcast as failed
    fn mark_failed(&self, block_hash: ExecutionBlockHash, proof_id: ProofId, max_attempts: u32) {
        let key = (block_hash, proof_id);

        let mut broadcasting = self.broadcasting.write();
        broadcasting.remove(&key);

        // Update or create failed attempt record
        let mut failed = self.failed.write();
        let attempt = failed
            .entry(key)
            .and_modify(|attempt| attempt.increment())
            .or_insert_with(FailedAttempt::new);

        // Check if we've exceeded retry limit
        if attempt.attempts >= max_attempts {
            // Remove from failed tracking
            failed.remove(&key);
            warn!(
                "Proof for block {:?} subnet {} exceeded retry limit ({} attempts), abandoning",
                key.0, *key.1, max_attempts
            );
        } else {
            // Still have retries left, re-add to queued
            let mut queued = self.queued.write();
            queued.insert(key);
        }
    }
}

/// Configuration for the execution proof broadcaster
#[derive(Debug)]
struct ExecutionProofBroadcasterConfig {
    /// How often to check for unbroadcast proofs
    broadcast_interval: Duration,
    /// Maximum number of broadcast attempts per proof
    max_broadcast_attempts: u32,
    /// Delay between retries for failed broadcasts
    retry_delay: Duration,
}

impl Default for ExecutionProofBroadcasterConfig {
    fn default() -> Self {
        Self {
            broadcast_interval: Duration::from_secs(1), // Check every second
            max_broadcast_attempts: 3,                  // Try up to 3 times
            retry_delay: Duration::from_secs(3),        // Wait 3 seconds between retries
        }
    }
}

/// Start the execution proof broadcaster service
/// This spawns the background task that periodically broadcasts unbroadcast execution proofs
pub fn start_execution_proof_broadcaster_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
) {
    // TODO: We use default config, but we could get it from cli
    let config = ExecutionProofBroadcasterConfig::default();
    let broadcast_manager = Arc::new(ProofBroadcastManager::new());

    info!("Starting execution proof broadcaster service");

    executor.spawn(
        execution_proof_broadcaster_task(chain, network_tx, config, broadcast_manager),
        "execution_proof_broadcaster",
    );
}

/// Background task that periodically broadcasts unbroadcast execution proofs
async fn execution_proof_broadcaster_task<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    config: ExecutionProofBroadcasterConfig,
    broadcast_manager: Arc<ProofBroadcastManager>,
) {
    let mut interval = tokio::time::interval(config.broadcast_interval);

    info!("Starting execution proof broadcaster task");

    loop {
        interval.tick().await;

        // Get new unqueued proofs from the proof store
        let new_proofs = chain.execution_payload_proof_store.take_unqueued_proofs();
        if !new_proofs.is_empty() {
            debug!(
                proof_count = new_proofs.len(),
                "Queueing execution proofs for broadcast"
            );
            broadcast_manager.queue_proofs(new_proofs);
        }

        // Get proofs ready to broadcast (new and retries)
        let ready_proofs =
            broadcast_manager.get_ready_proofs(config.max_broadcast_attempts, config.retry_delay);

        // Broadcast each ready proof
        for (execution_block_hash, proof_id) in ready_proofs {
            if let Some(proof) = chain
                .execution_payload_proof_store
                .get_proof(&execution_block_hash, proof_id)
            {
                broadcast_single_proof::<T::EthSpec>(
                    &network_tx,
                    &broadcast_manager,
                    execution_block_hash,
                    proof_id,
                    &proof,
                    config.max_broadcast_attempts,
                )
                .await;
            } else {
                // Proof was removed from store, remove from tracking
                broadcast_manager.mark_success(execution_block_hash, proof_id);
            }
        }
    }
}

/// Broadcast a single execution proof to the gossip network
async fn broadcast_single_proof<E: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<E>>,
    broadcast_manager: &ProofBroadcastManager,
    execution_block_hash: ExecutionBlockHash,
    proof_id: ProofId,
    stored_proof: &ExecutionProof,
    max_attempts: u32,
) {
    // Mark as currently broadcasting
    broadcast_manager.start_broadcast(execution_block_hash, proof_id);

    // Use the stored proof directly (already in ExecutionProof format)
    let gossip_proof = stored_proof.clone();

    // Create the gossip message
    let pubsub_message =
        PubsubMessage::ExecutionProofMessage(Box::new((proof_id, Arc::new(gossip_proof))));

    // Broadcast the proof
    match network_tx.send(NetworkMessage::Publish {
        messages: vec![pubsub_message],
    }) {
        Ok(()) => {
            // Mark as successfully broadcast
            broadcast_manager.mark_success(execution_block_hash, proof_id);
            debug!(
                execution_block_hash = ?execution_block_hash,
                subnet_id = *proof_id,
                "Broadcast execution proof"
            );
        }
        Err(e) => {
            // Mark as failed
            broadcast_manager.mark_failed(execution_block_hash, proof_id, max_attempts);
            warn!(
                execution_block_hash = ?execution_block_hash,
                subnet_id = *proof_id,
                error = %e,
                "Failed to broadcast execution proof"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use types::execution_proof_subnet_id::ExecutionProofSubnetId;
    use types::{ExecutionBlockHash, Hash256, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn test_failed_attempt_new() {
        let attempt = FailedAttempt::new();
        assert_eq!(attempt.attempts, 1);
        assert!(attempt.last_attempt.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_failed_attempt_can_retry() {
        let mut attempt = FailedAttempt::new();

        // Should be able to retry with attempts under limit
        assert!(attempt.can_retry(3, Duration::from_secs(0)));

        // Increment attempts
        attempt.increment();
        assert_eq!(attempt.attempts, 2);
        assert!(attempt.can_retry(3, Duration::from_secs(0)));

        // At limit
        attempt.increment();
        assert_eq!(attempt.attempts, 3);
        assert!(!attempt.can_retry(3, Duration::from_secs(0)));
    }

    #[test]
    fn test_proof_broadcast_manager_queue_proofs() {
        let manager = ProofBroadcastManager::new();
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let proof_id1 = ExecutionProofSubnetId::new(1).unwrap();
        let proof_id2 = ExecutionProofSubnetId::new(2).unwrap();

        // Queue some proofs
        manager.queue_proofs(vec![(block_hash1, proof_id1), (block_hash2, proof_id2)]);

        // Verify they're queued
        {
            let queued = manager.queued.read();
            assert_eq!(queued.len(), 2);
            assert!(queued.contains(&(block_hash1, proof_id1)));
            assert!(queued.contains(&(block_hash2, proof_id2)));
        }

        // Start broadcast for one (moves from queue to broadcasting)
        manager.start_broadcast(block_hash1, proof_id1);
        // Mark one as successful (removes from broadcasting)
        manager.mark_success(block_hash1, proof_id1);

        // Verify it was removed from queue
        {
            let queued = manager.queued.read();
            assert_eq!(queued.len(), 1);
            assert!(!queued.contains(&(block_hash1, proof_id1)));
            assert!(queued.contains(&(block_hash2, proof_id2)));
        }
    }

    #[test]
    fn test_proof_broadcast_manager_get_ready_proofs() {
        let manager = ProofBroadcastManager::new();
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let block_hash3 = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(1).unwrap();

        // Queue some proofs
        manager.queue_proofs(vec![
            (block_hash1, proof_id),
            (block_hash2, proof_id),
            (block_hash3, proof_id),
        ]);

        // Mark one as broadcasting
        manager.start_broadcast(block_hash2, proof_id);

        // Mark one as failed but can retry
        manager.mark_failed(block_hash3, proof_id, 3);

        // Get ready proofs
        let ready = manager.get_ready_proofs(3, Duration::from_secs(0));

        // Should get the non-broadcasting one and the failed one (retry)
        assert_eq!(ready.len(), 2);
        assert!(ready.contains(&(block_hash1, proof_id)));
        assert!(ready.contains(&(block_hash3, proof_id)));
        assert!(!ready.contains(&(block_hash2, proof_id)));
    }

    #[test]
    fn test_proof_broadcast_manager_mark_methods() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(1).unwrap();

        // Queue a proof
        manager.queue_proofs(vec![(block_hash, proof_id)]);

        // Start broadcast
        manager.start_broadcast(block_hash, proof_id);
        {
            let broadcasting = manager.broadcasting.read();
            assert!(broadcasting.contains(&(block_hash, proof_id)));
        }

        // Mark as success
        manager.mark_success(block_hash, proof_id);
        {
            let queued = manager.queued.read();
            let broadcasting = manager.broadcasting.read();
            let failed = manager.failed.read();

            assert!(!queued.contains(&(block_hash, proof_id)));
            assert!(!broadcasting.contains(&(block_hash, proof_id)));
            assert!(!failed.contains_key(&(block_hash, proof_id)));
        }
    }

    #[test]
    fn test_proof_broadcast_manager_retry_logic() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(1).unwrap();

        // Queue and fail multiple times
        manager.queue_proofs(vec![(block_hash, proof_id)]);

        // First failure - start broadcast, then fail
        manager.start_broadcast(block_hash, proof_id);
        manager.mark_failed(block_hash, proof_id, 3);
        {
            let failed = manager.failed.read();
            let attempt = failed.get(&(block_hash, proof_id)).unwrap();
            assert_eq!(attempt.attempts, 1);
        }

        // Second failure - start broadcast, then fail
        manager.start_broadcast(block_hash, proof_id);
        manager.mark_failed(block_hash, proof_id, 3);
        {
            let failed = manager.failed.read();
            let attempt = failed.get(&(block_hash, proof_id)).unwrap();
            assert_eq!(attempt.attempts, 2);
        }

        // At max attempts (3) - start broadcast, then fail
        manager.start_broadcast(block_hash, proof_id);
        manager.mark_failed(block_hash, proof_id, 3);
        let ready = manager.get_ready_proofs(3, Duration::from_secs(0));
        assert!(!ready.contains(&(block_hash, proof_id)));
    }

    #[test]
    fn test_execution_proof_broadcaster_config_default() {
        let config = ExecutionProofBroadcasterConfig::default();
        assert_eq!(config.broadcast_interval, Duration::from_secs(1));
        assert_eq!(config.max_broadcast_attempts, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_success() {
        let (network_tx, mut network_rx) = mpsc::unbounded_channel();
        let broadcast_manager = ProofBroadcastManager::new();

        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(1).unwrap();
        let stored_proof = ExecutionProof::new(block_hash, proof_id, 1, vec![1, 2, 3, 4, 5]);

        // Broadcast the proof
        broadcast_single_proof::<E>(
            &network_tx,
            &broadcast_manager,
            block_hash,
            proof_id,
            &stored_proof,
            3, // max_attempts
        )
        .await;

        // Verify the network message was sent
        let msg = network_rx.recv().await;
        assert!(msg.is_some());

        if let Some(NetworkMessage::Publish { messages }) = msg {
            assert_eq!(messages.len(), 1);
            if let PubsubMessage::ExecutionProofMessage(proof_box) = &messages[0] {
                let (subnet_id, proof) = proof_box.as_ref();
                assert_eq!(u64::from(subnet_id), 1);
                assert_eq!(proof.block_hash, block_hash);
                assert_eq!(proof.proof_data, vec![1, 2, 3, 4, 5]);
            } else {
                panic!("Expected ExecutionProofMessage");
            }
        } else {
            panic!("Expected Publish message");
        }

        // Verify the proof was removed from tracking
        {
            let queued = broadcast_manager.queued.read();
            let broadcasting = broadcast_manager.broadcasting.read();
            assert!(!queued.contains(&(block_hash, proof_id)));
            assert!(!broadcasting.contains(&(block_hash, proof_id)));
        }
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_network_error() {
        // Create a closed channel to simulate network error
        let (network_tx, _) = mpsc::unbounded_channel::<NetworkMessage<E>>();
        drop(network_tx);
        let (network_tx_closed, _) = mpsc::unbounded_channel::<NetworkMessage<E>>();

        let broadcast_manager = ProofBroadcastManager::new();

        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(1).unwrap();
        let stored_proof = ExecutionProof::new(block_hash, proof_id, 1, vec![1, 2, 3]);

        // Broadcast should handle the error gracefully
        broadcast_single_proof::<E>(
            &network_tx_closed,
            &broadcast_manager,
            block_hash,
            proof_id,
            &stored_proof,
            3, // max_attempts
        )
        .await;

        // Verify the proof was marked as failed
        {
            let failed = broadcast_manager.failed.read();
            assert!(failed.contains_key(&(block_hash, proof_id)));
        }
    }
}
