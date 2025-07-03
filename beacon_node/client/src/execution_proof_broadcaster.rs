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
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId};

/// Status of proof broadcasting to the network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastStatus {
    /// Proof has not been broadcast yet
    NotBroadcast,
    /// Proof is currently being broadcast
    Broadcasting,
    /// Proof has been successfully broadcast
    Broadcast,
    /// Proof broadcasting failed after retries
    Failed,
}

impl Default for BroadcastStatus {
    fn default() -> Self {
        BroadcastStatus::NotBroadcast
    }
}

/// Broadcast state for a specific execution proof
#[derive(Debug, Clone)]
pub struct ProofBroadcastState {
    /// Current broadcast status of this proof
    pub status: BroadcastStatus,
    /// Number of broadcast attempts made
    pub attempts: u32,
    /// Timestamp of the last broadcast attempt
    pub last_attempt: Option<Duration>,
}

impl ProofBroadcastState {
    /// Create a new broadcast state
    pub fn new() -> Self {
        Self {
            status: BroadcastStatus::NotBroadcast,
            attempts: 0,
            last_attempt: None,
        }
    }

    /// Check if this proof is ready to be broadcast
    pub fn is_ready_to_broadcast(&self) -> bool {
        matches!(
            self.status,
            BroadcastStatus::NotBroadcast | BroadcastStatus::Failed
        )
    }

    /// Mark proof as currently being broadcast
    pub fn mark_broadcasting(&mut self) {
        self.status = BroadcastStatus::Broadcasting;
        self.attempts += 1;
        self.last_attempt = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        );
    }

    /// Mark proof as successfully broadcast
    pub fn mark_broadcast_success(&mut self) {
        self.status = BroadcastStatus::Broadcast;
    }

    /// Mark proof broadcast as failed
    pub fn mark_broadcast_failed(&mut self) {
        self.status = BroadcastStatus::Failed;
    }

    /// Check if broadcast should be retried (failed with attempts under limit)
    pub fn should_retry_broadcast(&self, max_attempts: u32) -> bool {
        matches!(self.status, BroadcastStatus::Failed) && self.attempts < max_attempts
    }
}

impl Default for ProofBroadcastState {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages broadcast state for execution proofs separately from proof storage
#[derive(Debug)]
pub struct ProofBroadcastManager {
    /// Map from (execution block hash, proof ID) to broadcast state
    broadcast_states: RwLock<HashMap<(ExecutionBlockHash, ProofId), ProofBroadcastState>>,
}

impl ProofBroadcastManager {
    /// Create a new broadcast manager
    pub fn new() -> Self {
        Self {
            broadcast_states: RwLock::new(HashMap::new()),
        }
    }

    /// Get broadcast state for a proof, creating a new one if it doesn't exist
    pub fn get_or_create_state(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
    ) -> ProofBroadcastState {
        let mut states = self.broadcast_states.write();
        states
            .entry((block_hash, proof_id))
            .or_insert_with(ProofBroadcastState::new)
            .clone()
    }

    /// Update broadcast state for a proof
    pub fn update_state(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
        state: ProofBroadcastState,
    ) {
        let mut states = self.broadcast_states.write();
        states.insert((block_hash, proof_id), state);
    }

    /// Mark a proof as being broadcast
    pub fn mark_broadcasting(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcasting();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Mark a proof as successfully broadcast
    pub fn mark_broadcast_success(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcast_success();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Mark a proof broadcast as failed
    pub fn mark_broadcast_failed(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcast_failed();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Get all proofs ready for broadcast
    pub fn get_proofs_ready_for_broadcast<T: BeaconChainTypes>(
        &self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut ready_proofs = Vec::new();

        // Get all stored proofs
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();

        for (block_hash, proof_id) in stored_proofs.keys() {
            let state = self.get_or_create_state(*block_hash, *proof_id);
            if state.is_ready_to_broadcast() {
                ready_proofs.push((*block_hash, *proof_id));
            }
        }

        ready_proofs
    }

    /// Get proofs that should be retried
    pub fn get_proofs_for_retry<T: BeaconChainTypes>(
        &self,
        chain: &Arc<BeaconChain<T>>,
        max_attempts: u32,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut retry_proofs = Vec::new();

        // Get all stored proofs
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();

        for (block_hash, proof_id) in stored_proofs.keys() {
            let state = self.get_or_create_state(*block_hash, *proof_id);
            if state.should_retry_broadcast(max_attempts) {
                retry_proofs.push((*block_hash, *proof_id));
            }
        }

        retry_proofs
    }

    /// Clean up old broadcast states for proofs that no longer exist
    pub fn cleanup_old_states<T: BeaconChainTypes>(&self, chain: &Arc<BeaconChain<T>>) {
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();
        let mut states = self.broadcast_states.write();

        // Remove broadcast states for proofs that no longer exist in storage
        states.retain(|key, _| stored_proofs.contains_key(key));
    }
}

/// Configuration for the execution proof broadcaster
#[derive(Debug, Clone)]
pub struct ExecutionProofBroadcasterConfig {
    /// How often to check for unbroadcast proofs
    pub broadcast_interval: Duration,
    /// Maximum number of broadcast attempts per proof
    pub max_broadcast_attempts: u32,
    /// Delay between retries for failed broadcasts
    pub retry_delay: Duration,
}

impl Default for ExecutionProofBroadcasterConfig {
    fn default() -> Self {
        Self {
            broadcast_interval: Duration::from_secs(1), // Check every second
            max_broadcast_attempts: 3,                  // Try up to 3 times
            retry_delay: Duration::from_secs(5),        // Wait 5 seconds between retries
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
    // Only start the broadcaster if not in stateless validation mode
    // (stateless nodes don't generate proofs, they only validate them)
    if !chain.config.stateless_validation {
        let config = ExecutionProofBroadcasterConfig::default();
        let broadcast_manager = Arc::new(ProofBroadcastManager::new());

        info!("Starting execution proof broadcaster service");

        executor.spawn(
            execution_proof_broadcaster_task(chain, network_tx, config, broadcast_manager),
            "execution_proof_broadcaster",
        );
    } else {
        debug!("Skipping execution proof broadcaster service in stateless validation mode");
    }
}

/// Background task that periodically broadcasts unbroadcast execution proofs
pub async fn execution_proof_broadcaster_task<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    config: ExecutionProofBroadcasterConfig,
    broadcast_manager: Arc<ProofBroadcastManager>,
) {
    let mut interval = tokio::time::interval(config.broadcast_interval);

    info!("Starting execution proof broadcaster task");

    loop {
        interval.tick().await;

        // Get proofs ready for initial broadcast
        let ready_proofs = broadcast_manager.get_proofs_ready_for_broadcast(&chain);

        // Get proofs ready for retry
        let retry_proofs =
            broadcast_manager.get_proofs_for_retry(&chain, config.max_broadcast_attempts);

        let total_proofs = ready_proofs.len() + retry_proofs.len();

        if total_proofs > 0 {
            debug!(
                "Found {} proofs ready for broadcast ({} new, {} retries)",
                total_proofs,
                ready_proofs.len(),
                retry_proofs.len()
            );
        }

        // Broadcast ready proofs
        for (execution_block_hash, proof_id) in ready_proofs {
            if let Some(proof) = chain
                .execution_payload_proof_store
                .get_proof(&execution_block_hash, proof_id)
            {
                broadcast_single_proof(
                    &chain,
                    &network_tx,
                    &broadcast_manager,
                    execution_block_hash,
                    proof_id,
                    &proof,
                )
                .await;
            }
        }

        // Broadcast retry proofs (with delay if recently attempted)
        for (execution_block_hash, proof_id) in retry_proofs {
            if let Some(proof) = chain
                .execution_payload_proof_store
                .get_proof(&execution_block_hash, proof_id)
            {
                // Check if enough time has passed since last attempt
                let broadcast_state =
                    broadcast_manager.get_or_create_state(execution_block_hash, proof_id);
                if let Some(last_attempt) = broadcast_state.last_attempt {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();

                    if now.saturating_sub(last_attempt) < config.retry_delay {
                        debug!(
                            "Skipping retry for proof on subnet {} - not enough time since last attempt",
                            proof_id.subnet_id()
                        );
                        continue;
                    }
                }

                debug!(
                    "Retrying broadcast for proof on subnet {} (attempt {})",
                    proof_id.subnet_id(),
                    broadcast_state.attempts + 1
                );

                broadcast_single_proof(
                    &chain,
                    &network_tx,
                    &broadcast_manager,
                    execution_block_hash,
                    proof_id,
                    &proof,
                )
                .await;
            }
        }

        // Periodically clean up old broadcast states
        if total_proofs == 0 {
            broadcast_manager.cleanup_old_states(&chain);
        }
    }
}

/// Broadcast a single execution proof to the gossip network
async fn broadcast_single_proof<T: BeaconChainTypes>(
    _chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    broadcast_manager: &ProofBroadcastManager,
    execution_block_hash: ExecutionBlockHash,
    proof_id: ProofId,
    stored_proof: &beacon_chain::execution_payload_proofs::ExecutionPayloadProof,
) {
    // Mark as currently broadcasting
    if !broadcast_manager.mark_broadcasting(execution_block_hash, proof_id) {
        warn!(
            "Failed to mark proof as broadcasting for block {:?} subnet {}",
            execution_block_hash,
            proof_id.subnet_id()
        );
        return;
    }

    // Convert ExecutionPayloadProof to ExecutionProof (gossip format)
    let gossip_proof = ExecutionProof::new_with_current_timestamp(
        execution_block_hash,
        ExecutionProofSubnetId::new(proof_id.subnet_id()),
        stored_proof.version,
        stored_proof.proof_data.clone(),
    );

    // Create the gossip message
    let pubsub_message = PubsubMessage::ExecutionProofMessage(Box::new((
        ExecutionProofSubnetId::new(proof_id.subnet_id()),
        Arc::new(gossip_proof),
    )));

    // Broadcast the proof
    match network_tx.send(NetworkMessage::Publish {
        messages: vec![pubsub_message],
    }) {
        Ok(()) => {
            // Mark as successfully broadcast
            if broadcast_manager.mark_broadcast_success(execution_block_hash, proof_id) {
                info!(
                    "Successfully broadcast execution proof for block {:?} on subnet {}",
                    execution_block_hash,
                    proof_id.subnet_id()
                );
            } else {
                warn!(
                    "Broadcast succeeded but failed to update proof status for block {:?} subnet {}",
                    execution_block_hash,
                    proof_id.subnet_id()
                );
            }
        }
        Err(e) => {
            // Mark as failed
            if broadcast_manager.mark_broadcast_failed(execution_block_hash, proof_id) {
                warn!(
                    "Failed to broadcast execution proof for block {:?} subnet {}: {}",
                    execution_block_hash,
                    proof_id.subnet_id(),
                    e
                );
            } else {
                warn!(
                    "Broadcast failed and unable to update proof status for block {:?} subnet {}: {}",
                    execution_block_hash,
                    proof_id.subnet_id(),
                    e
                );
            }
        }
    }
}
