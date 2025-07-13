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
            info!(
                "STATELESS_TRACE: Broadcaster found {} proofs to broadcast (ready: {}, retry: {})",
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
                    "STATELESS: Successfully BROADCAST execution proof for block {:?} on subnet {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use beacon_chain::execution_payload_proofs::ExecutionPayloadProof;
    use types::{ExecutionBlockHash, Hash256, MainnetEthSpec};
    use tokio::sync::mpsc;

    type E = MainnetEthSpec;

    #[test]
    fn test_broadcast_status_default() {
        assert_eq!(BroadcastStatus::default(), BroadcastStatus::NotBroadcast);
    }

    #[test]
    fn test_proof_broadcast_state_new() {
        let state = ProofBroadcastState::new();
        assert_eq!(state.status, BroadcastStatus::NotBroadcast);
        assert_eq!(state.attempts, 0);
        assert!(state.last_attempt.is_none());
    }

    #[test]
    fn test_proof_broadcast_state_is_ready_to_broadcast() {
        let mut state = ProofBroadcastState::new();
        assert!(state.is_ready_to_broadcast());

        state.status = BroadcastStatus::Broadcasting;
        assert!(!state.is_ready_to_broadcast());

        state.status = BroadcastStatus::Broadcast;
        assert!(!state.is_ready_to_broadcast());

        state.status = BroadcastStatus::Failed;
        assert!(state.is_ready_to_broadcast());
    }

    #[test]
    fn test_proof_broadcast_state_mark_broadcasting() {
        let mut state = ProofBroadcastState::new();
        state.mark_broadcasting();
        
        assert_eq!(state.status, BroadcastStatus::Broadcasting);
        assert_eq!(state.attempts, 1);
        assert!(state.last_attempt.is_some());
        
        // Test multiple attempts
        state.mark_broadcasting();
        assert_eq!(state.attempts, 2);
    }

    #[test]
    fn test_proof_broadcast_state_mark_success() {
        let mut state = ProofBroadcastState::new();
        state.mark_broadcast_success();
        assert_eq!(state.status, BroadcastStatus::Broadcast);
    }

    #[test]
    fn test_proof_broadcast_state_mark_failed() {
        let mut state = ProofBroadcastState::new();
        state.mark_broadcast_failed();
        assert_eq!(state.status, BroadcastStatus::Failed);
    }

    #[test]
    fn test_proof_broadcast_state_should_retry() {
        let mut state = ProofBroadcastState::new();
        let max_attempts = 3;
        
        // Not failed, shouldn't retry
        assert!(!state.should_retry_broadcast(max_attempts));
        
        // Failed with 0 attempts
        state.status = BroadcastStatus::Failed;
        assert!(state.should_retry_broadcast(max_attempts));
        
        // Failed with attempts under limit
        state.attempts = 2;
        assert!(state.should_retry_broadcast(max_attempts));
        
        // Failed with attempts at limit
        state.attempts = 3;
        assert!(!state.should_retry_broadcast(max_attempts));
        
        // Failed with attempts over limit
        state.attempts = 4;
        assert!(!state.should_retry_broadcast(max_attempts));
    }

    #[test]
    fn test_proof_broadcast_manager_get_or_create_state() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // First access creates new state
        let state1 = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state1.status, BroadcastStatus::NotBroadcast);
        assert_eq!(state1.attempts, 0);
        
        // Second access returns existing state
        let state2 = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state2.status, state1.status);
        assert_eq!(state2.attempts, state1.attempts);
    }

    #[test]
    fn test_proof_broadcast_manager_update_state() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Update with custom state
        let mut custom_state = ProofBroadcastState::new();
        custom_state.status = BroadcastStatus::Broadcast;
        custom_state.attempts = 5;
        
        manager.update_state(block_hash, proof_id, custom_state.clone());
        
        // Verify the update
        let retrieved_state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(retrieved_state.status, BroadcastStatus::Broadcast);
        assert_eq!(retrieved_state.attempts, 5);
    }

    #[test]
    fn test_proof_broadcast_manager_mark_methods() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Test mark_broadcasting
        assert!(manager.mark_broadcasting(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcasting);
        assert_eq!(state.attempts, 1);
        
        // Test mark_broadcast_success
        assert!(manager.mark_broadcast_success(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcast);
        
        // Test mark_broadcast_failed
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        assert!(manager.mark_broadcast_failed(block_hash2, proof_id));
        let state = manager.get_or_create_state(block_hash2, proof_id);
        assert_eq!(state.status, BroadcastStatus::Failed);
    }

    #[tokio::test]
    async fn test_proof_broadcast_manager_get_proofs_ready() {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();
        
        let chain = Arc::new(harness.chain);
        let manager = ProofBroadcastManager::new();
        
        // Add some test proofs to the store
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let proof_id1 = ProofId::custom(1);
        let proof_id2 = ProofId::custom(2);
        
        // Store proofs
        let proof1 = ExecutionPayloadProof::new_v1(
            block_hash1,
            proof_id1,
            vec![1, 2, 3],
        );
        let proof2 = ExecutionPayloadProof::new_v1(
            block_hash2,
            proof_id2,
            vec![4, 5, 6],
        );
        
        assert!(chain.execution_payload_proof_store.store_proof(proof1).is_ok());
        assert!(chain.execution_payload_proof_store.store_proof(proof2).is_ok());
        
        // Initially all proofs should be ready
        let ready = manager.get_proofs_ready_for_broadcast(&chain);
        assert_eq!(ready.len(), 2);
        assert!(ready.contains(&(block_hash1, proof_id1)));
        assert!(ready.contains(&(block_hash2, proof_id2)));
        
        // Mark one as broadcast
        manager.mark_broadcast_success(block_hash1, proof_id1);
        
        // Now only one should be ready
        let ready = manager.get_proofs_ready_for_broadcast(&chain);
        assert_eq!(ready.len(), 1);
        assert!(ready.contains(&(block_hash2, proof_id2)));
    }

    #[tokio::test]
    async fn test_proof_broadcast_manager_get_proofs_for_retry() {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();
        
        let chain = Arc::new(harness.chain);
        let manager = ProofBroadcastManager::new();
        let max_attempts = 3;
        
        // Add test proofs
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Store proofs
        let proof1 = ExecutionPayloadProof::new_v1(block_hash1, proof_id, vec![1, 2, 3]);
        let proof2 = ExecutionPayloadProof::new_v1(block_hash2, proof_id, vec![4, 5, 6]);
        
        assert!(chain.execution_payload_proof_store.store_proof(proof1).is_ok());
        assert!(chain.execution_payload_proof_store.store_proof(proof2).is_ok());
        
        // Initially no proofs should need retry
        let retry = manager.get_proofs_for_retry(&chain, max_attempts);
        assert_eq!(retry.len(), 0);
        
        // Mark one as failed with attempts under limit
        let mut state1 = ProofBroadcastState::new();
        state1.status = BroadcastStatus::Failed;
        state1.attempts = 2;
        manager.update_state(block_hash1, proof_id, state1);
        
        // Mark another as failed but with attempts at limit
        let mut state2 = ProofBroadcastState::new();
        state2.status = BroadcastStatus::Failed;
        state2.attempts = 3;
        manager.update_state(block_hash2, proof_id, state2);
        
        // Only the first should be ready for retry
        let retry = manager.get_proofs_for_retry(&chain, max_attempts);
        assert_eq!(retry.len(), 1);
        assert!(retry.contains(&(block_hash1, proof_id)));
    }

    #[tokio::test]
    async fn test_proof_broadcast_manager_cleanup_old_states() {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();
        
        let chain = Arc::new(harness.chain);
        let manager = ProofBroadcastManager::new();
        
        // Add states for proofs that exist and don't exist
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Store only one proof
        let proof1 = ExecutionPayloadProof::new_v1(block_hash1, proof_id, vec![1, 2, 3]);
        assert!(chain.execution_payload_proof_store.store_proof(proof1).is_ok());
        
        // Create states for both
        manager.mark_broadcasting(block_hash1, proof_id);
        manager.mark_broadcasting(block_hash2, proof_id);
        
        // Verify both states exist
        {
            let states = manager.broadcast_states.read();
            assert_eq!(states.len(), 2);
        }
        
        // Cleanup should remove the state without a corresponding proof
        manager.cleanup_old_states(&chain);
        
        {
            let states = manager.broadcast_states.read();
            assert_eq!(states.len(), 1);
            assert!(states.contains_key(&(block_hash1, proof_id)));
            assert!(!states.contains_key(&(block_hash2, proof_id)));
        }
    }

    #[test]
    fn test_execution_proof_broadcaster_config_default() {
        let config = ExecutionProofBroadcasterConfig::default();
        assert_eq!(config.broadcast_interval, Duration::from_secs(1));
        assert_eq!(config.max_broadcast_attempts, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_success() {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();
        
        let chain = Arc::new(harness.chain);
        let (network_tx, mut network_rx) = mpsc::unbounded_channel();
        let broadcast_manager = ProofBroadcastManager::new();
        
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        let stored_proof = ExecutionPayloadProof::new_v1(
            block_hash,
            proof_id,
            vec![1, 2, 3, 4, 5],
        );
        
        // Broadcast the proof
        broadcast_single_proof(
            &chain,
            &network_tx,
            &broadcast_manager,
            block_hash,
            proof_id,
            &stored_proof,
        ).await;
        
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
        
        // Verify the state was updated
        let state = broadcast_manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcast);
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_network_error() {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();
        
        let chain = Arc::new(harness.chain);
        // Create a closed channel to simulate network error
        let (network_tx, _) = mpsc::unbounded_channel::<NetworkMessage<E>>();
        drop(network_tx);
        let (network_tx_closed, _) = mpsc::unbounded_channel::<NetworkMessage<E>>();
        
        let broadcast_manager = ProofBroadcastManager::new();
        
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        let stored_proof = ExecutionPayloadProof::new_v1(
            block_hash,
            proof_id,
            vec![1, 2, 3],
        );
        
        // Broadcast should handle the error gracefully
        broadcast_single_proof(
            &chain,
            &network_tx_closed,
            &broadcast_manager,
            block_hash,
            proof_id,
            &stored_proof,
        ).await;
        
        // Verify the state was marked as failed
        let state = broadcast_manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Failed);
    }
}
