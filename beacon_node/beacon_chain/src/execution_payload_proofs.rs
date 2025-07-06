use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use types::{EthSpec, ExecutionBlockHash, ExecutionPayload, Hash256};

/// Default maximum number of execution proof subnets for non-stateless nodes
/// This determines how many subnets non-stateless nodes will subscribe to by default
/// TODO: ProofId can then just be a u8
pub const DEFAULT_MAX_EXECUTION_PROOF_SUBNETS: u64 = 8;

/// Identifier for different types of proofs that can be received for execution payloads
/// Each proof ID will be received on a different gossip subnet
/// The u64 value can be mapped to subnet numbers for easy routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub u64);

impl ProofId {
    /// Execution witness proof (subnet 0)
    /// This is the standard execution payload witness proof
    pub const EXECUTION_WITNESS: ProofId = ProofId(0);

    /// Create a custom proof ID for specific zkVMs
    /// Each zkVM (e.g., SP1, RISC-V, zkEVM) will have its own subnet and proof ID
    /// For example:
    /// - SP1 proofs: ProofId::custom(1) → subnet 1
    /// - RISC-V proofs: ProofId::custom(2) → subnet 2  
    /// - zkEVM proofs: ProofId::custom(3) → subnet 3
    /// - etc.
    pub const fn custom(id: u64) -> Self {
        ProofId(id)
    }

    /// Get the numeric ID (useful for subnet mapping)
    pub fn id(&self) -> u64 {
        self.0
    }

    /// Get the gossip subnet ID for this proof type
    /// Direct one-to-one mapping: ProofId IS the subnet ID
    pub fn subnet_id(&self) -> u64 {
        self.0
    }

    /// Get the gossip topic name for this proof type
    pub fn subnet_topic(&self) -> String {
        format!("execution_proof_{}", self.0)
    }

    /// Get a string identifier for this proof type
    /// This can be used for logging, metrics, and subnet naming
    pub fn identifier(&self) -> &'static str {
        match self.0 {
            0 => "execution_witness",
            _ => "custom",
        }
    }

    /// Get a human-readable description of the proof type
    pub fn description(&self) -> String {
        match self.0 {
            0 => "Execution witness proof".to_string(),
            _ => format!("Custom proof type {}", self.0),
        }
    }
}

/// Represents a proof for an execution payload
/// Multiple proof types can exist for a single execution payload
#[derive(Debug, Clone)]
pub struct ExecutionPayloadProof {
    /// The execution block hash this proof attests to
    pub block_hash: ExecutionBlockHash,
    /// The ID of the proof type (maps to gossip subnet)
    pub proof_id: ProofId,
    /// Version of the proof format - allows for one subnet to upgrade their proof without all needing to
    pub version: u32,
    /// Opaque proof data - structure depends on proof_id and version
    /// This will contain cryptographic proofs received via gossip
    pub proof_data: Vec<u8>,
    /// Timestamp when this proof was received/stored
    pub timestamp: u64,
}

impl ExecutionPayloadProof {
    /// Create a new execution payload proof
    pub fn new(
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
        version: u32,
        proof_data: Vec<u8>,
    ) -> Self {
        Self {
            block_hash,
            proof_id,
            version,
            proof_data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a new execution payload proof with default version (1)
    pub fn new_v1(block_hash: ExecutionBlockHash, proof_id: ProofId, proof_data: Vec<u8>) -> Self {
        Self::new(block_hash, proof_id, 1, proof_data)
    }

    /// Check if this proof version is supported
    pub fn is_version_supported(&self) -> bool {
        matches!(self.version, 1)
    }

    /// Get a description of the proof including type and version
    pub fn description(&self) -> String {
        format!("{} v{}", self.proof_id.description(), self.version)
    }

    /// Get the identifier string for this proof (useful for metrics/logging)
    pub fn identifier(&self) -> String {
        format!("{}_v{}", self.proof_id.identifier(), self.version)
    }
}

/// Storage for execution payload proofs
/// Designed to be thread-safe and efficient for concurrent access
/// Supports multiple proof types per execution payload
/// 
/// Workflow:
/// 1. When spawning proofs: BeaconBlockHash → ExecutionPayload (via extract_execution_payload)
/// 2. Proof generation receives concrete ExecutionPayload<E> 
/// 3. Proofs are stored using ExecutionBlockHash as key (extracted from payload)
/// 4. Verification looks up proofs by ExecutionBlockHash
#[derive(Debug)]
pub struct ExecutionPayloadProofStore {
    /// Map from (execution block hash, proof ID) to proof
    /// This allows multiple proof types for the same execution payload
    /// TODO: Handle orphaned proofs - proofs that arrive for blocks we never imported
    proofs: Arc<RwLock<HashMap<(ExecutionBlockHash, ProofId), ExecutionPayloadProof>>>,
    /// Reverse mapping: execution block hash -> beacon block roots waiting for proofs
    /// This allows efficient lookup of which beacon blocks to re-evaluate when proofs arrive
    ///
    /// TODO: need to verify the following Note, on one execution payload mapping to multiple beacon blocks
    /// TODO: If not the case, then it becomes a 1-1 mapping
    ///
    /// Note: Multiple beacon block roots can share the same execution block hash in fork scenarios.
    /// For example, during consensus layer forks, competing beacon blocks may contain the same
    /// execution payload, resulting in multiple beacon block roots waiting for the same execution proof.
    pending_blocks: Arc<RwLock<HashMap<ExecutionBlockHash, Vec<Hash256>>>>,
    /// Maximum number of proofs to store (LRU eviction)
    max_proofs: usize,
}

impl ExecutionPayloadProofStore {
    /// Create a new proof store with given capacity
    pub fn new(max_proofs: usize) -> Self {
        Self {
            proofs: Arc::new(RwLock::new(HashMap::new())),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            max_proofs,
        }
    }

    /// Check if we have any proof for the given execution block hash
    /// Returns true if at least one proof type exists (all stored proofs are pre-validated)
    pub fn has_valid_proof(&self, block_hash: &ExecutionBlockHash) -> bool {
        let proofs = self.proofs.read();
        proofs.keys().any(|(hash, _proof_id)| hash == block_hash)
    }

    /// Check if we have a proof for a specific proof ID and execution block hash
    /// Returns true if the proof exists (all stored proofs are pre-validated)
    pub fn has_valid_proof_for_id(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool {
        let proofs = self.proofs.read();
        proofs.contains_key(&(*block_hash, proof_id))
    }

    /// Get all proofs for the given execution block hash
    pub fn get_proofs(&self, block_hash: &ExecutionBlockHash) -> Vec<ExecutionPayloadProof> {
        let proofs = self.proofs.read();
        proofs
            .iter()
            .filter_map(|((hash, _proof_id), proof)| {
                if hash == block_hash {
                    Some(proof.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all stored proofs (for broadcast management)
    pub fn get_all_proofs(&self) -> HashMap<(ExecutionBlockHash, ProofId), ExecutionPayloadProof> {
        self.proofs.read().clone()
    }

    /// Get a specific proof for the given execution block hash and proof ID
    pub fn get_proof(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> Option<ExecutionPayloadProof> {
        let proofs = self.proofs.read();
        proofs.get(&(*block_hash, proof_id)).cloned()
    }

    /// Store a proof for an execution payload after validation
    /// This method validates the proof before storing it
    /// TODO: This will be called when proofs are received via gossip subnet
    pub fn store_proof(&self, proof: ExecutionPayloadProof) -> Result<(), String> {
        // Validate the proof before storing
        if !Self::validate_proof(&proof) {
            return Err(format!(
                "Invalid proof for block hash {:?}, proof ID {}: validation failed",
                proof.block_hash,
                proof.proof_id.id()
            ));
        }

        let mut proofs = self.proofs.write();

        // Simple LRU eviction if we're at capacity
        if proofs.len() >= self.max_proofs {
            // Remove the oldest proof
            if let Some(oldest_key) = proofs
                .iter()
                .min_by_key(|(_, proof)| proof.timestamp)
                .map(|(key, _)| *key)
            {
                proofs.remove(&oldest_key);
            }
        }

        let key = (proof.block_hash, proof.proof_id);
        proofs.insert(key, proof);
        Ok(())
    }

    /// Store a proof for an execution payload without validation
    /// This method assumes the proof has already been validated
    /// Use this when you've already validated the proof externally
    pub fn store_validated_proof(&self, proof: ExecutionPayloadProof) {
        let mut proofs = self.proofs.write();

        // Simple LRU eviction if we're at capacity
        if proofs.len() >= self.max_proofs {
            // Remove the oldest proof
            if let Some(oldest_key) = proofs
                .iter()
                .min_by_key(|(_, proof)| proof.timestamp)
                .map(|(key, _)| *key)
            {
                proofs.remove(&oldest_key);
            }
        }

        let key = (proof.block_hash, proof.proof_id);
        proofs.insert(key, proof);
    }

    /// Get the total number of stored proofs (across all proof types and payloads)
    pub fn len(&self) -> usize {
        self.proofs.read().len()
    }

    /// Get the number of unique payloads that have at least one proof
    pub fn unique_payload_count(&self) -> usize {
        let proofs = self.proofs.read();
        let unique_hashes: std::collections::HashSet<ExecutionBlockHash> =
            proofs.keys().map(|(hash, _proof_id)| *hash).collect();
        unique_hashes.len()
    }

    /// Get the number of proofs for a specific execution block hash
    pub fn proof_count_for_payload(&self, block_hash: &ExecutionBlockHash) -> usize {
        let proofs = self.proofs.read();
        proofs
            .keys()
            .filter(|(hash, _proof_id)| hash == block_hash)
            .count()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.proofs.read().is_empty()
    }

    /// Clear all stored proofs
    pub fn clear(&self) {
        self.proofs.write().clear();
    }

    /// Remove proofs older than the given timestamp
    pub fn prune_old_proofs(&self, cutoff_timestamp: u64) {
        let mut proofs = self.proofs.write();
        proofs.retain(|_, proof| proof.timestamp >= cutoff_timestamp);
    }

    /// Generate a dummy proof for testing purposes
    /// TODO: Replace with actual proof generation from zkVMs or other proof systems
    ///
    /// This accepts the concrete ExecutionPayload<E> type which is what the EL expects
    /// and can be easily serialized for sending to external systems.
    pub fn generate_dummy_proof<T: EthSpec>(
        payload: &ExecutionPayload<T>,
        proof_id: ProofId,
    ) -> ExecutionPayloadProof {
        let execution_block_hash = payload.block_hash();
        let block_number = payload.block_number();

        // Create dummy proof data that includes the subnet information and payload details
        let dummy_data = format!(
            "dummy_proof_subnet_{}_block_{:?}_number_{}_timestamp_{}",
            proof_id.subnet_id(),
            execution_block_hash,
            block_number,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        )
        .into_bytes();

        ExecutionPayloadProof::new_v1(execution_block_hash, proof_id, dummy_data)
    }

    /// Generate and store a dummy proof for the given execution payload and proof ID
    /// This is a convenience method that combines proof generation and storage
    pub fn generate_and_store_dummy_proof<T: EthSpec>(
        &self,
        payload: &ExecutionPayload<T>,
        proof_id: ProofId,
    ) -> Result<ExecutionPayloadProof, String> {
        let proof = Self::generate_dummy_proof(payload, proof_id);
        self.store_proof(proof.clone())?;
        Ok(proof)
    }


    /// Validate a proof (placeholder implementation)
    /// TODO: Implement actual cryptographic proof validation based on version and type
    pub fn validate_proof(proof: &ExecutionPayloadProof) -> bool {
        // Placeholder validation - in reality this would verify cryptographic proofs
        // based on both proof_type and version
        match proof.version {
            1 => {
                // Version 1 validation: non-empty data
                !proof.proof_data.is_empty()
            }
            _ => {
                // Unknown version - consider invalid
                // In the future, might want to have version-specific validation
                false
            }
        }
    }

    /// Register a beacon block as pending proof for the given execution block hash
    /// This is called when a block is imported optimistically and needs proof validation
    /// Prevents duplicate registration of the same block
    pub fn register_pending_block(
        &self,
        execution_block_hash: ExecutionBlockHash,
        beacon_block_root: Hash256,
    ) {
        let mut pending = self.pending_blocks.write();
        let blocks = pending.entry(execution_block_hash).or_insert_with(Vec::new);

        // Only add if not already present (duplicate protection)
        if !blocks.contains(&beacon_block_root) {
            blocks.push(beacon_block_root);
        }
    }

    /// Get beacon block roots that are pending proofs for the given execution block hash
    /// Returns empty vec if no blocks are pending
    pub fn get_pending_blocks(&self, execution_block_hash: &ExecutionBlockHash) -> Vec<Hash256> {
        self.pending_blocks
            .read()
            .get(execution_block_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove and return pending blocks for the given execution block hash
    /// This is called when proofs arrive and blocks are re-evaluated
    pub fn take_pending_blocks(&self, execution_block_hash: &ExecutionBlockHash) -> Vec<Hash256> {
        self.pending_blocks
            .write()
            .remove(execution_block_hash)
            .unwrap_or_default()
    }

    /// Remove a specific beacon block from the pending list
    /// This is useful when blocks are finalized or pruned
    pub fn remove_pending_block(
        &self,
        execution_block_hash: &ExecutionBlockHash,
        beacon_block_root: Hash256,
    ) {
        let mut pending = self.pending_blocks.write();
        if let Some(blocks) = pending.get_mut(execution_block_hash) {
            blocks.retain(|&block_root| block_root != beacon_block_root);
            // Remove the entry if no blocks are left
            if blocks.is_empty() {
                pending.remove(execution_block_hash);
            }
        }
    }

    /// Get the number of execution block hashes that have pending blocks
    pub fn pending_execution_hashes_count(&self) -> usize {
        self.pending_blocks.read().len()
    }

    /// Get the total number of pending beacon blocks across all execution hashes
    pub fn total_pending_blocks_count(&self) -> usize {
        self.pending_blocks
            .read()
            .values()
            .map(|blocks| blocks.len())
            .sum()
    }

    /// Clean up pending blocks that have been finalized or are no longer needed
    /// This should be called periodically to prevent memory leaks
    /// Uses a two-phase approach to avoid holding locks during callback execution
    /// TODO: Test edge case where we receive a lot of pending blocks and cannot
    /// TODO: finalize
    pub fn cleanup_finalized_pending_blocks<F>(&self, should_remove: F) -> usize
    where
        F: Fn(Hash256) -> bool,
    {
        use std::collections::HashSet;

        // Collect all block roots to check (read-only access)
        let blocks_to_check: Vec<Hash256> = {
            let pending = self.pending_blocks.read();
            pending.values().flatten().copied().collect()
        };

        // Determine which blocks should be removed (no locks held during callback)
        let blocks_to_remove: HashSet<Hash256> = blocks_to_check
            .into_iter()
            .filter(|&block_root| should_remove(block_root))
            .collect();

        // Remove the identified blocks (short-duration write lock)
        let mut pending = self.pending_blocks.write();
        let mut removed_count = 0;
        let mut execution_hashes_to_remove = Vec::new();

        for (execution_hash, blocks) in pending.iter_mut() {
            let original_len = blocks.len();
            blocks.retain(|&block_root| !blocks_to_remove.contains(&block_root));
            removed_count += original_len - blocks.len();

            // Mark execution hash for removal if no blocks remain
            if blocks.is_empty() {
                execution_hashes_to_remove.push(*execution_hash);
            }
        }

        // Remove empty execution hash entries
        for execution_hash in execution_hashes_to_remove {
            pending.remove(&execution_hash);
        }

        removed_count
    }

    /// Remove all pending blocks older than the given slot
    /// This is a simpler cleanup method when you have access to block slot information
    pub fn cleanup_pending_blocks_by_slot<F>(&self, is_old_block: F) -> usize
    where
        F: Fn(Hash256) -> bool,
    {
        self.cleanup_finalized_pending_blocks(is_old_block)
    }
}

impl Default for ExecutionPayloadProofStore {
    fn default() -> Self {
        // Default to storing 10,000 proofs
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    #[test]
    fn test_proof_store_basic_operations() {
        let store = ExecutionPayloadProofStore::new(4);
        let hash1 = ExecutionBlockHash::from(Hash256::random());
        let hash2 = ExecutionBlockHash::from(Hash256::random());

        // Initially empty
        assert!(!store.has_valid_proof(&hash1));
        assert_eq!(store.len(), 0);
        assert_eq!(store.unique_payload_count(), 0);

        // Store an execution witness proof for hash1
        let proof1 =
            ExecutionPayloadProof::new_v1(hash1, ProofId::EXECUTION_WITNESS, vec![1, 2, 3]);
        store
            .store_proof(proof1.clone())
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof_for_id(&hash1, ProofId::EXECUTION_WITNESS));
        assert!(!store.has_valid_proof_for_id(&hash1, ProofId::custom(1)));
        assert_eq!(store.len(), 1);
        assert_eq!(store.unique_payload_count(), 1);
        assert_eq!(store.proof_count_for_payload(&hash1), 1);

        // Store a custom zkVM proof for the same hash1
        let proof1_custom = ExecutionPayloadProof::new_v1(hash1, ProofId::custom(1), vec![7, 8, 9]);
        store
            .store_proof(proof1_custom)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof_for_id(&hash1, ProofId::EXECUTION_WITNESS));
        assert!(store.has_valid_proof_for_id(&hash1, ProofId::custom(1)));
        assert_eq!(store.len(), 2);
        assert_eq!(store.unique_payload_count(), 1); // Still 1 unique payload
        assert_eq!(store.proof_count_for_payload(&hash1), 2);

        // Store a proof for hash2
        let proof2 = ExecutionPayloadProof::new_v1(hash2, ProofId::custom(2), vec![4, 5, 6]);
        store
            .store_proof(proof2)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash2));
        assert!(store.has_valid_proof_for_id(&hash2, ProofId::custom(2)));
        assert_eq!(store.len(), 3);
        assert_eq!(store.unique_payload_count(), 2);
        assert_eq!(store.proof_count_for_payload(&hash2), 1);

        // Get all proofs for hash1
        let hash1_proofs = store.get_proofs(&hash1);
        assert_eq!(hash1_proofs.len(), 2);
    }

    #[test]
    fn test_proof_validation() {
        let store = ExecutionPayloadProofStore::new(10);
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Valid proof (non-empty data) should store successfully
        let valid_proof =
            ExecutionPayloadProof::new_v1(hash, ProofId::EXECUTION_WITNESS, vec![1, 2, 3]);
        assert!(ExecutionPayloadProofStore::validate_proof(&valid_proof));
        assert!(store.store_proof(valid_proof).is_ok());
        assert!(store.has_valid_proof(&hash));

        // Invalid proof (empty data) should fail to store
        let invalid_proof = ExecutionPayloadProof::new_v1(hash, ProofId::custom(1), vec![]);
        assert!(!ExecutionPayloadProofStore::validate_proof(&invalid_proof));
        assert!(store.store_proof(invalid_proof).is_err());
        // Should still only have the first proof
        assert_eq!(store.proof_count_for_payload(&hash), 1);
        assert!(!store.has_valid_proof_for_id(&hash, ProofId::custom(1)));
    }

    #[test]
    fn test_lru_eviction() {
        let store = ExecutionPayloadProofStore::new(2);
        let hash1 = ExecutionBlockHash::from(Hash256::random());
        let hash2 = ExecutionBlockHash::from(Hash256::random());
        let hash3 = ExecutionBlockHash::from(Hash256::random());

        // Create proofs with manually set timestamps to ensure proper ordering
        let mut proof1 = ExecutionPayloadProof::new_v1(hash1, ProofId::EXECUTION_WITNESS, vec![1]);
        proof1.timestamp = 100; // Oldest

        let mut proof2 = ExecutionPayloadProof::new_v1(hash2, ProofId::custom(1), vec![2]);
        proof2.timestamp = 200; // Middle

        let mut proof3 = ExecutionPayloadProof::new_v1(hash3, ProofId::custom(2), vec![3]);
        proof3.timestamp = 300; // Newest

        // Store first proof
        store
            .store_proof(proof1)
            .expect("valid proof should store successfully");
        assert_eq!(store.len(), 1);
        assert!(store.has_valid_proof(&hash1));

        // Store second proof
        store
            .store_proof(proof2)
            .expect("valid proof should store successfully");
        assert_eq!(store.len(), 2);
        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof(&hash2));

        // Store a third proof, should evict the oldest (hash1)
        store
            .store_proof(proof3)
            .expect("valid proof should store successfully");

        assert_eq!(store.len(), 2);
        assert!(!store.has_valid_proof(&hash1)); // Evicted (oldest)
        assert!(store.has_valid_proof(&hash2)); // Kept (middle)
        assert!(store.has_valid_proof(&hash3)); // Kept (newest)
    }

    #[test]
    fn test_multiple_proof_types_per_payload() {
        let store = ExecutionPayloadProofStore::new(10);
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Store different proof types for the same payload
        store
            .store_proof(ExecutionPayloadProof::new_v1(
                hash,
                ProofId::EXECUTION_WITNESS,
                vec![1, 2, 3],
            ))
            .expect("valid proof should store successfully");
        store
            .store_proof(ExecutionPayloadProof::new_v1(
                hash,
                ProofId::custom(1),
                vec![4, 5, 6],
            ))
            .expect("valid proof should store successfully");
        store
            .store_proof(ExecutionPayloadProof::new_v1(
                hash,
                ProofId::custom(2),
                vec![7, 8, 9],
            ))
            .expect("valid proof should store successfully");

        // Should have all three proof types
        assert!(store.has_valid_proof_for_id(&hash, ProofId::EXECUTION_WITNESS));
        assert!(store.has_valid_proof_for_id(&hash, ProofId::custom(1)));
        assert!(store.has_valid_proof_for_id(&hash, ProofId::custom(2)));
        assert!(!store.has_valid_proof_for_id(&hash, ProofId::custom(3)));

        // Should have valid proof overall
        assert!(store.has_valid_proof(&hash));

        // Get all proofs for this payload
        let proofs = store.get_proofs(&hash);
        assert_eq!(proofs.len(), 3);

        // Verify counts
        assert_eq!(store.len(), 3);
        assert_eq!(store.unique_payload_count(), 1);
        assert_eq!(store.proof_count_for_payload(&hash), 3);
    }

    #[test]
    fn test_proof_id_methods() {
        // Test execution witness proof ID
        assert_eq!(ProofId::EXECUTION_WITNESS.id(), 0);
        assert_eq!(ProofId::EXECUTION_WITNESS.identifier(), "execution_witness");
        assert_eq!(
            ProofId::EXECUTION_WITNESS.description(),
            "Execution witness proof"
        );

        // Test custom proof IDs (for different zkVMs)
        let sp1_proof = ProofId::custom(1);
        assert_eq!(sp1_proof.id(), 1);
        assert_eq!(sp1_proof.identifier(), "custom");
        assert_eq!(sp1_proof.description(), "Custom proof type 1");

        let risc_v_proof = ProofId::custom(2);
        assert_eq!(risc_v_proof.id(), 2);
        assert_eq!(risc_v_proof.identifier(), "custom");
        assert_eq!(risc_v_proof.description(), "Custom proof type 2");

        let zkvm_proof = ProofId::custom(100);
        assert_eq!(zkvm_proof.id(), 100);
        assert_eq!(zkvm_proof.identifier(), "custom");
        assert_eq!(zkvm_proof.description(), "Custom proof type 100");
    }

    #[test]
    fn test_proof_versions() {
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Test version 1 proof (supported)
        let v1_proof =
            ExecutionPayloadProof::new_v1(hash, ProofId::EXECUTION_WITNESS, vec![1, 2, 3]);
        assert_eq!(v1_proof.version, 1);
        assert!(v1_proof.is_version_supported());
        assert!(ExecutionPayloadProofStore::validate_proof(&v1_proof));
        assert_eq!(v1_proof.description(), "Execution witness proof v1");
        assert_eq!(v1_proof.identifier(), "execution_witness_v1");

        // Test explicit version constructor with custom proof ID
        let v1_explicit = ExecutionPayloadProof::new(hash, ProofId::custom(1), 1, vec![4, 5, 6]);
        assert_eq!(v1_explicit.version, 1);
        assert!(v1_explicit.is_version_supported());
        assert!(ExecutionPayloadProofStore::validate_proof(&v1_explicit));
        assert_eq!(v1_explicit.description(), "Custom proof type 1 v1");
        assert_eq!(v1_explicit.identifier(), "custom_v1");

        // Test unsupported version
        let v2_proof =
            ExecutionPayloadProof::new(hash, ProofId::EXECUTION_WITNESS, 2, vec![7, 8, 9]);
        assert_eq!(v2_proof.version, 2);
        assert!(!v2_proof.is_version_supported());
        assert!(!ExecutionPayloadProofStore::validate_proof(&v2_proof)); // Should fail validation for unknown version
        assert_eq!(v2_proof.description(), "Execution witness proof v2");
        assert_eq!(v2_proof.identifier(), "execution_witness_v2");

        // Test empty data with version 1 (should be invalid)
        let empty_v1 = ExecutionPayloadProof::new_v1(hash, ProofId::EXECUTION_WITNESS, vec![]);
        assert!(!ExecutionPayloadProofStore::validate_proof(&empty_v1));

        // Test custom proof ID
        let custom_proof = ExecutionPayloadProof::new_v1(hash, ProofId::custom(42), vec![1, 2, 3]);
        assert_eq!(custom_proof.description(), "Custom proof type 42 v1");
        assert_eq!(custom_proof.identifier(), "custom_v1");
    }

    #[test]
    fn test_proof_subnet_mapping() {
        // Test direct one-to-one mapping
        assert_eq!(ProofId::EXECUTION_WITNESS.subnet_id(), 0);
        assert_eq!(ProofId::custom(1).subnet_id(), 1);
        assert_eq!(ProofId::custom(42).subnet_id(), 42);
        assert_eq!(ProofId::custom(100).subnet_id(), 100);

        // Test subnet topic generation
        assert_eq!(
            ProofId::EXECUTION_WITNESS.subnet_topic(),
            "execution_proof_0"
        );
        assert_eq!(ProofId::custom(1).subnet_topic(), "execution_proof_1");
        assert_eq!(ProofId::custom(42).subnet_topic(), "execution_proof_42");

        // Test that ProofId and subnet_id are equivalent
        for id in [0, 1, 2, 3, 4, 5, 6, 7] {
            let proof_id = ProofId::custom(id);
            assert_eq!(proof_id.id(), id);
            assert_eq!(proof_id.subnet_id(), id);
            assert_eq!(proof_id.subnet_topic(), format!("execution_proof_{}", id));
        }

        // Test higher subnet IDs still work (for future expansion)
        let high_id = ProofId::custom(100);
        assert_eq!(high_id.subnet_id(), 100);
        assert_eq!(high_id.subnet_topic(), "execution_proof_100");
    }

    #[test]
    fn test_generate_dummy_proof_method() {
        use types::{ExecutionPayloadBellatrix, FullPayloadBellatrix, MainnetEthSpec};

        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(5);

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::default(),
                receipts_root: Hash256::default(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::default(),
                block_number: 555,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: types::Uint256::from(0u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let proof = ExecutionPayloadProofStore::generate_dummy_proof(&exec_payload, proof_id);

        assert_eq!(proof.block_hash, execution_block_hash);
        assert_eq!(proof.proof_id, proof_id);
        assert_eq!(proof.version, 1);
        assert!(!proof.proof_data.is_empty());
        assert!(ExecutionPayloadProofStore::validate_proof(&proof));

        // Verify the proof data contains expected information
        let proof_data_str = String::from_utf8_lossy(&proof.proof_data);
        assert!(proof_data_str.contains("dummy_proof_subnet_5"));
        assert!(proof_data_str.contains(&format!("{:?}", execution_block_hash)));
        assert!(proof_data_str.contains("number_555"));
    }

    #[test]
    fn test_generate_and_store_dummy_proof_method() {
        use types::{ExecutionPayloadBellatrix, FullPayloadBellatrix, MainnetEthSpec};

        let store = ExecutionPayloadProofStore::new(10);
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(3);

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::default(),
                receipts_root: Hash256::default(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::default(),
                block_number: 333,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: types::Uint256::from(0u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        // Initially no proofs
        assert!(!store.has_valid_proof(&execution_block_hash));
        assert_eq!(store.len(), 0);

        // Generate and store a proof
        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload.clone());
        let result = store.generate_and_store_dummy_proof(&exec_payload, proof_id);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.block_hash, execution_block_hash);
        assert_eq!(proof.proof_id, proof_id);

        // Verify it's stored in the store
        assert!(store.has_valid_proof(&execution_block_hash));
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id));
        assert_eq!(store.len(), 1);
        assert_eq!(store.proof_count_for_payload(&execution_block_hash), 1);

        // Generate another proof for the same payload with different proof ID
        let proof_id_2 = ProofId::custom(7);
        let exec_payload2 = ExecutionPayload::Bellatrix(payload.execution_payload);
        let result_2 = store.generate_and_store_dummy_proof(&exec_payload2, proof_id_2);
        assert!(result_2.is_ok());

        // Should have 2 proofs now
        assert_eq!(store.len(), 2);
        assert_eq!(store.proof_count_for_payload(&execution_block_hash), 2);
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id));
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id_2));
    }
}
