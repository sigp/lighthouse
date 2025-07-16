use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use types::{
    execution_proof_subnet_id::MAX_EXECUTION_PROOF_SUBNETS, EthSpec, ExecPayload,
    ExecutionBlockHash, ExecutionPayload, Hash256, Slot,
};


/// Identifier for different types of proofs that can be received for execution payloads
/// Each proof ID will be received on a different gossip subnet
/// The u64 value can be mapped to subnet numbers for easy routing
/// TODO: maybe just alias `ExecutionProofSubnetId`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub u64);

impl ProofId {
    /// Execution witness proof (subnet 0)
    /// This is the standard execution payload witness proof
    pub const EXECUTION_WITNESS: ProofId = ProofId(0);

    /// Create a custom proof ID for specific zkVMs
    /// Each zkVM (e.g., SP1, RISC-V, zkEVM) will have its own subnet and proof ID
    /// For example:
    /// - SP1 proofs: ProofId::custom(1).unwrap() → subnet 1
    /// - RISC-V proofs: ProofId::custom(2).unwrap() → subnet 2  
    /// - zkEVM proofs: ProofId::custom(3).unwrap() → subnet 3
    /// - etc.
    /// 
    /// Returns an error if id >= MAX_EXECUTION_PROOF_SUBNETS
    pub fn custom(id: u64) -> Result<Self, String> {
        if id >= MAX_EXECUTION_PROOF_SUBNETS {
            return Err(format!(
                "ProofId {} exceeds MAX_EXECUTION_PROOF_SUBNETS ({})",
                id, MAX_EXECUTION_PROOF_SUBNETS
            ));
        }
        Ok(ProofId(id))
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

/// Information about a block that has been proven with execution proofs
#[derive(Debug, Clone)]
pub struct ProvenBlockInfo {
    /// The beacon block root
    pub beacon_block_root: Hash256,
    /// The execution block hash
    pub execution_block_hash: ExecutionBlockHash,
    /// The slot of the block
    pub slot: Slot,
    /// The parent beacon block root
    pub parent_root: Hash256,
    /// Number of proofs available for this block
    pub proof_count: usize,
    /// When this block was marked as proven
    pub proven_at: Instant,
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
    /// Tracks the proven canonical chain - blocks that have sufficient proofs
    /// Maps beacon block root to proven block information
    proven_canonical_chain: Arc<RwLock<HashMap<Hash256, ProvenBlockInfo>>>,
    /// The current proven head (beacon block root, slot)
    /// This is the deepest block in the canonical chain that has sufficient proofs
    proven_head: Arc<RwLock<Option<(Hash256, Slot)>>>,
    /// The proven finalized checkpoint (beacon block root, slot)
    /// This is updated when the proven chain reaches finalization depth
    proven_finalized: Arc<RwLock<Option<(Hash256, Slot)>>>,
}

impl ExecutionPayloadProofStore {
    /// Create a new proof store with given capacity
    pub fn new(max_proofs: usize) -> Self {
        Self {
            proofs: Arc::new(RwLock::new(HashMap::new())),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            max_proofs,
            proven_canonical_chain: Arc::new(RwLock::new(HashMap::new())),
            proven_head: Arc::new(RwLock::new(None)),
            proven_finalized: Arc::new(RwLock::new(None)),
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
    /// The execution_state_witness would be obtained from the EL (e.g., via debug_executionWitness)
    pub fn generate_dummy_proof<T: EthSpec>(
        payload: &ExecutionPayload<T>,
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> ExecutionPayloadProof {
        let execution_block_hash = payload.block_hash();
        let block_number = payload.block_number();

        // Create dummy proof data that includes the subnet information and payload details
        // In a real implementation, this would use the execution_state_witness to generate
        // a cryptographic proof of the payload's validity
        let dummy_data = format!(
            "dummy_proof_subnet_{}_block_{:?}_number_{}_witness_len_{}_timestamp_{}",
            proof_id.subnet_id(),
            execution_block_hash,
            block_number,
            execution_state_witness.len(),
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
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> Result<ExecutionPayloadProof, String> {
        let proof = Self::generate_dummy_proof(payload, execution_state_witness, proof_id);
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

    /// Get the current proven head (beacon block root and slot)
    /// Returns None if no proven head has been established yet
    pub fn get_proven_head(&self) -> Option<(Hash256, Slot)> {
        *self.proven_head.read()
    }

    /// Get the proven finalized checkpoint (beacon block root and slot)
    /// Returns None if no proven finalized checkpoint has been established yet
    pub fn get_proven_finalized(&self) -> Option<(Hash256, Slot)> {
        *self.proven_finalized.read()
    }

    /// Check if a beacon block is part of the proven canonical chain
    pub fn is_block_proven(&self, beacon_block_root: &Hash256) -> bool {
        self.proven_canonical_chain
            .read()
            .contains_key(beacon_block_root)
    }

    /// Get information about a proven block
    pub fn get_proven_block_info(&self, beacon_block_root: &Hash256) -> Option<ProvenBlockInfo> {
        self.proven_canonical_chain
            .read()
            .get(beacon_block_root)
            .cloned()
    }

    /// Get the entire proven canonical chain from finalized to head
    /// Returns a vector of proven blocks ordered from oldest to newest
    pub fn get_proven_canonical_chain(&self) -> Vec<ProvenBlockInfo> {
        let chain = self.proven_canonical_chain.read();
        let mut blocks: Vec<ProvenBlockInfo> = chain.values().cloned().collect();
        // Sort by slot, oldest first
        blocks.sort_by_key(|b| b.slot);
        blocks
    }

    /// Get the depth of the proven chain (number of proven blocks)
    pub fn get_proven_chain_depth(&self) -> usize {
        self.proven_canonical_chain.read().len()
    }

    /// Check if an execution payload has sufficient proofs to be considered proven
    /// This uses the stateless_min_proofs_required from the chain config
    pub fn has_sufficient_proofs(
        &self,
        execution_block_hash: &ExecutionBlockHash,
        min_proofs_required: usize,
    ) -> bool {
        let proof_count = self.proof_count_for_payload(execution_block_hash);
        proof_count >= min_proofs_required
    }

    /// Update the proven canonical chain based on available proofs
    /// This method walks backwards from the optimistic head to find the longest proven chain
    /// Note: This requires access to BeaconChain, so it's called from beacon_chain.rs
    /// TODO: Walking back each time is expensive, we can probably make this faster by 
    /// TODO: having the proof store save intermediate information would help here, but don't want to
    /// TODO: make it compelx (ie keeping track of different forks)
    pub fn update_proven_chain<T: crate::BeaconChainTypes>(
        &self,
        chain: &crate::BeaconChain<T>,
    ) -> Result<bool, String> {
        // Keep track of the current proven head before update to detect actual changes
        let previous_proven_slot = self.proven_head.read()
            .as_ref()
            .map(|(_, slot)| *slot);
        
        // Get current optimistic head from fork choice
        let head = chain.canonical_head.cached_head();
        let head_block_root = head.head_block_root();
        let head_slot = head.head_slot();

        let min_proofs_required = chain.config.stateless_min_proofs_required;

        info!(
            "PROOFCHAIN: updating proven chain from optimistic head at slot {}",
            head_slot.as_u64()
        );

        // Walk backwards from optimistic head to find longest proven chain
        let mut current = head_block_root;
        let mut proven_chain = Vec::new();
        let mut proven_head_candidate = None;

        while let Ok(Some(block)) = chain.get_blinded_block(&current) {
            let beacon_block_root = block.canonical_root();
            let slot = block.slot();
            let parent_root = block.parent_root();

            // Get execution payload hash
            let exec_hash = match block.message().execution_payload() {
                Ok(payload) => payload.block_hash(),
                Err(_) => {
                    // Pre-merge block, stop here
                    break;
                }
            };

            // Check if this block has sufficient proofs
            if self.has_sufficient_proofs(&exec_hash, min_proofs_required) {
                let proof_count = self.proof_count_for_payload(&exec_hash);

                let proven_info = ProvenBlockInfo {
                    beacon_block_root,
                    execution_block_hash: exec_hash,
                    slot,
                    parent_root,
                    proof_count,
                    proven_at: Instant::now(),
                };

                proven_chain.push(proven_info.clone());

                // Track the deepest proven block as head candidate
                if proven_head_candidate.is_none() {
                    proven_head_candidate = Some((beacon_block_root, slot));
                }

                // Continue walking backwards
                current = parent_root;
            } else {
                debug!(
                    "PROOFCHAIN {}: insufficient proofs at slot {}. Proofs: {}/{} required",
                    exec_hash,
                    slot.as_u64(),
                    self.proof_count_for_payload(&exec_hash),
                    min_proofs_required
                );
                break;
            }
        }

        // Update proven chain storage
        let mut proven_canonical_chain = self.proven_canonical_chain.write();
        let mut proven_head = self.proven_head.write();

        // Clear old proven chain
        proven_canonical_chain.clear();

        // Add new proven blocks
        for block_info in proven_chain.iter() {
            proven_canonical_chain.insert(block_info.beacon_block_root, block_info.clone());
        }

        // Update proven head
        let head_changed = *proven_head != proven_head_candidate;
        *proven_head = proven_head_candidate;

        if let Some((_new_head_root, new_head_slot)) = proven_head_candidate {
            // Get current finalization info from the chain
            let finalized_checkpoint = chain.canonical_head.cached_head().finalized_checkpoint();
            let finalized_slot = finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());

            // Calculate proven epochs (most likely 32 slots per epoch)
            let slots_per_epoch = T::EthSpec::slots_per_epoch();
            let proven_epoch = new_head_slot.epoch(slots_per_epoch);
            let head_epoch = head_slot.epoch(slots_per_epoch);

            // Get proven finalized info
            let proven_finalized_info = self.proven_finalized.read();
            let proven_finalized_str = if let Some((_pf_root, pf_slot)) = *proven_finalized_info {
                format!("slot {} (epoch {})", pf_slot.as_u64(), pf_slot.epoch(slots_per_epoch).as_u64())
            } else {
                "none".to_string()
            };

            // Only log if the proven slot has actually changed
            if previous_proven_slot != Some(new_head_slot) {
                info!(
                    "PROOFCHAIN STATUS: Proven slot {} | Optimistic slot {} | Lag {} slots | Status: {}",
                    new_head_slot.as_u64(),
                    head_slot.as_u64(),
                    head_slot.saturating_sub(new_head_slot).as_u64(),
                    if head_slot == new_head_slot { "Fully proven" } else { "Catching up" }
                );
            }
            
            // Log a detailed summary every 3 updates
            static UPDATE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let counter = UPDATE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if counter % 3 == 0 {
                info!("PROOFCHAIN SUMMARY:");
                info!("  Proven head: slot {} (epoch {})", new_head_slot.as_u64(), proven_epoch.as_u64());
                info!("  Proven chain depth: {} blocks", proven_chain.len());
                info!("  Optimistic head: slot {} (epoch {})", head_slot.as_u64(), head_epoch.as_u64());
                info!("  Regular finalized: slot {} (epoch {})", finalized_slot.as_u64(), finalized_checkpoint.epoch.as_u64());
                info!("  Proven finalized: {}", proven_finalized_str);
                info!("  Proof generation lag: {} slots", head_slot.saturating_sub(new_head_slot).as_u64());
                info!("  Min proofs required: {}", min_proofs_required);
            }
        } else {
            warn!("PROOFCHAIN: no proven head found - no blocks have sufficient proofs");
        }

        // Check if we should update proven finalized
        self.update_proven_finalized(&proven_chain, chain);

        Ok(head_changed)
    }

    /// Update the proven finalized checkpoint based on the proven chain
    fn update_proven_finalized<T: crate::BeaconChainTypes>(
        &self,
        proven_chain: &[ProvenBlockInfo],
        chain: &crate::BeaconChain<T>,
    ) {
        // TODO: Implement finalization logic
        // For now, we'll consider a block finalized if it's proven and
        // at least 2 epochs old (similar to normal finalization distance)

        // This is a placeholder - proper implementation would check
        // actual finalization rules and epoch boundaries
        if proven_chain.is_empty() {
            return;
        }

        // Get current epoch for the proof chain
        let current_slot = chain.slot().unwrap_or(Slot::new(0));
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let current_epoch = current_slot.epoch(slots_per_epoch);

        // Find the latest proven block that is at least 2 epochs old (similar to finalization distance)
        let finalization_distance = 2u64;
        let mut proven_finalized_candidate = None;

        for block_info in proven_chain.iter().rev() {
            let block_epoch = block_info.slot.epoch(slots_per_epoch);
            if current_epoch.saturating_sub(block_epoch).as_u64() >= finalization_distance {
                proven_finalized_candidate = Some((block_info.beacon_block_root, block_info.slot));
                break;
            }
        }

        // Update proven finalized if we found a candidate
        let mut proven_finalized = self.proven_finalized.write();
        if proven_finalized_candidate != *proven_finalized {
            *proven_finalized = proven_finalized_candidate;

            if let Some((finalized_root, finalized_slot)) = proven_finalized_candidate {
                let finalized_epoch = finalized_slot.epoch(slots_per_epoch);
                info!(
                    "PROOFCHAIN FINALIZED: block {:?} at slot {} (epoch {})",
                    finalized_root,
                    finalized_slot.as_u64(),
                    finalized_epoch.as_u64()
                );
            }
        }
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
    use types::{Hash256, FixedBytesExtended};

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
        assert!(!store.has_valid_proof_for_id(&hash1, ProofId::custom(1).unwrap()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.unique_payload_count(), 1);
        assert_eq!(store.proof_count_for_payload(&hash1), 1);

        // Store a custom zkVM proof for the same hash1
        let proof1_custom = ExecutionPayloadProof::new_v1(hash1, ProofId::custom(1).unwrap(), vec![7, 8, 9]);
        store
            .store_proof(proof1_custom)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof_for_id(&hash1, ProofId::EXECUTION_WITNESS));
        assert!(store.has_valid_proof_for_id(&hash1, ProofId::custom(1).unwrap()));
        assert_eq!(store.len(), 2);
        assert_eq!(store.unique_payload_count(), 1); // Still 1 unique payload
        assert_eq!(store.proof_count_for_payload(&hash1), 2);

        // Store a proof for hash2
        let proof2 = ExecutionPayloadProof::new_v1(hash2, ProofId::custom(2).unwrap(), vec![4, 5, 6]);
        store
            .store_proof(proof2)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash2));
        assert!(store.has_valid_proof_for_id(&hash2, ProofId::custom(2).unwrap()));
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
        let invalid_proof = ExecutionPayloadProof::new_v1(hash, ProofId::custom(1).unwrap(), vec![]);
        assert!(!ExecutionPayloadProofStore::validate_proof(&invalid_proof));
        assert!(store.store_proof(invalid_proof).is_err());
        // Should still only have the first proof
        assert_eq!(store.proof_count_for_payload(&hash), 1);
        assert!(!store.has_valid_proof_for_id(&hash, ProofId::custom(1).unwrap()));
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

        let mut proof2 = ExecutionPayloadProof::new_v1(hash2, ProofId::custom(1).unwrap(), vec![2]);
        proof2.timestamp = 200; // Middle

        let mut proof3 = ExecutionPayloadProof::new_v1(hash3, ProofId::custom(2).unwrap(), vec![3]);
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
                ProofId::custom(1).unwrap(),
                vec![4, 5, 6],
            ))
            .expect("valid proof should store successfully");
        store
            .store_proof(ExecutionPayloadProof::new_v1(
                hash,
                ProofId::custom(2).unwrap(),
                vec![7, 8, 9],
            ))
            .expect("valid proof should store successfully");

        // Should have all three proof types
        assert!(store.has_valid_proof_for_id(&hash, ProofId::EXECUTION_WITNESS));
        assert!(store.has_valid_proof_for_id(&hash, ProofId::custom(1).unwrap()));
        assert!(store.has_valid_proof_for_id(&hash, ProofId::custom(2).unwrap()));
        assert!(!store.has_valid_proof_for_id(&hash, ProofId::custom(3).unwrap()));

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
        let sp1_proof = ProofId::custom(1).unwrap();
        assert_eq!(sp1_proof.id(), 1);
        assert_eq!(sp1_proof.identifier(), "custom");
        assert_eq!(sp1_proof.description(), "Custom proof type 1");

        let risc_v_proof = ProofId::custom(2).unwrap();
        assert_eq!(risc_v_proof.id(), 2);
        assert_eq!(risc_v_proof.identifier(), "custom");
        assert_eq!(risc_v_proof.description(), "Custom proof type 2");

        // Test invalid proof ID (exceeds MAX_EXECUTION_PROOF_SUBNETS)
        assert!(ProofId::custom(100).is_err());
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
        let v1_explicit = ExecutionPayloadProof::new(hash, ProofId::custom(1).unwrap(), 1, vec![4, 5, 6]);
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

        // Test custom proof ID (within valid range)
        let custom_proof = ExecutionPayloadProof::new_v1(hash, ProofId::custom(7).unwrap(), vec![1, 2, 3]);
        assert_eq!(custom_proof.description(), "Custom proof type 7 v1");
        assert_eq!(custom_proof.identifier(), "custom_v1");
    }

    #[test]
    fn test_proof_subnet_mapping() {
        // Test direct one-to-one mapping
        assert_eq!(ProofId::EXECUTION_WITNESS.subnet_id(), 0);
        assert_eq!(ProofId::custom(1).unwrap().subnet_id(), 1);
        assert_eq!(ProofId::custom(7).unwrap().subnet_id(), 7);

        // Test subnet topic generation
        assert_eq!(
            ProofId::EXECUTION_WITNESS.subnet_topic(),
            "execution_proof_0"
        );
        assert_eq!(ProofId::custom(1).unwrap().subnet_topic(), "execution_proof_1");
        assert_eq!(ProofId::custom(7).unwrap().subnet_topic(), "execution_proof_7");

        // Test that ProofId and subnet_id are equivalent
        for id in 0..MAX_EXECUTION_PROOF_SUBNETS {
            let proof_id = if id == 0 {
                ProofId::EXECUTION_WITNESS
            } else {
                ProofId::custom(id).unwrap()
            };
            assert_eq!(proof_id.id(), id);
            assert_eq!(proof_id.subnet_id(), id);
            assert_eq!(proof_id.subnet_topic(), format!("execution_proof_{}", id));
        }

        // Test that high subnet IDs are rejected
        assert!(ProofId::custom(100).is_err());
    }

    #[test]
    fn test_generate_dummy_proof_method() {
        use types::{ExecutionPayloadBellatrix, FullPayloadBellatrix, MainnetEthSpec};

        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(5).unwrap();

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
        let dummy_witness = b"test_witness_data";
        let proof = ExecutionPayloadProofStore::generate_dummy_proof(
            &exec_payload,
            dummy_witness,
            proof_id,
        );

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
        assert!(proof_data_str.contains("witness_len_17")); // 17 is the length of "test_witness_data"
    }

    #[test]
    fn test_generate_and_store_dummy_proof_method() {
        use types::{ExecutionPayloadBellatrix, FullPayloadBellatrix, MainnetEthSpec};

        let store = ExecutionPayloadProofStore::new(10);
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(3).unwrap();

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
        let dummy_witness = b"test_witness_data";
        let result = store.generate_and_store_dummy_proof(&exec_payload, dummy_witness, proof_id);
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
        let proof_id_2 = ProofId::custom(7).unwrap();
        let exec_payload2 = ExecutionPayload::Bellatrix(payload.execution_payload);
        let result_2 =
            store.generate_and_store_dummy_proof(&exec_payload2, dummy_witness, proof_id_2);
        assert!(result_2.is_ok());

        // Should have 2 proofs now
        assert_eq!(store.len(), 2);
        assert_eq!(store.proof_count_for_payload(&execution_block_hash), 2);
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id));
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id_2));
    }

    #[test]
    fn test_proven_chain_tracking_basic() {
        let store = ExecutionPayloadProofStore::new(100);
        
        // Initially no proven head
        assert!(store.get_proven_head().is_none());
        assert!(store.get_proven_finalized().is_none());
        
        // The proven head and finalized are set internally by update_proven_chain
        // We can't set them directly, so this test focuses on checking initial state
    }

    #[test]
    fn test_is_execution_payload_proven() {
        let store = ExecutionPayloadProofStore::new(100);
        let min_proofs = 2;
        
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        
        // No proofs = not proven
        assert!(store.proof_count_for_payload(&block_hash) < min_proofs);
        
        // Add one proof - still not enough
        let proof1 = ExecutionPayloadProof::new_v1(
            block_hash,
            ProofId::EXECUTION_WITNESS,
            vec![1, 2, 3],
        );
        assert!(store.store_proof(proof1).is_ok());
        assert!(store.proof_count_for_payload(&block_hash) < min_proofs);
        
        // Add second proof - now it's proven
        let proof2 = ExecutionPayloadProof::new_v1(
            block_hash,
            ProofId::custom(1).unwrap(),
            vec![4, 5, 6],
        );
        assert!(store.store_proof(proof2).is_ok());
        assert!(store.proof_count_for_payload(&block_hash) >= min_proofs);
        
        // With min_proofs = 1, it should have been proven with just one proof
        assert!(store.proof_count_for_payload(&block_hash) >= 1);
    }

    #[test]
    fn test_is_beacon_block_proven() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let beacon_root = Hash256::from_low_u64_be(1);
        
        // Initially not proven
        assert!(!store.is_block_proven(&beacon_root));
        
        // The proven chain is populated by update_proven_chain
        // which requires a full BeaconChain, so we can't test the full flow here
        
        // Test with a different block
        assert!(!store.is_block_proven(&Hash256::from_low_u64_be(999)));
    }

    #[test]
    fn test_get_proven_chain_empty() {
        let store = ExecutionPayloadProofStore::new(100);
        
        // Initially the proven canonical chain should be empty
        let proven_blocks = store.get_proven_canonical_chain();
        assert_eq!(proven_blocks.len(), 0);
        assert_eq!(store.get_proven_chain_depth(), 0);
    }

    #[test]
    fn test_pending_blocks() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        let beacon_root1 = Hash256::random();
        let beacon_root2 = Hash256::random();
        
        // Register pending blocks
        store.register_pending_block(exec_hash, beacon_root1);
        
        // Check pending blocks
        let pending = store.get_pending_blocks(&exec_hash);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains(&beacon_root1));
        
        // Register another
        store.register_pending_block(exec_hash, beacon_root2);
        let pending = store.get_pending_blocks(&exec_hash);
        assert_eq!(pending.len(), 2);
        
        // Remove one pending block
        store.remove_pending_block(&exec_hash, beacon_root1);
        let pending = store.get_pending_blocks(&exec_hash);
        assert_eq!(pending.len(), 1);
        assert!(!pending.contains(&beacon_root1));
        assert!(pending.contains(&beacon_root2));
    }

    #[test]
    fn test_take_pending_blocks() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        let beacon_root1 = Hash256::random();
        let beacon_root2 = Hash256::random();
        
        // Register pending blocks
        store.register_pending_block(exec_hash, beacon_root1);
        store.register_pending_block(exec_hash, beacon_root2);
        
        // Take pending blocks (removes them)
        let taken = store.take_pending_blocks(&exec_hash);
        assert_eq!(taken.len(), 2);
        assert!(taken.contains(&beacon_root1));
        assert!(taken.contains(&beacon_root2));
        
        // Should be empty now
        let pending = store.get_pending_blocks(&exec_hash);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_pending_blocks_counts() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash1 = ExecutionBlockHash::from(Hash256::random());
        let exec_hash2 = ExecutionBlockHash::from(Hash256::random());
        let beacon_root1 = Hash256::random();
        let beacon_root2 = Hash256::random();
        let beacon_root3 = Hash256::random();
        
        // Initially no pending blocks
        assert_eq!(store.pending_execution_hashes_count(), 0);
        assert_eq!(store.total_pending_blocks_count(), 0);
        
        // Add pending blocks
        store.register_pending_block(exec_hash1, beacon_root1);
        store.register_pending_block(exec_hash1, beacon_root2);
        store.register_pending_block(exec_hash2, beacon_root3);
        
        // Check counts
        assert_eq!(store.pending_execution_hashes_count(), 2); // 2 unique execution hashes
        assert_eq!(store.total_pending_blocks_count(), 3); // 3 total pending blocks
    }

    #[test]
    fn test_is_block_proven() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let beacon_root = Hash256::random();
        
        // Initially not proven
        assert!(!store.is_block_proven(&beacon_root));
        
        // The proven chain is populated by update_proven_chain
        // which requires a full BeaconChain, so we can't test it here
    }

    #[test]
    fn test_get_proven_block_info() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let beacon_root = Hash256::random();
        
        // Should return None for non-existent blocks
        assert!(store.get_proven_block_info(&beacon_root).is_none());
    }

    #[test]
    fn test_cleanup_finalized_pending_blocks() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash1 = ExecutionBlockHash::from(Hash256::random());
        let exec_hash2 = ExecutionBlockHash::from(Hash256::random());
        let beacon_root1 = Hash256::random();
        let beacon_root2 = Hash256::random();
        let beacon_root3 = Hash256::random();
        
        // Register pending blocks
        store.register_pending_block(exec_hash1, beacon_root1);
        store.register_pending_block(exec_hash1, beacon_root2);
        store.register_pending_block(exec_hash2, beacon_root3);
        
        // Cleanup with a predicate that removes beacon_root1 and beacon_root2
        let removed = store.cleanup_finalized_pending_blocks(|root| {
            root == beacon_root1 || root == beacon_root2
        });
        
        assert_eq!(removed, 2);
        
        // Check remaining blocks
        let pending1 = store.get_pending_blocks(&exec_hash1);
        assert_eq!(pending1.len(), 0); // All blocks for exec_hash1 were removed
        
        let pending2 = store.get_pending_blocks(&exec_hash2);
        assert_eq!(pending2.len(), 1);
        assert!(pending2.contains(&beacon_root3));
    }

    #[test]
    fn test_cleanup_pending_blocks_by_slot() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash1 = ExecutionBlockHash::from(Hash256::random());
        let exec_hash2 = ExecutionBlockHash::from(Hash256::random());
        let old_block = Hash256::random();
        let new_block = Hash256::random();
        
        // Register blocks
        store.register_pending_block(exec_hash1, old_block);
        store.register_pending_block(exec_hash2, new_block);
        
        // Cleanup old blocks
        let removed = store.cleanup_pending_blocks_by_slot(|root| root == old_block);
        
        assert_eq!(removed, 1);
        
        // Verify old block is gone
        let pending1 = store.get_pending_blocks(&exec_hash1);
        assert_eq!(pending1.len(), 0);
        
        // Verify new block remains
        let pending2 = store.get_pending_blocks(&exec_hash2);
        assert_eq!(pending2.len(), 1);
        assert!(pending2.contains(&new_block));
    }

    #[test]
    fn test_has_sufficient_proofs() {
        let store = ExecutionPayloadProofStore::new(100);
        
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        
        // No proofs = insufficient
        assert!(!store.has_sufficient_proofs(&exec_hash, 1));
        assert!(!store.has_sufficient_proofs(&exec_hash, 2));
        
        // Add one proof
        let proof1 = ExecutionPayloadProof::new_v1(
            exec_hash,
            ProofId::EXECUTION_WITNESS,
            vec![1, 2, 3],
        );
        assert!(store.store_proof(proof1).is_ok());
        
        // Sufficient for min=1, insufficient for min=2
        assert!(store.has_sufficient_proofs(&exec_hash, 1));
        assert!(!store.has_sufficient_proofs(&exec_hash, 2));
        
        // Add second proof
        let proof2 = ExecutionPayloadProof::new_v1(
            exec_hash,
            ProofId::custom(1).unwrap(),
            vec![4, 5, 6],
        );
        assert!(store.store_proof(proof2).is_ok());
        
        // Now sufficient for min=2
        assert!(store.has_sufficient_proofs(&exec_hash, 2));
    }
}
