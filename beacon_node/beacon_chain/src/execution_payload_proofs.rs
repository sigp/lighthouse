use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use types::{
    execution_proof_subnet_id::ExecutionProofSubnetId, EthSpec, ExecPayload, ExecutionBlockHash,
    ExecutionPayload, ExecutionProof, Hash256, Slot,
};

/// Error types for execution proof operations
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionProofError {
    /// Validation errors indicate the proof is invalid
    ValidationError {
        proof_id: u64,
        block_hash: ExecutionBlockHash,
        reason: String,
    },
    /// Storage errors indicate internal issues and should not result in peer penalties
    StorageError { reason: String },
}

impl fmt::Display for ExecutionProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionProofError::ValidationError {
                proof_id,
                block_hash,
                reason,
            } => write!(
                f,
                "Invalid proof for block hash {:?}, proof ID {}: {}",
                block_hash, proof_id, reason
            ),
            ExecutionProofError::StorageError { reason } => {
                write!(f, "Storage error: {}", reason)
            }
        }
    }
}

impl std::error::Error for ExecutionProofError {}

impl ExecutionProofError {
    /// Check if this error should result in peer penalties
    ///
    /// TODO: maybe remove this and put this in `process_gossip_execution_proof`
    pub fn should_penalize_peer(&self) -> bool {
        matches!(self, ExecutionProofError::ValidationError { .. })
    }

    /// Create a validation error
    pub fn validation_error(
        proof_id: u64,
        block_hash: ExecutionBlockHash,
        reason: impl Into<String>,
    ) -> Self {
        Self::ValidationError {
            proof_id,
            block_hash,
            reason: reason.into(),
        }
    }

    /// Create a storage error
    pub fn storage_error(reason: impl Into<String>) -> Self {
        Self::StorageError {
            reason: reason.into(),
        }
    }
}

/// Type alias for ProofId using ExecutionProofSubnetId
pub type ProofId = ExecutionProofSubnetId;

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
    proofs: Arc<RwLock<HashMap<(ExecutionBlockHash, ProofId), ExecutionProof>>>,
    /// Tracks insertion order for LRU eviction
    insertion_order: Arc<RwLock<VecDeque<(ExecutionBlockHash, ProofId)>>>,
    /// Queue of proofs waiting to be broadcast
    broadcast_queue: Arc<RwLock<Vec<(ExecutionBlockHash, ProofId)>>>,
    /// Reverse mapping: execution block hash -> beacon block roots waiting for proofs
    /// This allows efficient lookup of which beacon blocks to re-evaluate when proofs arrive
    ///
    /// TODO: need to verify the following Note, on one execution payload mapping to multiple beacon blocks
    /// TODO: If not the case, then it becomes a 1-1 mapping
    ///
    /// Note: Multiple beacon block roots can share the same execution block hash in fork scenarios.
    /// For example, during consensus layer forks, competing beacon blocks may contain the same
    /// execution payload, resulting in multiple beacon block roots waiting for the same execution proof.
    ///
    /// TODO: The most common case is 1 ExecutionBlockHash to 1 BeaconRoot, so SmallVec<[Hash256; 1]> might make more sense
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
            insertion_order: Arc::new(RwLock::new(VecDeque::new())),
            broadcast_queue: Arc::new(RwLock::new(Vec::new())),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            max_proofs,
            proven_canonical_chain: Arc::new(RwLock::new(HashMap::new())),
            proven_head: Arc::new(RwLock::new(None)),
            proven_finalized: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if we have any proof for the given execution block hash
    /// Returns true if at least one proof type exists
    ///
    /// Note: all stored proofs are validated. We assume that proofs are added via `store_proofs`
    pub fn has_valid_proof(&self, block_hash: &ExecutionBlockHash) -> bool {
        let proofs = self.proofs.read();
        proofs.keys().any(|(hash, _proof_id)| hash == block_hash)
    }

    /// Check if we have a proof for a specific proof ID and execution block hash
    /// Returns true if the proof exists
    ///
    /// Note: all stored proofs are validated. We assume that proofs are added via `store_proofs`
    pub fn has_valid_proof_for_id(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool {
        let proofs = self.proofs.read();
        proofs.contains_key(&(*block_hash, proof_id))
    }

    /// Get all proofs for the given execution block hash
    pub fn get_proofs(&self, block_hash: &ExecutionBlockHash) -> Vec<ExecutionProof> {
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

    /// Get a specific proof for the given execution block hash and proof ID
    pub fn get_proof(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> Option<ExecutionProof> {
        let proofs = self.proofs.read();
        proofs.get(&(*block_hash, proof_id)).cloned()
    }

    /// Take all proofs from the broadcast queue
    /// This drains the queue and returns all pending proofs
    ///
    /// Note: This is used for the BroadcastManager
    pub fn take_unqueued_proofs(&self) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut queue = self.broadcast_queue.write();
        std::mem::take(&mut *queue)
    }

    /// Store a proof for an execution payload
    ///
    /// Note: This method validates the proof before storing it
    pub fn store_proof(&self, proof: ExecutionProof) -> Result<(), ExecutionProofError> {
        // Validate the proof before storing
        if !Self::validate_proof(&proof) {
            return Err(ExecutionProofError::validation_error(
                *proof.subnet_id,
                proof.block_hash,
                "validation failed",
            ));
        }

        let key = (proof.block_hash, proof.subnet_id);

        // Acquire both locks to maintain consistency
        let mut proofs = self.proofs.write();
        let mut insertion_order = self.insertion_order.write();

        // Simple LRU eviction if we're at capacity
        if proofs.len() >= self.max_proofs {
            // Remove the oldest proof (front of the queue)
            if let Some(oldest_key) = insertion_order.pop_front() {
                proofs.remove(&oldest_key);
            }
        }

        // Insert the new proof
        proofs.insert(key, proof);
        insertion_order.push_back(key);

        // Add to broadcast queue
        drop(proofs); // Release the proofs lock
        drop(insertion_order); // Release the insertion_order lock
        let mut queue = self.broadcast_queue.write();
        queue.push(key);

        Ok(())
    }

    /// Get the total number of stored proofs (across all proof types and payloads)
    pub fn len(&self) -> usize {
        self.proofs.read().len()
    }

    /// Get the number of unique payloads that have at least one proof
    #[cfg(test)]
    pub fn unique_payload_count(&self) -> usize {
        let proofs = self.proofs.read();
        let unique_hashes: std::collections::HashSet<ExecutionBlockHash> =
            proofs.keys().map(|(hash, _proof_id)| *hash).collect();
        unique_hashes.len()
    }

    /// Get the number of proofs for a specific execution block hash
    ///
    /// This method is essential for stateless validation to determine:
    /// - Whether a block has received the minimum required number of proofs (e.g., 2 out of 3)
    /// - If we should transition from optimistic to proven state for a block
    /// - The exact proof count for logging and chain tracking purposes
    ///
    /// Multiple proof types can exist for a single execution payload (one per subnet),
    /// and we need to count them to ensure sufficient independent validation before
    /// considering the payload as proven.
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
        self.insertion_order.write().clear();
    }

    /// Generate a proof for an execution payload
    pub fn generate_proof<T: EthSpec>(
        payload: &ExecutionPayload<T>,
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> ExecutionProof {
        crate::execution_proof_generation::generate_proof(
            payload,
            execution_state_witness,
            proof_id,
        )
    }

    /// Validate a proof
    pub fn validate_proof(proof: &ExecutionProof) -> bool {
        crate::execution_proof_generation::validate_proof(proof)
    }

    /// Generate and store a proof for the given execution payload and proof ID
    /// This is a convenience method that combines proof generation and storage
    pub fn generate_and_store_proof<T: EthSpec>(
        &self,
        payload: &ExecutionPayload<T>,
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> Result<ExecutionProof, ExecutionProofError> {
        let proof = Self::generate_proof(payload, execution_state_witness, proof_id);
        self.store_proof(proof.clone())?;
        Ok(proof)
    }

    /// Adds a beacon block to the list of blocks awaiting proofs for their execution payloads
    ///
    /// This is called when a block is imported optimistically.
    ///
    /// Note: Prevents duplicate registration of the same block
    pub fn register_pending_block(
        &self,
        execution_block_hash: ExecutionBlockHash,
        beacon_block_root: Hash256,
    ) {
        let mut pending = self.pending_blocks.write();
        let blocks = pending.entry(execution_block_hash).or_insert_with(Vec::new);

        // Only add if not already present (prevents duplicate registration of the same beacon block)
        // Note: Multiple different beacon blocks can reference the same execution payload hash (e.g., during reorgs)
        if !blocks.contains(&beacon_block_root) {
            blocks.push(beacon_block_root);
        }
    }

    /// Get beacon block roots that are pending proofs for the given execution block hash
    ///
    /// Returns empty vec if no blocks are pending
    pub fn get_pending_blocks(&self, execution_block_hash: &ExecutionBlockHash) -> Vec<Hash256> {
        self.pending_blocks
            .read()
            .get(execution_block_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove and return pending blocks for the given execution block hash
    ///
    /// This is called after we've verified that sufficient proofs exist for the payload.
    /// The returned blocks have transitioned from optimistic to proven state.
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
    #[cfg(test)]
    pub fn pending_execution_hashes_count(&self) -> usize {
        self.pending_blocks.read().len()
    }

    /// Get the total number of pending beacon blocks across all execution hashes
    #[cfg(test)]
    pub fn total_pending_blocks_count(&self) -> usize {
        self.pending_blocks
            .read()
            .values()
            .map(|blocks| blocks.len())
            .sum()
    }

    /// Clean up pending blocks based on a provided predicate
    ///
    /// Note: This should be called periodically to prevent memory leaks
    ///
    /// Note: `take_pending_blocks` is called to remove blocks which have received
    /// enough proofs, it uses the `ExecutionPayloadHash` to do the removal.
    /// Whereas this method is periodically triggered to remove blocks that will no longer receive proofs, it uses `BeaconBlockRoot`s
    /// to do this removal.
    /// The reason for removal can be due to:
    /// -  Beacon blocks being on abandoned forks
    /// -  Beacon blocks are too old (past the finalization slot) TODO: This shouldn't happen once proofs are a part of consensus
    ///
    /// Uses a two-phase approach to avoid holding locks during callback execution
    ///
    /// TODO: Test edge case where we receive a lot of pending blocks and cannot
    /// TODO: finalize. Perhaps we can move to storage, when doing LRU evictions
    pub fn cleanup_pending_blocks<F>(&self, should_remove: F) -> usize
    where
        F: Fn(Hash256) -> bool,
    {
        use std::collections::HashSet;

        // 1) Collect all unique beacon block roots to check
        let blocks_to_check: HashSet<Hash256> = self
            .pending_blocks
            .read()
            .values()
            .flatten()
            .copied()
            .collect();

        // 2) Evaluate predicate (without holding locks)
        let blocks_to_remove: HashSet<Hash256> = blocks_to_check
            .into_iter()
            .filter(|&block_root| should_remove(block_root))
            .collect();

        if blocks_to_remove.is_empty() {
            return 0;
        }

        // 3) Remove identified blocks
        let mut pending = self.pending_blocks.write();
        let mut removed_count = 0;

        pending.retain(|_, blocks| {
            let original_len = blocks.len();
            blocks.retain(|block_root| !blocks_to_remove.contains(block_root));
            removed_count += original_len - blocks.len();
            !blocks.is_empty()
        });

        removed_count
    }

    /// Get the current proven head (beacon block root and slot)
    /// Returns None if no proven head has been established yet
    #[cfg(test)]
    fn get_proven_head(&self) -> Option<(Hash256, Slot)> {
        *self.proven_head.read()
    }

    /// Get the proven finalized checkpoint (beacon block root and slot)
    /// Returns None if no proven finalized checkpoint has been established yet
    #[cfg(test)]
    fn get_proven_finalized(&self) -> Option<(Hash256, Slot)> {
        *self.proven_finalized.read()
    }

    /// Check if a beacon block is part of the proven canonical chain
    #[cfg(test)]
    fn is_block_proven(&self, beacon_block_root: &Hash256) -> bool {
        self.proven_canonical_chain
            .read()
            .contains_key(beacon_block_root)
    }

    /// Get information about a proven block
    #[cfg(test)]
    fn get_proven_block_info(&self, beacon_block_root: &Hash256) -> Option<ProvenBlockInfo> {
        self.proven_canonical_chain
            .read()
            .get(beacon_block_root)
            .cloned()
    }

    /// Get the entire proven canonical chain from finalized to head
    /// Returns a vector of proven blocks ordered from oldest to newest
    #[cfg(test)]
    fn get_proven_canonical_chain(&self) -> Vec<ProvenBlockInfo> {
        let chain = self.proven_canonical_chain.read();
        let mut blocks: Vec<ProvenBlockInfo> = chain.values().cloned().collect();
        // Sort by slot, oldest first
        blocks.sort_by_key(|b| b.slot);
        blocks
    }

    /// Get the depth of the proven chain (number of proven blocks)
    #[cfg(test)]
    fn get_proven_chain_depth(&self) -> usize {
        self.proven_canonical_chain.read().len()
    }

    /// Check if an execution payload has sufficient proofs to be considered proven
    /// This uses the `stateless_min_proofs_required` from the chain config
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
    ///
    ///  Note: This requires access to BeaconChain, so it's called from beacon_chain.rs
    ///
    /// Example:
    ///
    ///```text
    ///   Genesis ← Block 1 ← Block 2 ← Block 3 ← Block 4 ← Block 5 (optimistic head)
    ///             [proven]   [proven]   [proven]   [no proofs] [no proofs]
    ///                                     ↑
    ///                                proven_head
    ///```
    /// TODO: Walking back each time is expensive, we can probably make this faster by
    /// TODO: having the proof store save intermediate information would help here, but don't want to
    /// TODO: make it complex (ie keeping track of different forks)
    pub fn update_proven_chain<T: crate::BeaconChainTypes>(
        &self,
        chain: &crate::BeaconChain<T>,
    ) -> Result<bool, String> {
        // Keep track of the current proven head before update to detect actual changes
        let previous_proven_slot = self.proven_head.read().as_ref().map(|(_, slot)| *slot);

        // Get current optimistic head from fork choice
        let head = chain.canonical_head.cached_head();
        let head_block_root = head.head_block_root();
        let head_slot = head.head_slot();

        let min_proofs_required = chain.config.stateless_min_proofs_required;

        info!(
            "PROOFCHAIN: updating proven chain from optimistic head at slot {}",
            head_slot.as_u64()
        );

        // Walk backwards from optimistic head to find the block at the highest slot which is proven
        let mut current = head_block_root;
        let mut proven_chain = Vec::new();
        let mut proven_head_candidate = None;

        // Note: call `get_blinded_block` because we only need the header and not the transactions
        while let Ok(Some(block)) = chain.get_blinded_block(&current) {
            let beacon_block_root = block.canonical_root();
            let slot = block.slot();
            let parent_root = block.parent_root();

            // Get execution payload hash
            let exec_hash = match block.message().execution_payload() {
                Ok(payload) => payload.block_hash(),
                Err(_) => {
                    // Pre-merge block, stop here
                    // TODO: should we just panic here?
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
                    // TODO: remove `proven_at` -- if we want to save when a block was proven at, this should be exactly when it was proven
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
                format!(
                    "slot {} (epoch {})",
                    pf_slot.as_u64(),
                    pf_slot.epoch(slots_per_epoch).as_u64()
                )
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
            static UPDATE_COUNTER: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let counter = UPDATE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if counter % 3 == 0 {
                info!("PROOFCHAIN SUMMARY:");
                info!(
                    "  Proven head: slot {} (epoch {})",
                    new_head_slot.as_u64(),
                    proven_epoch.as_u64()
                );
                info!("  Proven chain depth: {} blocks", proven_chain.len());
                info!(
                    "  Optimistic head: slot {} (epoch {})",
                    head_slot.as_u64(),
                    head_epoch.as_u64()
                );
                info!(
                    "  Regular finalized: slot {} (epoch {})",
                    finalized_slot.as_u64(),
                    finalized_checkpoint.epoch.as_u64()
                );
                info!("  Proven finalized: {}", proven_finalized_str);
                info!(
                    "  Proof generation lag: {} slots",
                    head_slot.saturating_sub(new_head_slot).as_u64()
                );
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
    use types::{
        execution_proof_subnet_id::MAX_EXECUTION_PROOF_SUBNETS, FixedBytesExtended, Hash256,
    };

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
        let proof1 = ExecutionProof::new(
            hash1,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        store
            .store_proof(proof1.clone())
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof_for_id(&hash1, ExecutionProofSubnetId::new(0).unwrap()));
        assert!(!store.has_valid_proof_for_id(&hash1, ExecutionProofSubnetId::new(1).unwrap()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.unique_payload_count(), 1);
        assert_eq!(store.proof_count_for_payload(&hash1), 1);

        // Store a custom zkVM proof for the same hash1
        let proof1_custom = ExecutionProof::new(
            hash1,
            ExecutionProofSubnetId::new(1).unwrap(),
            1,
            vec![7, 8, 9],
        );
        store
            .store_proof(proof1_custom)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash1));
        assert!(store.has_valid_proof_for_id(&hash1, ExecutionProofSubnetId::new(0).unwrap()));
        assert!(store.has_valid_proof_for_id(&hash1, ExecutionProofSubnetId::new(1).unwrap()));
        assert_eq!(store.len(), 2);
        assert_eq!(store.unique_payload_count(), 1); // Still 1 unique payload
        assert_eq!(store.proof_count_for_payload(&hash1), 2);

        // Store a proof for hash2
        let proof2 = ExecutionProof::new(
            hash2,
            ExecutionProofSubnetId::new(2).unwrap(),
            1,
            vec![4, 5, 6],
        );
        store
            .store_proof(proof2)
            .expect("valid proof should store successfully");

        assert!(store.has_valid_proof(&hash2));
        assert!(store.has_valid_proof_for_id(&hash2, ExecutionProofSubnetId::new(2).unwrap()));
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
        let valid_proof = ExecutionProof::new(
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert!(ExecutionPayloadProofStore::validate_proof(&valid_proof));
        assert!(store.store_proof(valid_proof).is_ok());
        assert!(store.has_valid_proof(&hash));

        // Invalid proof (empty data) should fail to store
        let invalid_proof =
            ExecutionProof::new(hash, ExecutionProofSubnetId::new(1).unwrap(), 1, vec![]);
        assert!(!ExecutionPayloadProofStore::validate_proof(&invalid_proof));
        assert!(store.store_proof(invalid_proof).is_err());
        // Should still only have the first proof
        assert_eq!(store.proof_count_for_payload(&hash), 1);
        assert!(!store.has_valid_proof_for_id(&hash, ExecutionProofSubnetId::new(1).unwrap()));
    }

    #[test]
    fn test_lru_eviction() {
        let store = ExecutionPayloadProofStore::new(2);
        let hash1 = ExecutionBlockHash::from(Hash256::random());
        let hash2 = ExecutionBlockHash::from(Hash256::random());
        let hash3 = ExecutionBlockHash::from(Hash256::random());

        // Create proofs - insertion order will determine LRU eviction
        let proof1 =
            ExecutionProof::new(hash1, ExecutionProofSubnetId::new(0).unwrap(), 1, vec![1]);
        let proof2 =
            ExecutionProof::new(hash2, ExecutionProofSubnetId::new(1).unwrap(), 1, vec![2]);
        let proof3 =
            ExecutionProof::new(hash3, ExecutionProofSubnetId::new(2).unwrap(), 1, vec![3]);

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
            .store_proof(ExecutionProof::new(
                hash,
                ExecutionProofSubnetId::new(0).unwrap(),
                1,
                vec![1, 2, 3],
            ))
            .expect("valid proof should store successfully");
        store
            .store_proof(ExecutionProof::new(
                hash,
                ExecutionProofSubnetId::new(1).unwrap(),
                1,
                vec![4, 5, 6],
            ))
            .expect("valid proof should store successfully");
        store
            .store_proof(ExecutionProof::new(
                hash,
                ExecutionProofSubnetId::new(2).unwrap(),
                1,
                vec![7, 8, 9],
            ))
            .expect("valid proof should store successfully");

        // Should have all three proof types
        assert!(store.has_valid_proof_for_id(&hash, ExecutionProofSubnetId::new(0).unwrap()));
        assert!(store.has_valid_proof_for_id(&hash, ExecutionProofSubnetId::new(1).unwrap()));
        assert!(store.has_valid_proof_for_id(&hash, ExecutionProofSubnetId::new(2).unwrap()));
        assert!(!store.has_valid_proof_for_id(&hash, ExecutionProofSubnetId::new(3).unwrap()));

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
    fn test_proof_versions() {
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Test version 1 proof (supported)
        let v1_proof = ExecutionProof::new(
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert_eq!(v1_proof.version, 1);
        assert!(ExecutionPayloadProofStore::validate_proof(&v1_proof));

        // Test explicit version constructor with custom proof ID
        let v1_explicit = ExecutionProof::new(
            hash,
            ExecutionProofSubnetId::new(1).unwrap(),
            1,
            vec![4, 5, 6],
        );
        assert_eq!(v1_explicit.version, 1);
        assert!(ExecutionPayloadProofStore::validate_proof(&v1_explicit));

        // Test unsupported version
        let v2_proof = ExecutionProof::new(
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            2,
            vec![7, 8, 9],
        );
        assert_eq!(v2_proof.version, 2);
        assert!(!ExecutionPayloadProofStore::validate_proof(&v2_proof)); // Should fail validation for unknown version

        // Test empty data with version 1 (should be invalid)
        let empty_v1 =
            ExecutionProof::new(hash, ExecutionProofSubnetId::new(0).unwrap(), 1, vec![]);
        assert!(!ExecutionPayloadProofStore::validate_proof(&empty_v1));

        // Test custom proof ID (within valid range)
        let custom_proof = ExecutionProof::new(
            hash,
            ExecutionProofSubnetId::new(7).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert!(ExecutionPayloadProofStore::validate_proof(&custom_proof));
    }

    #[test]
    fn test_proof_id_validation() {
        // Test valid subnet IDs
        for id in 0..MAX_EXECUTION_PROOF_SUBNETS {
            assert!(ExecutionProofSubnetId::new(id).is_ok());
        }

        // Test that high subnet IDs are rejected
        assert!(ExecutionProofSubnetId::new(MAX_EXECUTION_PROOF_SUBNETS).is_err());
        assert!(ExecutionProofSubnetId::new(100).is_err());
    }

    #[test]
    fn test_generate_and_store_proof_method() {
        use types::{ExecutionPayloadBellatrix, FullPayloadBellatrix, MainnetEthSpec};

        let store = ExecutionPayloadProofStore::new(10);
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(3).unwrap();

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
        let result = store.generate_and_store_proof(&exec_payload, dummy_witness, proof_id);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.block_hash, execution_block_hash);
        assert_eq!(proof.subnet_id, proof_id);

        // Verify it's stored in the store
        assert!(store.has_valid_proof(&execution_block_hash));
        assert!(store.has_valid_proof_for_id(&execution_block_hash, proof_id));
        assert_eq!(store.len(), 1);
        assert_eq!(store.proof_count_for_payload(&execution_block_hash), 1);

        // Generate another proof for the same payload with different proof ID
        let proof_id_2 = ExecutionProofSubnetId::new(7).unwrap();
        let exec_payload2 = ExecutionPayload::Bellatrix(payload.execution_payload);
        let result_2 = store.generate_and_store_proof(&exec_payload2, dummy_witness, proof_id_2);
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
        let proof1 = ExecutionProof::new(
            block_hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert!(store.store_proof(proof1).is_ok());
        assert!(store.proof_count_for_payload(&block_hash) < min_proofs);

        // Add second proof - now it's proven
        let proof2 = ExecutionProof::new(
            block_hash,
            ExecutionProofSubnetId::new(1).unwrap(),
            1,
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
    fn test_cleanup_pending_blocks() {
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
        let removed =
            store.cleanup_pending_blocks(|root| root == beacon_root1 || root == beacon_root2);

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
        let removed = store.cleanup_pending_blocks(|root| root == old_block);

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
        let proof1 = ExecutionProof::new(
            exec_hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert!(store.store_proof(proof1).is_ok());

        // Sufficient for min=1, insufficient for min=2
        assert!(store.has_sufficient_proofs(&exec_hash, 1));
        assert!(!store.has_sufficient_proofs(&exec_hash, 2));

        // Add second proof
        let proof2 = ExecutionProof::new(
            exec_hash,
            ExecutionProofSubnetId::new(1).unwrap(),
            1,
            vec![4, 5, 6],
        );
        assert!(store.store_proof(proof2).is_ok());

        // Now sufficient for min=2
        assert!(store.has_sufficient_proofs(&exec_hash, 2));
    }
}
