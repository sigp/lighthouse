use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use tracing::debug;
use types::{
    execution_proof_subnet_id::ExecutionProofSubnetId, EthSpec, ExecutionBlockHash,
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

/// Information about a block that has been proven using execution proofs
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProvenBlockInfo {
    /// The beacon block root
    beacon_block_root: Hash256,
    /// The execution block hash
    execution_block_hash: ExecutionBlockHash,
    /// The slot of the block
    slot: Slot,
    /// The parent beacon block root
    parent_root: Hash256,
    /// Number of proofs available for this block
    proof_count: usize,
}

/// Information about the current proven chain status
#[derive(Debug, Clone)]
pub struct ProvenChainStatus {
    /// The proven head (block root and slot), if any
    pub proven_head: Option<(Hash256, Slot)>,
    /// The proven finalized checkpoint (block root and slot), if any
    pub proven_finalized: Option<(Hash256, Slot)>,
    /// The depth of the proven chain
    pub proven_chain_depth: usize,
    /// Whether the proven head changed in the last update
    pub head_changed: bool,
}

/// Default maximum number of proofs to store
const DEFAULT_MAX_PROOFS: usize = 10_000;

impl Default for ExecutionPayloadProofStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PROOFS)
    }
}

/// Manages storage and tracking of execution payload proofs for stateless validation.
///
/// It maintains proofs submitted by network participants and tracks
/// which beacon blocks have transitioned from `optimistic` to `proven` based on
/// receiving sufficient independent proofs for that beacon blocks execution payload.
///
/// # Key Responsibilities
///
/// 1. **Proof Storage**: Stores execution proofs indexed by (ExecutionBlockHash, ProofId)
///    with LRU eviction to manage memory usage.
///
/// 2. **Pending Block Tracking**: Maintains a mapping of execution block hashes to
///    beacon blocks awaiting proofs.
///
/// 3. **Proven Chain Tracking**: Maintains the longest chain of blocks that have received
///    sufficient proofs, including tracking the proven head and finalized checkpoints.
///    Note: Once proofs are a part of consensus, this tracking will not be needed.
///
/// 4. **Broadcast Queue**: Manages a queue of newly received proofs that need to be
///    broadcasted to the network.
///
/// # Stateless Validation Flow (Roughly)
///
/// 1. When a beacon block is imported optimistically, it is registered as pending
/// 2. Network participants generate and submit proofs for the execution payload
/// 3. Once sufficient proofs are received (e.g., 2 out of 3), the block transitions to proven
/// 4. The proven chain is updated, potentially advancing the proven head
/// 5. Old or abandoned blocks are periodically cleaned up
///
/// # Thread Safety
///
/// All state is protected by read-write locks, making this store safe to access
/// across multiple threads.
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
}

// ============================================================================
// Proof Management
// ============================================================================

impl ExecutionPayloadProofStore {
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

    /// Generate a proof for an execution payload
    /// TODO: can remove
    async fn generate_proof<T: EthSpec>(
        payload: &ExecutionPayload<T>,
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> ExecutionProof {
        crate::execution_proof_generation::generate_proof(
            payload,
            execution_state_witness,
            proof_id,
        )
        .await
    }

    /// Validate a proof
    /// TODO: can remove
    fn validate_proof(proof: &ExecutionProof) -> bool {
        crate::execution_proof_generation::validate_proof(proof)
    }

    /// Generate and store a proof for the given execution payload and proof ID
    ///
    /// This is a convenience method that combines proof generation and storage
    pub async fn generate_and_store_proof<T: EthSpec>(
        &self,
        payload: &ExecutionPayload<T>,
        execution_state_witness: &[u8],
        proof_id: ProofId,
    ) -> Result<ExecutionProof, ExecutionProofError> {
        let proof = Self::generate_proof(payload, execution_state_witness, proof_id).await;
        self.store_proof(proof.clone())?;
        Ok(proof)
    }
}

// ============================================================================
// Broadcasting
// ============================================================================

impl ExecutionPayloadProofStore {
    /// Take all proofs from the broadcast queue
    /// This drains the queue and returns all pending proofs
    ///
    /// Note: This is used for the BroadcastManager
    pub fn take_unqueued_proofs(&self) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut queue = self.broadcast_queue.write();
        std::mem::take(&mut *queue)
    }
}

// ============================================================================
// Pending Block Management
// ============================================================================

impl ExecutionPayloadProofStore {
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
}

// ============================================================================
// Chain Updates
// ============================================================================

impl ExecutionPayloadProofStore {
    /// Check if an execution payload has sufficient proofs to be considered proven
    /// This uses the `stateless_min_proofs_required` from the chain config
    fn has_sufficient_proofs(
        &self,
        execution_block_hash: &ExecutionBlockHash,
        min_proofs_required: usize,
    ) -> bool {
        let proof_count = self.proof_count_for_payload(execution_block_hash);
        proof_count >= min_proofs_required
    }

    /// Collect proven blocks by walking backwards from the given head
    ///
    /// # Parameters
    /// - `get_block`: A function that takes a block root and returns block information:
    ///   - Input: `&Hash256` - The block root to look up
    ///   - Output: `Result<Option<(slot, parent_root, exec_hash_opt)>, Error>`
    ///     - `slot`: The slot number of the block
    ///     - `parent_root`: The parent block's root hash
    ///     - `exec_hash_opt`: The execution payload hash (None for pre-merge blocks)
    ///   - Returns `Ok(None)` if block doesn't exist
    ///   - Returns `Err` on storage/retrieval errors
    /// - `head_block_root`: The block root to start walking backwards from
    /// - `min_proofs_required`: Minimum number of proofs needed to consider a block proven
    ///
    /// # Returns
    /// - `proven_chain`: Vector of proven blocks (from newest to oldest)
    /// - `proven_head`: The deepest proven block (highest slot with proofs), if any
    fn collect_proven_blocks<F, E>(
        &self,
        get_block: F,
        head_block_root: Hash256,
        min_proofs_required: usize,
    ) -> (Vec<ProvenBlockInfo>, Option<(Hash256, Slot)>)
    where
        F: Fn(&Hash256) -> Result<Option<(Slot, Hash256, Option<ExecutionBlockHash>)>, E>,
        E: std::fmt::Debug,
    {
        let mut current = head_block_root;
        let mut proven_chain = Vec::new();
        let mut proven_head_candidate = None;

        // Walk backwards through the chain using the provided getter
        while let Ok(Some((slot, parent_root, exec_hash_opt))) = get_block(&current) {
            // Check if this is a pre-merge block
            let exec_hash = match exec_hash_opt {
                Some(hash) => hash,
                None => {
                    // Pre-merge block, stop here
                    // TODO: should we just panic here?
                    break;
                }
            };

            // Check if this block has sufficient proofs
            if self.has_sufficient_proofs(&exec_hash, min_proofs_required) {
                let proof_count = self.proof_count_for_payload(&exec_hash);

                let proven_info = ProvenBlockInfo {
                    beacon_block_root: current, // Use the current block root we're examining
                    execution_block_hash: exec_hash,
                    slot,
                    parent_root,
                    proof_count,
                };

                proven_chain.push(proven_info);

                // Track the deepest proven block as head candidate
                if proven_head_candidate.is_none() {
                    proven_head_candidate = Some((current, slot));
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

        (proven_chain, proven_head_candidate)
    }

    /// Update the proven chain storage with new proven blocks
    /// Returns true if the proven head changed
    fn update_proven_storage(
        &self,
        proven_chain: &[ProvenBlockInfo],
        proven_head_candidate: Option<(Hash256, Slot)>,
    ) -> bool {
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

        head_changed
    }

    /// Update the proven canonical chain based on available proofs
    /// This method walks backwards from the optimistic head to find the longest proven chain
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
    pub fn update_proven_chain<F, E>(
        &self,
        get_block: F,
        head_block_root: Hash256,
        current_slot: Slot,
        slots_per_epoch: u64,
        min_proofs_required: usize,
    ) -> Result<ProvenChainStatus, String>
    where
        F: Fn(&Hash256) -> Result<Option<(Slot, Hash256, Option<ExecutionBlockHash>)>, E>,
        E: std::fmt::Debug,
    {
        // Keep track of the current proven head before update to detect actual changes
        let _previous_proven_head = self.proven_head.read().clone();

        // Step 1: Collect proven blocks by walking backwards from head
        let (proven_chain, proven_head_candidate) =
            self.collect_proven_blocks(get_block, head_block_root, min_proofs_required);

        // Step 2: Update storage with the new proven chain
        let head_changed = self.update_proven_storage(&proven_chain, proven_head_candidate);

        // Step 3: Update proven finalized checkpoint
        self.update_proven_finalized(&proven_chain, current_slot, slots_per_epoch);

        // Step 4: Get current proven finalized for status
        let proven_finalized = self.proven_finalized.read().clone();

        Ok(ProvenChainStatus {
            proven_head: proven_head_candidate,
            proven_finalized,
            proven_chain_depth: proven_chain.len(),
            head_changed,
        })
    }

    /// Update the proven finalized checkpoint based on the proven chain
    fn update_proven_finalized(
        &self,
        proven_chain: &[ProvenBlockInfo],
        current_slot: Slot,
        slots_per_epoch: u64,
    ) {
        if proven_chain.is_empty() {
            return;
        }

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
        }
    }
}

#[cfg(test)]
impl ExecutionPayloadProofStore {
    /// Get the total number of stored proofs (across all proof types and payloads)
    fn len(&self) -> usize {
        self.proofs.read().len()
    }

    /// Check if we have any proof for the given execution block hash
    /// Returns true if at least one proof type exists
    ///
    /// Note: all stored proofs are validated. We assume that proofs are added via `store_proofs`
    fn has_valid_proof(&self, block_hash: &ExecutionBlockHash) -> bool {
        let proofs = self.proofs.read();
        proofs.keys().any(|(hash, _proof_id)| hash == block_hash)
    }

    /// Check if we have a proof for a specific proof ID and execution block hash
    /// Returns true if the proof exists
    ///
    /// Note: all stored proofs are validated. We assume that proofs are added via `store_proofs`
    fn has_valid_proof_for_id(&self, block_hash: &ExecutionBlockHash, proof_id: ProofId) -> bool {
        let proofs = self.proofs.read();
        proofs.contains_key(&(*block_hash, proof_id))
    }

    /// Get the number of unique payloads that have at least one proof
    fn unique_payload_count(&self) -> usize {
        let proofs = self.proofs.read();
        let unique_hashes: std::collections::HashSet<ExecutionBlockHash> =
            proofs.keys().map(|(hash, _proof_id)| *hash).collect();
        unique_hashes.len()
    }

    /// Get the number of execution block hashes that have pending blocks
    fn pending_execution_hashes_count(&self) -> usize {
        self.pending_blocks.read().len()
    }

    /// Get the total number of pending beacon blocks across all execution hashes
    fn total_pending_blocks_count(&self) -> usize {
        self.pending_blocks
            .read()
            .values()
            .map(|blocks| blocks.len())
            .sum()
    }

    /// Get the current proven head (beacon block root and slot)
    /// Returns None if no proven head has been established yet
    fn get_proven_head(&self) -> Option<(Hash256, Slot)> {
        *self.proven_head.read()
    }

    /// Get the proven finalized checkpoint (beacon block root and slot)
    /// Returns None if no proven finalized checkpoint has been established yet
    fn get_proven_finalized(&self) -> Option<(Hash256, Slot)> {
        *self.proven_finalized.read()
    }

    /// Check if a beacon block is part of the proven canonical chain
    fn is_block_proven(&self, beacon_block_root: &Hash256) -> bool {
        self.proven_canonical_chain
            .read()
            .contains_key(beacon_block_root)
    }

    /// Get beacon block roots that are pending proofs for the given execution block hash
    /// (Test-only helper method)
    fn get_pending_blocks(&self, execution_block_hash: &ExecutionBlockHash) -> Vec<Hash256> {
        self.pending_blocks
            .read()
            .get(execution_block_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get information about a proven block
    fn get_proven_block_info(&self, beacon_block_root: &Hash256) -> Option<ProvenBlockInfo> {
        self.proven_canonical_chain
            .read()
            .get(beacon_block_root)
            .cloned()
    }

    /// Get the entire proven canonical chain from finalized to head
    /// Returns a vector of proven blocks ordered from oldest to newest
    fn get_proven_canonical_chain(&self) -> Vec<ProvenBlockInfo> {
        let chain = self.proven_canonical_chain.read();
        let mut blocks: Vec<ProvenBlockInfo> = chain.values().cloned().collect();
        // Sort by slot, oldest first
        blocks.sort_by_key(|b| b.slot);
        blocks
    }

    /// Get the depth of the proven chain (number of proven blocks)
    fn get_proven_chain_depth(&self) -> usize {
        self.proven_canonical_chain.read().len()
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

    #[tokio::test]
    async fn test_generate_and_store_proof_method() {
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
        let result = store
            .generate_and_store_proof(&exec_payload, dummy_witness, proof_id)
            .await;
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
        let result_2 = store
            .generate_and_store_proof(&exec_payload2, dummy_witness, proof_id_2)
            .await;
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
        let exec_hash = ExecutionBlockHash::from(Hash256::from_low_u64_be(101));

        // Initially not proven
        assert!(!store.is_block_proven(&beacon_root));

        // Store proofs for the execution payload
        for i in 0..2 {
            let proof = ExecutionProof::new(
                exec_hash,
                ExecutionProofSubnetId::new(i).unwrap(),
                1,
                vec![i as u8],
            );
            store.store_proof(proof).unwrap();
        }

        // Mock getter that returns our block
        let mock_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            &'static str,
        > {
            if *block_root == beacon_root {
                Ok(Some((Slot::new(1), Hash256::zero(), Some(exec_hash))))
            } else {
                Ok(None)
            }
        };

        // Update proven chain
        let status = store
            .update_proven_chain(mock_getter, beacon_root, Slot::new(10), 32, 2)
            .unwrap();

        // Now the block should be proven
        assert!(store.is_block_proven(&beacon_root));
        assert_eq!(status.proven_head, Some((beacon_root, Slot::new(1))));

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
        assert!(pending.contains(&beacon_root1));
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
        let exec_hash = ExecutionBlockHash::from(Hash256::random());

        // Initially not proven
        assert!(!store.is_block_proven(&beacon_root));

        // Store proofs
        for i in 0..3 {
            let proof = ExecutionProof::new(
                exec_hash,
                ExecutionProofSubnetId::new(i).unwrap(),
                1,
                vec![i as u8],
            );
            store.store_proof(proof).unwrap();
        }

        // Create a simple chain: genesis <- block1
        let mock_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            &'static str,
        > {
            if *block_root == beacon_root {
                Ok(Some((Slot::new(1), Hash256::zero(), Some(exec_hash))))
            } else if block_root == &Hash256::zero() {
                Ok(None) // Genesis
            } else {
                Ok(None)
            }
        };

        // Update proven chain with min_proofs = 3
        store
            .update_proven_chain(mock_getter, beacon_root, Slot::new(100), 32, 3)
            .unwrap();

        // Now it should be proven
        assert!(store.is_block_proven(&beacon_root));

        // Random block should not be proven
        let random_root = Hash256::random();
        assert!(!store.is_block_proven(&random_root));
    }

    #[test]
    fn test_get_proven_block_info() {
        let store = ExecutionPayloadProofStore::new(100);

        let beacon_root = Hash256::random();
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        let parent_root = Hash256::random();

        // Should return None for non-existent blocks
        assert!(store.get_proven_block_info(&beacon_root).is_none());

        // Store proofs
        for i in 0..2 {
            let proof = ExecutionProof::new(
                exec_hash,
                ExecutionProofSubnetId::new(i).unwrap(),
                1,
                vec![i as u8],
            );
            store.store_proof(proof).unwrap();
        }

        // Mock getter
        let mock_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            &'static str,
        > {
            if *block_root == beacon_root {
                Ok(Some((Slot::new(42), parent_root, Some(exec_hash))))
            } else if *block_root == parent_root {
                Ok(Some((Slot::new(41), Hash256::zero(), None))) // Parent is pre-merge
            } else {
                Ok(None)
            }
        };

        // Update proven chain
        store
            .update_proven_chain(mock_getter, beacon_root, Slot::new(100), 32, 2)
            .unwrap();

        // Now we should be able to get the proven block info
        let info = store.get_proven_block_info(&beacon_root);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.beacon_block_root, beacon_root);
        assert_eq!(info.execution_block_hash, exec_hash);
        assert_eq!(info.slot, Slot::new(42));
        assert_eq!(info.parent_root, parent_root);
        assert_eq!(info.proof_count, 2);
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

    #[test]
    fn test_update_proven_storage() {
        let store = ExecutionPayloadProofStore::new(100);

        // Initially no proven head
        assert!(store.get_proven_head().is_none());

        // Create some test proven blocks
        let block1_root = Hash256::from_low_u64_be(1);
        let block2_root = Hash256::from_low_u64_be(2);
        let exec_hash1 = ExecutionBlockHash::from(Hash256::from_low_u64_be(101));
        let exec_hash2 = ExecutionBlockHash::from(Hash256::from_low_u64_be(102));

        let proven_chain = vec![
            ProvenBlockInfo {
                beacon_block_root: block1_root,
                execution_block_hash: exec_hash1,
                slot: Slot::new(1),
                parent_root: Hash256::zero(),
                proof_count: 2,
            },
            ProvenBlockInfo {
                beacon_block_root: block2_root,
                execution_block_hash: exec_hash2,
                slot: Slot::new(2),
                parent_root: block1_root,
                proof_count: 3,
            },
        ];

        let proven_head_candidate = Some((block2_root, Slot::new(2)));

        // Update storage
        let head_changed = store.update_proven_storage(&proven_chain, proven_head_candidate);
        assert!(head_changed);

        // Verify proven head was updated
        assert_eq!(store.get_proven_head(), proven_head_candidate);

        // Verify blocks are in proven chain
        assert!(store.is_block_proven(&block1_root));
        assert!(store.is_block_proven(&block2_root));

        // Verify block info is stored correctly
        let block1_info = store.get_proven_block_info(&block1_root).unwrap();
        assert_eq!(block1_info.execution_block_hash, exec_hash1);
        assert_eq!(block1_info.slot, Slot::new(1));

        // Test updating with same head (no change)
        let head_changed2 = store.update_proven_storage(&proven_chain, proven_head_candidate);
        assert!(!head_changed2);

        // Test clearing proven chain
        let head_changed3 = store.update_proven_storage(&[], None);
        assert!(head_changed3);
        assert!(store.get_proven_head().is_none());
        assert!(!store.is_block_proven(&block1_root));
    }

    #[test]
    fn test_proven_chain_depth_tracking() {
        let store = ExecutionPayloadProofStore::new(100);

        // Initially depth is 0
        assert_eq!(store.get_proven_chain_depth(), 0);

        // Create a chain of 5 blocks
        let mut proven_chain = Vec::new();
        for i in 1..=5 {
            proven_chain.push(ProvenBlockInfo {
                beacon_block_root: Hash256::from_low_u64_be(i),
                execution_block_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(100 + i)),
                slot: Slot::new(i),
                parent_root: if i == 1 {
                    Hash256::zero()
                } else {
                    Hash256::from_low_u64_be(i - 1)
                },
                proof_count: 2,
            });
        }

        let proven_head = Some((Hash256::from_low_u64_be(5), Slot::new(5)));
        store.update_proven_storage(&proven_chain, proven_head);

        // Verify depth
        assert_eq!(store.get_proven_chain_depth(), 5);

        // Verify chain is ordered correctly
        let chain = store.get_proven_canonical_chain();
        assert_eq!(chain.len(), 5);
        for (i, block) in chain.iter().enumerate() {
            assert_eq!(block.slot, Slot::new((i + 1) as u64));
        }
    }

    #[test]
    fn test_cleanup_pending_blocks_integration() {
        let store = ExecutionPayloadProofStore::new(100);

        // Set up some execution hashes and beacon blocks
        let exec_hash1 = ExecutionBlockHash::from(Hash256::random());
        let exec_hash2 = ExecutionBlockHash::from(Hash256::random());
        let beacon_root1 = Hash256::from_low_u64_be(1);
        let beacon_root2 = Hash256::from_low_u64_be(2);
        let beacon_root3 = Hash256::from_low_u64_be(3);

        // Register pending blocks
        store.register_pending_block(exec_hash1, beacon_root1);
        store.register_pending_block(exec_hash1, beacon_root2);
        store.register_pending_block(exec_hash2, beacon_root3);

        // Initial counts
        assert_eq!(store.pending_execution_hashes_count(), 2);
        assert_eq!(store.total_pending_blocks_count(), 3);

        // Clean up blocks 1 and 3 (simulating they're finalized)
        let removed =
            store.cleanup_pending_blocks(|root| root == beacon_root1 || root == beacon_root3);
        assert_eq!(removed, 2);

        // Verify remaining state
        assert_eq!(store.pending_execution_hashes_count(), 1);
        assert_eq!(store.total_pending_blocks_count(), 1);

        let remaining = store.get_pending_blocks(&exec_hash1);
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains(&beacon_root2));
    }

    #[test]
    fn test_collect_proven_blocks() {
        let store = ExecutionPayloadProofStore::new(100);

        // Set up test data
        let block1_root = Hash256::from_low_u64_be(1);
        let block2_root = Hash256::from_low_u64_be(2);
        let block3_root = Hash256::from_low_u64_be(3);
        let block4_root = Hash256::from_low_u64_be(4);
        let block5_root = Hash256::from_low_u64_be(5);

        let exec_hash1 = ExecutionBlockHash::from(Hash256::from_low_u64_be(101));
        let exec_hash2 = ExecutionBlockHash::from(Hash256::from_low_u64_be(102));
        let exec_hash3 = ExecutionBlockHash::from(Hash256::from_low_u64_be(103));
        let exec_hash4 = ExecutionBlockHash::from(Hash256::from_low_u64_be(104));
        let exec_hash5 = ExecutionBlockHash::from(Hash256::from_low_u64_be(105));

        // Add proofs for blocks 1, 2, and 3 (but not 4 and 5)
        for exec_hash in &[exec_hash1, exec_hash2, exec_hash3] {
            for subnet in 0..2 {
                let proof = ExecutionProof::new(
                    *exec_hash,
                    ExecutionProofSubnetId::new(subnet).unwrap(),
                    1,
                    vec![1, 2, 3],
                );
                store.store_proof(proof).unwrap();
            }
        }

        // Create a mock getter that simulates the chain
        let mock_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            String,
        > {
            if *block_root == block5_root {
                Ok(Some((Slot::new(5), block4_root, Some(exec_hash5))))
            } else if *block_root == block4_root {
                Ok(Some((Slot::new(4), block3_root, Some(exec_hash4))))
            } else if *block_root == block3_root {
                Ok(Some((Slot::new(3), block2_root, Some(exec_hash3))))
            } else if *block_root == block2_root {
                Ok(Some((Slot::new(2), block1_root, Some(exec_hash2))))
            } else if *block_root == block1_root {
                Ok(Some((Slot::new(1), Hash256::zero(), Some(exec_hash1))))
            } else if *block_root == Hash256::zero() {
                Ok(None) // Genesis has no parent
            } else {
                Ok(None)
            }
        };

        // Test collecting from block 5 (head) with min_proofs = 2
        let (proven_chain, proven_head) = store.collect_proven_blocks(
            mock_getter,
            block5_root,
            2, // min_proofs_required
        );

        // Should find no proven blocks because block 5 has no proofs (stops immediately)
        assert_eq!(proven_chain.len(), 0);
        assert_eq!(proven_head, None);

        // Now test from block 3 which has proofs
        let (proven_chain2, proven_head2) =
            store.collect_proven_blocks(mock_getter, block3_root, 2);

        // Should find blocks 3, 2, 1 as proven
        assert_eq!(proven_chain2.len(), 3);
        assert_eq!(proven_chain2[0].beacon_block_root, block3_root);
        assert_eq!(proven_chain2[1].beacon_block_root, block2_root);
        assert_eq!(proven_chain2[2].beacon_block_root, block1_root);
        assert_eq!(proven_head2, Some((block3_root, Slot::new(3))));

        // Test with pre-merge block
        let pre_merge_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            String,
        > {
            if *block_root == block3_root {
                Ok(Some((Slot::new(3), block2_root, Some(exec_hash3))))
            } else if *block_root == block2_root {
                Ok(Some((Slot::new(2), block1_root, None))) // Pre-merge
            } else {
                Ok(None)
            }
        };

        let (proven_chain_pre_merge, proven_head_pre_merge) =
            store.collect_proven_blocks(pre_merge_getter, block3_root, 2);

        // Should only find block 3 (stops at pre-merge block 2)
        assert_eq!(proven_chain_pre_merge.len(), 1);
        assert_eq!(proven_chain_pre_merge[0].beacon_block_root, block3_root);
        assert_eq!(proven_head_pre_merge, Some((block3_root, Slot::new(3))));
    }

    #[test]
    fn test_proof_broadcast_queue() {
        let store = ExecutionPayloadProofStore::new(100);

        // Initially queue is empty
        let proofs = store.take_unqueued_proofs();
        assert!(proofs.is_empty());

        // Store a proof (should add to broadcast queue)
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(0).unwrap();
        let proof = ExecutionProof::new(exec_hash, proof_id, 1, vec![1, 2, 3]);
        store.store_proof(proof).unwrap();

        // Take from queue
        let proofs = store.take_unqueued_proofs();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0], (exec_hash, proof_id));

        // Queue should be empty after taking
        let proofs = store.take_unqueued_proofs();
        assert!(proofs.is_empty());
    }

    #[test]
    fn test_update_proven_chain_returns_status() {
        let store = ExecutionPayloadProofStore::new(100);

        // Setup mock blocks
        let exec_hash1 = ExecutionBlockHash::from(Hash256::from_low_u64_be(101));
        let exec_hash2 = ExecutionBlockHash::from(Hash256::from_low_u64_be(102));
        let block1_root = Hash256::from_low_u64_be(1);
        let block2_root = Hash256::from_low_u64_be(2);

        // Store proofs for both blocks
        for i in 0..2 {
            let proof1 = ExecutionProof::new(
                exec_hash1,
                ExecutionProofSubnetId::new(i).unwrap(),
                1,
                vec![i as u8],
            );
            store.store_proof(proof1).unwrap();

            let proof2 = ExecutionProof::new(
                exec_hash2,
                ExecutionProofSubnetId::new(i).unwrap(),
                1,
                vec![i as u8, 2],
            );
            store.store_proof(proof2).unwrap();
        }

        // Mock getter
        let mock_getter = |block_root: &Hash256| -> Result<
            Option<(Slot, Hash256, Option<ExecutionBlockHash>)>,
            &'static str,
        > {
            if *block_root == block2_root {
                Ok(Some((Slot::new(2), block1_root, Some(exec_hash2))))
            } else if *block_root == block1_root {
                Ok(Some((Slot::new(1), Hash256::zero(), Some(exec_hash1))))
            } else {
                Ok(None)
            }
        };

        // Test update_proven_chain
        let status = store
            .update_proven_chain(
                mock_getter,
                block2_root,
                Slot::new(10), // current slot
                32,            // slots per epoch
                2,             // min proofs required
            )
            .unwrap();

        // Verify status - both blocks have proofs, so proven head should be block2
        assert_eq!(status.proven_head, Some((block2_root, Slot::new(2))));
        assert_eq!(status.proven_chain_depth, 2);
        assert!(status.head_changed);
        assert_eq!(status.proven_finalized, None); // Too recent to be finalized

        // Update again with same state - head_changed should be false
        let status2 = store
            .update_proven_chain(mock_getter, block2_root, Slot::new(10), 32, 2)
            .unwrap();

        assert!(!status2.head_changed);
        assert_eq!(status2.proven_head, status.proven_head);
    }

    #[test]
    fn test_update_proven_finalized() {
        let store = ExecutionPayloadProofStore::new(100);

        // Create a proven chain with blocks at different epochs
        let mut proven_chain = Vec::new();
        let slots_per_epoch = 32;

        // Block at slot 32 (epoch 1)
        proven_chain.push(ProvenBlockInfo {
            beacon_block_root: Hash256::from_low_u64_be(1),
            execution_block_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(101)),
            slot: Slot::new(32),
            parent_root: Hash256::zero(),
            proof_count: 2,
        });

        // Block at slot 64 (epoch 2)
        proven_chain.push(ProvenBlockInfo {
            beacon_block_root: Hash256::from_low_u64_be(2),
            execution_block_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(102)),
            slot: Slot::new(64),
            parent_root: Hash256::from_low_u64_be(1),
            proof_count: 2,
        });

        // Block at slot 96 (epoch 3)
        proven_chain.push(ProvenBlockInfo {
            beacon_block_root: Hash256::from_low_u64_be(3),
            execution_block_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(103)),
            slot: Slot::new(96),
            parent_root: Hash256::from_low_u64_be(2),
            proof_count: 2,
        });

        // Test at current slot 160 (epoch 5) - blocks at epochs 1,2,3 should be finalizable
        store.update_proven_finalized(&proven_chain, Slot::new(160), slots_per_epoch);

        let finalized = store.proven_finalized.read();
        assert_eq!(
            *finalized,
            Some((Hash256::from_low_u64_be(3), Slot::new(96)))
        );
        drop(finalized);

        // Test with current slot 96 (epoch 3) - only block at epoch 1 should be finalizable
        store.update_proven_finalized(&proven_chain, Slot::new(96), slots_per_epoch);

        let finalized2 = store.proven_finalized.read();
        assert_eq!(
            *finalized2,
            Some((Hash256::from_low_u64_be(1), Slot::new(32)))
        );
    }
}
