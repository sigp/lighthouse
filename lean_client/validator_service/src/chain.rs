use std::collections::HashMap;
use std::sync::Arc;

use lean_consensus::attestation::{SignedAttestation, Slot as LeanSlot};
use lean_consensus::lean_block::{LeanBlock, LeanBlockBody};
use lean_consensus::lean_state::LeanState;
use lean_forkchoice::proto_array::{ProtoArray, ProtoArrayError};
use lean_store::LeanStore;
use ssz::{Decode, Encode};
use store::KeyValueStore;
use tree_hash::TreeHash;
use types::{EthSpec, FixedBytesExtended, Hash256, VariableList};

/// Central coordinator for fork-choice state and database access.
///
/// `LeanChain` maintains an in-memory proto-array alongside persistent storage.
/// The validator service delegates block/attestation integration and head updates to this struct.
///
/// States and blocks are cached in memory per root, avoiding database reads during block processing.
/// The database is used for persistence only, with all hot-path operations using the in-memory caches.
pub struct LeanChain<E: EthSpec, D: KeyValueStore<E>> {
    store: LeanStore<E, D>,
    proto_array: ProtoArray,
    latest_votes: HashMap<u64, Hash256>,
    /// In-memory cache of states keyed by block root
    states: HashMap<Hash256, Arc<LeanState<E>>>,
    /// In-memory cache of blocks keyed by block root
    blocks: HashMap<Hash256, LeanBlock<E>>,
}

impl<E: EthSpec, D: KeyValueStore<E>> LeanChain<E, D> {
    /// Clones a state using SSZ serialization/deserialization.
    ///
    /// Ensures deep copies of all state fields including complex types like milhouse::List and BitVector.
    pub fn clone_state(state: &LeanState<E>) -> Result<LeanState<E>, String> {
        let bytes = state.as_ssz_bytes();
        LeanState::from_ssz_bytes(&bytes)
            .map_err(|e| format!("Failed to clone state via SSZ: {:?}", e))
    }

    /// Construct a new chain coordinator from an existing key-value backend.
    pub fn new(db: Arc<D>) -> Self {
        let store = LeanStore::new(db);
        let (proto_array, latest_votes, states, blocks) = match Self::initialize_fork_choice(&store)
        {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to initialize proto array from store, starting empty"
                );
                (
                    ProtoArray::new(Hash256::zero(), LeanSlot(0)),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                )
            }
        };

        Self {
            store,
            proto_array,
            latest_votes,
            states,
            blocks,
        }
    }

    /// Returns a reference to the underlying store.
    pub fn store(&self) -> &LeanStore<E, D> {
        &self.store
    }

    /// Registers a block with the in-memory proto-array, ensuring the parent chain exists.
    pub fn register_block(
        &mut self,
        block_root: Hash256,
        slot: LeanSlot,
        parent_root: Hash256,
    ) -> Result<(), String> {
        if parent_root != Hash256::zero() {
            self.ensure_block_in_proto_array(parent_root)?;
        }

        self.proto_array
            .on_block(block_root, slot, parent_root)
            .map_err(Self::format_proto_error)
    }

    /// Returns true if the block root is in cache or on disk.
    pub fn block_exists(&self, block_root: Hash256) -> Result<bool, String> {
        if self.blocks.contains_key(&block_root) {
            return Ok(true);
        }
        self.store.block_exists(block_root)
    }

    /// Gets a block from the cache by root.
    /// Returns None if the block is not in the cache.
    pub fn get_block(&self, block_root: &Hash256) -> Option<&LeanBlock<E>> {
        self.blocks.get(block_root)
    }

    /// Gets a state from the cache by block root.
    /// Returns None if the state is not in the cache.
    pub fn get_state(&self, block_root: &Hash256) -> Option<Arc<LeanState<E>>> {
        self.states.get(block_root).cloned()
    }

    /// Fetches a block by root from cache first, then DB if not cached.
    /// Use get_block() for cache-only access during hot paths.
    ///
    /// Note: This method takes &self and returns a clone. For write-heavy workloads,
    /// consider using get_block() which returns a reference.
    pub fn fetch_block(&self, block_root: Hash256) -> Result<Option<LeanBlock<E>>, String> {
        // Check cache first
        if let Some(block) = self.blocks.get(&block_root) {
            return Ok(Some(block.clone()));
        }

        // Fall back to DB and populate cache
        // Since we have &self, we can't mutate the cache here.
        // The block will be cached when saved via save_block().
        self.store.fetch_block(block_root)
    }

    /// Persists a block to cache and disk atomically.
    pub fn save_block(&mut self, block_root: Hash256, block: &LeanBlock<E>) -> Result<(), String> {
        // Update cache first
        self.blocks.insert(block_root, block.clone());
        // Then persist to disk
        self.store.save_block(block_root, block)
    }

    /// Returns all blocks from cache.
    pub fn load_all_blocks(&self) -> Result<HashMap<Hash256, LeanBlock<E>>, String> {
        Ok(self.blocks.clone())
    }

    /// Returns the latest head root from disk.
    pub fn fetch_head_root(&self) -> Result<Option<Hash256>, String> {
        self.store.fetch_head_root()
    }

    /// Retrieves a state by block root from cache.
    /// Returns None if not in cache. Does not hit the database.
    pub fn fetch_state(&self, block_root: &Hash256) -> Option<Arc<LeanState<E>>> {
        self.get_state(block_root)
    }

    /// Gets the current head state from cache.
    /// Returns None if head root is not set or state not in cache.
    pub fn get_head_state(&self) -> Option<Arc<LeanState<E>>> {
        let head_root = self.store.fetch_head_root().ok()??;
        self.get_state(&head_root)
    }

    /// Persists a state to cache and disk atomically.
    /// The state is associated with the provided block root.
    pub fn save_state(&mut self, block_root: Hash256, state: &LeanState<E>) -> Result<(), String> {
        // Update cache first
        self.states
            .insert(block_root, Arc::new(Self::clone_state(state)?));
        // Persist to disk (using the old single-state model for now)
        self.store.save_state(state)
    }

    /// Returns the current safe target if stored.
    pub fn fetch_safe_target(&self) -> Result<Option<Hash256>, String> {
        self.store.fetch_safe_target()
    }

    /// Persists the safe target root.
    pub fn save_safe_target(&self, safe_target: Hash256) -> Result<(), String> {
        self.store.save_safe_target(safe_target)
    }

    /// Loads all known attestations keyed by validator index.
    pub fn load_known_attestations(&self) -> Result<HashMap<u64, SignedAttestation>, String> {
        self.store.load_known_attestations()
    }

    /// Loads all new attestations keyed by validator index.
    pub fn load_new_attestations(&self) -> Result<HashMap<u64, SignedAttestation>, String> {
        self.store.load_new_attestations()
    }

    /// Persists a new attestation.
    pub fn save_new_attestation(
        &self,
        validator_id: u64,
        attestation: &SignedAttestation,
    ) -> Result<(), String> {
        self.store.save_new_attestation(validator_id, attestation)
    }

    /// Persists a known attestation.
    pub fn save_known_attestation(
        &self,
        validator_id: u64,
        attestation: &SignedAttestation,
    ) -> Result<(), String> {
        self.store.save_known_attestation(validator_id, attestation)
    }

    /// Deletes a pending attestation for the given validator.
    pub fn delete_new_attestation(&self, validator_id: u64) -> Result<(), String> {
        self.store.delete_new_attestation(validator_id)
    }

    /// Applies weight for a validator attestation to the fork-choice tree.
    pub fn apply_attestation_weight(
        &mut self,
        validator_id: u64,
        head_root: Hash256,
    ) -> Result<(), String> {
        if head_root == Hash256::zero() {
            return Ok(());
        }

        self.ensure_block_in_proto_array(head_root)?;

        if let Some(previous_root) = self.latest_votes.get(&validator_id).copied() {
            if previous_root == head_root {
                return Ok(());
            }

            self.proto_array
                .remove_weight(previous_root, 1)
                .map_err(Self::format_proto_error)?;
        }

        self.proto_array
            .add_weight(head_root, 1)
            .map_err(Self::format_proto_error)?;
        self.latest_votes.insert(validator_id, head_root);
        Ok(())
    }

    /// Promotes pending attestations to known, updating fork-choice weights in the process.
    pub fn promote_new_attestations(&mut self) -> Result<(), String> {
        let new_attestations = self.store.load_new_attestations()?;
        for (validator_id, attestation) in new_attestations.iter() {
            let head_root = attestation.message.attestation_data.head.root;
            if let Err(e) = self.apply_attestation_weight(*validator_id, head_root) {
                tracing::warn!(
                    validator_id = *validator_id,
                    ?head_root,
                    error = %e,
                    "Failed to apply weight for promoted attestation"
                );
            }
        }
        self.store.accept_new_attestations()
    }

    /// Updates the canonical head using the proto-array and persists it to the store.
    pub fn update_head(&mut self, current_state: &LeanState<E>) -> Result<Hash256, String> {
        let stored_head = self.store.fetch_head_root()?;
        let current_head_root = current_state.latest_block_header.tree_hash_root();
        let candidates = [
            Some(current_state.latest_justified.root),
            stored_head,
            Some(current_head_root),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate == Hash256::zero() {
                continue;
            }

            if let Err(e) = self.ensure_block_in_proto_array(candidate) {
                tracing::warn!(
                    ?candidate,
                    error = %e,
                    "Failed to ensure candidate root exists in proto array"
                );
                continue;
            }

            match self.proto_array.find_head(candidate) {
                Ok(head) => {
                    self.store.save_head_root(head)?;
                    return Ok(head);
                }
                Err(err) => {
                    let err_msg = Self::format_proto_error(err);
                    tracing::warn!(
                        ?candidate,
                        error = err_msg,
                        "Proto array head selection failed for candidate"
                    );
                }
            }
        }

        self.store.save_head_root(Hash256::zero())?;
        Ok(Hash256::zero())
    }

    fn initialize_fork_choice(
        store: &LeanStore<E, D>,
    ) -> Result<
        (
            ProtoArray,
            HashMap<u64, Hash256>,
            HashMap<Hash256, Arc<LeanState<E>>>,
            HashMap<Hash256, LeanBlock<E>>,
        ),
        String,
    > {
        let state = match store.fetch_state()? {
            Some(state) => state,
            None => {
                return Ok((
                    ProtoArray::new(Hash256::zero(), LeanSlot(0)),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                ));
            }
        };

        let stored_head = store.fetch_head_root()?;
        let genesis_slot = state.slot;

        // For genesis (slot 0), key the state by the stored head root (populated genesis block)
        // instead of the internal zeroed-header root. This ensures correct cache lookups.
        let genesis_root = if genesis_slot == LeanSlot(0) {
            stored_head.unwrap_or_else(|| state.latest_block_header.tree_hash_root())
        } else {
             state.latest_block_header.tree_hash_root()
        };
        let genesis_proposer = state.latest_block_header.proposer_index.0 as u64;
        let genesis_parent_root = state.latest_block_header.parent_root;
        let genesis_state_root = state.latest_block_header.state_root;

        tracing::info!(
            genesis_root = ?genesis_root,
            genesis_slot = genesis_slot.0,
            "Loaded genesis state from database for fork choice initialization"
        );

        // Initialize state cache with genesis state
        let mut states = HashMap::new();
        states.insert(genesis_root, Arc::new(state));

        // Persist the genesis block if it is not already available.
        if store.fetch_block(genesis_root)?.is_none() {
            let block = LeanBlock {
                slot: genesis_slot,
                proposer_index: genesis_proposer,
                parent_root: genesis_parent_root,
                state_root: genesis_state_root,
                body: LeanBlockBody {
                    attestations: VariableList::default(),
                },
            };
            store.save_block(genesis_root, &block)?;
        }

        // Ensure head and safe target are initialized.
        if store.fetch_head_root()?.is_none() {
            store.save_head_root(genesis_root)?;
        }
        if store.fetch_safe_target()?.is_none() {
            store.save_safe_target(genesis_root)?;
        }

        // Load all known blocks from DB into memory cache
        let blocks = store.load_all_blocks()?;
        let mut proto_array = ProtoArray::new(genesis_root, genesis_slot);

        let mut entries: Vec<_> = blocks.iter().collect();
        entries.sort_by_key(|(_, block)| block.slot.0);

        for (root, block) in entries {
            proto_array
                .on_block(*root, block.slot, block.parent_root)
                .map_err(Self::format_proto_error)?;
        }

        let mut latest_votes = HashMap::new();
        let known_attestations = store.load_known_attestations()?;
        for (validator_id, attestation) in known_attestations {
            let head_root = attestation.message.attestation_data.head.root;
            if !proto_array.contains(&head_root) || head_root == Hash256::zero() {
                continue;
            }
            proto_array
                .add_weight(head_root, 1)
                .map_err(Self::format_proto_error)?;
            latest_votes.insert(validator_id, head_root);
        }

        Ok((proto_array, latest_votes, states, blocks))
    }

    fn ensure_block_in_proto_array(&mut self, block_root: Hash256) -> Result<(), String> {
        if block_root == Hash256::zero() || self.proto_array.contains(&block_root) {
            return Ok(());
        }

        // Fetch block from cache or DB
        let block = self
            .fetch_block(block_root)?
            .ok_or_else(|| format!("Block {:?} not found in cache or store", block_root))?;

        if block.parent_root != Hash256::zero() {
            self.ensure_block_in_proto_array(block.parent_root)?;
        }

        self.proto_array
            .on_block(block_root, block.slot, block.parent_root)
            .map_err(Self::format_proto_error)
    }

    fn format_proto_error(err: ProtoArrayError) -> String {
        match err {
            ProtoArrayError::UnknownParent {
                block_root,
                parent_root,
            } => format!(
                "Proto array missing parent {:?} for block {:?}",
                parent_root, block_root
            ),
            ProtoArrayError::UnknownBlock(root) => {
                format!("Proto array is missing block {:?}", root)
            }
            ProtoArrayError::InvalidNodeIndex(index) => {
                format!("Proto array encountered invalid node index {}", index)
            }
        }
    }
}
