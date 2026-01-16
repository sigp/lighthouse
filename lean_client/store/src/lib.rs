use lean_consensus::attestation::SignedAttestation;
use lean_consensus::lean_block::LeanBlock;
use lean_consensus::lean_state::LeanState;
use ssz::{Decode, Encode};
use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{DBColumn, KeyValueStore};
use types::{EthSpec, Hash256};

/// Rolling block metadata record stored in `StorageKey::BlockMetaIndex`.
///
/// SSZ is not used here; we store fixed-size binary records for compactness:
/// - slot (u64 LE)
/// - block_root (32 bytes)
/// - parent_root (32 bytes)
#[derive(Clone, Copy, Debug)]
struct BlockMetaEntry {
    slot: u64,
    root: Hash256,
    parent_root: Hash256,
}

/// Rolling state metadata record stored in `StorageKey::StateMetaIndex`.
///
/// Fixed-size binary records:
/// - slot (u64 LE)
/// - block_root (32 bytes)
#[derive(Clone, Copy, Debug)]
struct StateMetaEntry {
    slot: u64,
    block_root: Hash256,
}

// Keep meta indices bounded to avoid unbounded allocations and steadily increasing RSS.
// These are "best effort" buffers used for pruning/loading; pruning still enforces the real windows.
const BLOCK_META_INDEX_MAX_ENTRIES: usize = 4096;
const STATE_META_INDEX_MAX_ENTRIES: usize = 4096;

/// Storage key definitions for the lean client
#[derive(Debug, Clone, Copy)]
enum StorageKey {
    /// Single-item keys
    State,
    HeadRoot,
    SafeTarget,
    /// Prefix-based keys with u64 suffix
    Block,
    /// Prefix-based keys with Hash256 suffix (per-root state)
    StateByRoot,
    Attestation,
    NewAttestation,
    /// Index keys
    /// Legacy: list of all block roots ever seen. Kept for backward compat/migration only.
    BlockRootsIndex,
    /// Rolling block metadata for pruning/loading: (slot, block_root, parent_root) records.
    BlockMetaIndex,
    /// Rolling state metadata for pruning: (slot, state_root_keyed_by_block_root) records.
    StateMetaIndex,
    ValidatorIndices,
    NewValidatorIndices,
}

impl StorageKey {
    /// Get the key bytes, optionally with a u64 suffix
    fn key(&self) -> Vec<u8> {
        match self {
            StorageKey::State => b"lean_state".to_vec(),
            StorageKey::HeadRoot => b"head_root".to_vec(),
            StorageKey::SafeTarget => b"safe_target".to_vec(),
            StorageKey::Block => b"block_".to_vec(),
            StorageKey::StateByRoot => b"lean_state_".to_vec(),
            StorageKey::Attestation => b"attestation_".to_vec(),
            StorageKey::NewAttestation => b"new_attestation_".to_vec(),
            StorageKey::BlockRootsIndex => b"block_roots_index".to_vec(),
            StorageKey::BlockMetaIndex => b"block_meta_index".to_vec(),
            StorageKey::StateMetaIndex => b"state_meta_index".to_vec(),
            StorageKey::ValidatorIndices => b"validator_indices".to_vec(),
            StorageKey::NewValidatorIndices => b"new_validator_indices".to_vec(),
        }
    }

    /// Get key with u64 suffix (for indexed items)
    fn key_with_id(&self, id: u64) -> Vec<u8> {
        let mut key = self.key();
        key.extend_from_slice(&id.to_le_bytes());
        key
    }

    /// Get key with Hash256 suffix (for blocks)
    fn key_with_hash(&self, hash: &Hash256) -> Vec<u8> {
        let mut key = self.key();
        key.extend_from_slice(&hash.0);
        key
    }
}

/// Store for managing lean client database operations
pub struct LeanStore<E: EthSpec, D: KeyValueStore<E>> {
    db: Arc<D>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, D: KeyValueStore<E>> LeanStore<E, D> {
    /// Creates a new store with the provided database
    pub fn new(db: Arc<D>) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    // ============ State Management ============

    /// Fetches the lean state from the database
    pub fn fetch_state(&self) -> Result<Option<LeanState<E>>, String> {
        self.fetch_single_item(StorageKey::State, DBColumn::BeaconMeta)
    }

    /// Saves the lean state to the database
    pub fn save_state(&self, state: &LeanState<E>) -> Result<(), String> {
        self.save_single_item(StorageKey::State, DBColumn::BeaconMeta, state)
    }

    /// Fetches a state by the block root it was computed for.
    pub fn fetch_state_by_root(&self, block_root: Hash256) -> Result<Option<LeanState<E>>, String> {
        let key = StorageKey::StateByRoot.key_with_hash(&block_root);
        self.fetch_with_key(DBColumn::BeaconState, &key)
    }

    /// Saves a state keyed by the block root it was computed for.
    pub fn save_state_by_root(
        &self,
        block_root: Hash256,
        state: &LeanState<E>,
    ) -> Result<(), String> {
        let key = StorageKey::StateByRoot.key_with_hash(&block_root);
        let bytes = state.as_ssz_bytes();
        self.db
            .put_bytes(DBColumn::BeaconState, &key, &bytes)
            .map_err(|e| format!("Failed to save state by root: {:?}", e))?;

        self.append_state_meta(block_root, state.slot.0)?;
        Ok(())
    }

    // ============ Block Management ============

    /// Saves a block to the database by its root and updates the rolling block meta index.
    pub fn save_block(&self, block_root: Hash256, block: &LeanBlock<E>) -> Result<(), String> {
        let key = StorageKey::Block.key_with_hash(&block_root);
        // Avoid duplicate index entries and expensive index rewrites.
        if self
            .db
            .key_exists(DBColumn::BeaconBlock, &key)
            .map_err(|e| format!("Failed to check block existence: {:?}", e))?
        {
            return Ok(());
        }
        let bytes = block.as_ssz_bytes();
        self.db
            .put_bytes(DBColumn::BeaconBlock, &key, &bytes)
            .map_err(|e| format!("Failed to save block: {:?}", e))?;

        // Update rolling block meta index (used for pruning/loading).
        self.append_block_meta(block_root, block.slot.0, block.parent_root)?;
        Ok(())
    }

    /// Fetches a block from the database by its root
    pub fn fetch_block(&self, block_root: Hash256) -> Result<Option<LeanBlock<E>>, String> {
        let key = StorageKey::Block.key_with_hash(&block_root);
        self.fetch_with_key(DBColumn::BeaconBlock, &key)
    }

    /// Checks if a block exists in the database
    pub fn block_exists(&self, block_root: Hash256) -> Result<bool, String> {
        let key = StorageKey::Block.key_with_hash(&block_root);
        self.db
            .key_exists(DBColumn::BeaconBlock, &key)
            .map_err(|e| format!("Failed to check block existence: {:?}", e))
    }

    /// Loads blocks from the database using the rolling block meta index.
    ///
    /// If the meta index doesn't exist yet (older DB), falls back to the legacy block roots index.
    pub fn load_all_blocks(&self) -> Result<HashMap<Hash256, LeanBlock<E>>, String> {
        let mut block_roots: Vec<Hash256> = self
            .load_block_meta_index()?
            .into_iter()
            .map(|m| m.root)
            .collect();

        if block_roots.is_empty() {
            // Backward compat: old DBs only have the legacy index.
            block_roots = self.load_hash256_index(StorageKey::BlockRootsIndex)?;
            // Best-effort migrate: populate meta index from legacy roots by reading blocks.
            self.migrate_block_meta_index_from_roots(&block_roots)?;
        }
        let mut blocks = HashMap::new();

        for block_root in block_roots {
            if let Some(block) = self.fetch_block(block_root)? {
                blocks.insert(block_root, block);
            }
        }

        Ok(blocks)
    }

    /// Prune old blocks from the DB, keeping a rolling window by slot.
    ///
    /// - Keeps all blocks with `slot >= min_slot_to_keep`
    /// - Also keeps any roots in `always_keep_roots` and their ancestors (while those ancestors exist in DB)
    /// - Deletes pruned blocks from `DBColumn::BeaconBlock`
    /// - Rewrites the `BlockRootsIndex` to only include kept roots
    ///
    /// Returns the number of deleted blocks.
    pub fn prune_blocks_older_than(
        &self,
        min_slot_to_keep: u64,
        always_keep_roots: &HashSet<Hash256>,
    ) -> Result<usize, String> {
        let meta_entries = self.load_block_meta_index()?;
        if meta_entries.is_empty() {
            return Ok(0);
        }

        let mut meta: HashMap<Hash256, (u64, Hash256)> = HashMap::new();
        for m in &meta_entries {
            meta.insert(m.root, (m.slot, m.parent_root));
        }

        // Initial keep-set: blocks in the rolling window.
        let mut keep: HashSet<Hash256> = HashSet::new();
        for (root, (slot, _parent)) in &meta {
            if *slot >= min_slot_to_keep {
                keep.insert(*root);
            }
        }

        // Always keep explicit roots + their ancestors.
        let mut stack: Vec<Hash256> = always_keep_roots.iter().copied().collect();
        while let Some(root) = stack.pop() {
            if keep.insert(root) {
                if let Some((_slot, parent)) = meta.get(&root).copied() {
                    if parent != Hash256::ZERO {
                        stack.push(parent);
                    }
                }
            }
        }

        // Also keep ancestors of all kept blocks so we don't strand parents on restart.
        let mut ancestor_stack: Vec<Hash256> = keep.iter().copied().collect();
        while let Some(root) = ancestor_stack.pop() {
            if let Some((_slot, parent)) = meta.get(&root).copied() {
                if parent != Hash256::ZERO && keep.insert(parent) {
                    ancestor_stack.push(parent);
                }
            }
        }

        // Delete blocks not in keep-set and rebuild meta index.
        let mut deleted = 0usize;
        let mut kept_meta: Vec<BlockMetaEntry> = Vec::new();
        for entry in meta_entries {
            if keep.contains(&entry.root) {
                kept_meta.push(entry);
                continue;
            }

            let key = StorageKey::Block.key_with_hash(&entry.root);
            self.db
                .key_delete(DBColumn::BeaconBlock, &key)
                .map_err(|e| format!("Failed to delete block: {:?}", e))?;
            deleted += 1;
        }

        self.save_block_meta_index(&kept_meta)?;

        // Compact the beacon block column to reclaim space.
        self.db
            .compact_column(DBColumn::BeaconBlock)
            .map_err(|e| format!("Failed to compact BeaconBlock column: {:?}", e))?;

        Ok(deleted)
    }

    /// Prune old per-root states from the DB, keeping a rolling window by slot.
    ///
    /// Returns number of deleted states.
    pub fn prune_states_older_than(
        &self,
        min_slot_to_keep: u64,
        always_keep_roots: &HashSet<Hash256>,
    ) -> Result<usize, String> {
        let entries = self.load_state_meta_index()?;
        if entries.is_empty() {
            return Ok(0);
        }

        let mut keep: HashSet<Hash256> = HashSet::new();
        for e in &entries {
            if e.slot >= min_slot_to_keep {
                keep.insert(e.block_root);
            }
        }
        for r in always_keep_roots {
            keep.insert(*r);
        }

        let mut deleted = 0usize;
        let mut kept: Vec<StateMetaEntry> = Vec::new();
        for e in entries {
            if keep.contains(&e.block_root) {
                kept.push(e);
                continue;
            }
            let key = StorageKey::StateByRoot.key_with_hash(&e.block_root);
            self.db
                .key_delete(DBColumn::BeaconState, &key)
                .map_err(|er| format!("Failed to delete state: {:?}", er))?;
            deleted += 1;
        }

        self.save_state_meta_index(&kept)?;
        self.db
            .compact_column(DBColumn::BeaconState)
            .map_err(|e| format!("Failed to compact BeaconState column: {:?}", e))?;
        Ok(deleted)
    }

    // ======== Block meta index helpers ========

    fn load_block_meta_index(&self) -> Result<Vec<BlockMetaEntry>, String> {
        let bytes = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &StorageKey::BlockMetaIndex.key())
            .map_err(|e| format!("Failed to load block meta index: {:?}", e))?;
        let Some(data) = bytes else { return Ok(Vec::new()) };
        if data.len() % 72 != 0 {
            return Err("Invalid block meta index length".to_string());
        }
        let mut out: Vec<BlockMetaEntry> = Vec::with_capacity(data.len() / 72);
        for chunk in data.chunks_exact(72) {
            let slot = u64::from_le_bytes(chunk[0..8].try_into().map_err(|_| "Invalid slot bytes".to_string())?);
            let root = Hash256::from_slice(&chunk[8..40]);
            let parent_root = Hash256::from_slice(&chunk[40..72]);
            out.push(BlockMetaEntry { slot, root, parent_root });
        }
        Ok(out)
    }

    fn save_block_meta_index(&self, entries: &[BlockMetaEntry]) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(entries.len() * 72);
        for e in entries {
            bytes.extend_from_slice(&e.slot.to_le_bytes());
            bytes.extend_from_slice(&e.root.0);
            bytes.extend_from_slice(&e.parent_root.0);
        }
        self.db
            .put_bytes(DBColumn::BeaconMeta, &StorageKey::BlockMetaIndex.key(), &bytes)
            .map_err(|e| format!("Failed to save block meta index: {:?}", e))
    }

    fn append_block_meta(
        &self,
        block_root: Hash256,
        slot: u64,
        parent_root: Hash256,
    ) -> Result<(), String> {
        let key = StorageKey::BlockMetaIndex.key();
        let mut data = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &key)
            .map_err(|e| format!("Failed to load block meta index: {:?}", e))?
            .unwrap_or_default();

        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(&block_root.0);
        data.extend_from_slice(&parent_root.0);

        let max_len = BLOCK_META_INDEX_MAX_ENTRIES * 72;
        if data.len() > max_len {
            let start = data.len() - max_len;
            data.drain(0..start);
        }

        self.db
            .put_bytes(DBColumn::BeaconMeta, &key, &data)
            .map_err(|e| format!("Failed to append block meta index: {:?}", e))
    }

    fn migrate_block_meta_index_from_roots(&self, roots: &[Hash256]) -> Result<(), String> {
        if !self.load_block_meta_index()?.is_empty() {
            return Ok(());
        }
        let mut entries: Vec<BlockMetaEntry> = Vec::new();
        for r in roots {
            if let Some(b) = self.fetch_block(*r)? {
                entries.push(BlockMetaEntry {
                    slot: b.slot.0,
                    root: *r,
                    parent_root: b.parent_root,
                });
            }
        }
        self.save_block_meta_index(&entries)
    }

    // ======== State meta index helpers ========

    fn load_state_meta_index(&self) -> Result<Vec<StateMetaEntry>, String> {
        let bytes = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &StorageKey::StateMetaIndex.key())
            .map_err(|e| format!("Failed to load state meta index: {:?}", e))?;
        let Some(data) = bytes else { return Ok(Vec::new()) };
        if data.len() % 40 != 0 {
            return Err("Invalid state meta index length".to_string());
        }
        let mut out: Vec<StateMetaEntry> = Vec::with_capacity(data.len() / 40);
        for chunk in data.chunks_exact(40) {
            let slot = u64::from_le_bytes(chunk[0..8].try_into().map_err(|_| "Invalid slot bytes".to_string())?);
            let block_root = Hash256::from_slice(&chunk[8..40]);
            out.push(StateMetaEntry { slot, block_root });
        }
        Ok(out)
    }

    fn save_state_meta_index(&self, entries: &[StateMetaEntry]) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(entries.len() * 40);
        for e in entries {
            bytes.extend_from_slice(&e.slot.to_le_bytes());
            bytes.extend_from_slice(&e.block_root.0);
        }
        self.db
            .put_bytes(DBColumn::BeaconMeta, &StorageKey::StateMetaIndex.key(), &bytes)
            .map_err(|e| format!("Failed to save state meta index: {:?}", e))
    }

    fn append_state_meta(&self, block_root: Hash256, slot: u64) -> Result<(), String> {
        let key = StorageKey::StateMetaIndex.key();
        let mut data = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &key)
            .map_err(|e| format!("Failed to load state meta index: {:?}", e))?
            .unwrap_or_default();

        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(&block_root.0);

        let max_len = STATE_META_INDEX_MAX_ENTRIES * 40;
        if data.len() > max_len {
            let start = data.len() - max_len;
            data.drain(0..start);
        }

        self.db
            .put_bytes(DBColumn::BeaconMeta, &key, &data)
            .map_err(|e| format!("Failed to append state meta index: {:?}", e))
    }

    // ============ Fork Choice State ============

    /// Saves the current head root to the database
    pub fn save_head_root(&self, head_root: Hash256) -> Result<(), String> {
        self.save_hash256_item(StorageKey::HeadRoot, head_root)
    }

    /// Fetches the current head root from the database
    pub fn fetch_head_root(&self) -> Result<Option<Hash256>, String> {
        self.fetch_hash256_item(StorageKey::HeadRoot)
    }

    /// Saves the current safe target root to the database
    pub fn save_safe_target(&self, safe_target: Hash256) -> Result<(), String> {
        self.save_hash256_item(StorageKey::SafeTarget, safe_target)
    }

    /// Fetches the current safe target root from the database
    pub fn fetch_safe_target(&self) -> Result<Option<Hash256>, String> {
        self.fetch_hash256_item(StorageKey::SafeTarget)
    }

    // ============ Attestation Management ============

    /// Saves a known (confirmed) attestation to the database
    pub fn save_known_attestation(
        &self,
        validator_id: u64,
        attestation: &SignedAttestation,
    ) -> Result<(), String> {
        self.save_indexed_item(StorageKey::Attestation, validator_id, attestation)?;
        self.add_to_index(StorageKey::ValidatorIndices, &validator_id.to_le_bytes())?;
        Ok(())
    }

    /// Saves a new (pending) attestation to the database
    pub fn save_new_attestation(
        &self,
        validator_id: u64,
        attestation: &SignedAttestation,
    ) -> Result<(), String> {
        self.save_indexed_item(StorageKey::NewAttestation, validator_id, attestation)?;
        self.add_to_index(StorageKey::NewValidatorIndices, &validator_id.to_le_bytes())?;
        Ok(())
    }

    /// Loads all known attestations from the database
    pub fn load_known_attestations(&self) -> Result<HashMap<u64, SignedAttestation>, String> {
        self.load_indexed_items(StorageKey::Attestation, StorageKey::ValidatorIndices)
    }

    /// Loads all new (pending) attestations from the database
    pub fn load_new_attestations(&self) -> Result<HashMap<u64, SignedAttestation>, String> {
        self.load_indexed_items(StorageKey::NewAttestation, StorageKey::NewValidatorIndices)
    }

    /// Loads all attestations (alias for known attestations)
    pub fn load_all_attestations(&self) -> Result<HashMap<u64, SignedAttestation>, String> {
        self.load_known_attestations()
    }

    /// Deletes a new attestation for the given validator index
    pub fn delete_new_attestation(&self, validator_id: u64) -> Result<(), String> {
        let key = StorageKey::NewAttestation.key_with_id(validator_id);
        self.db
            .key_delete(DBColumn::BeaconMeta, &key)
            .map_err(|e| format!("Failed to delete new attestation: {:?}", e))?;

        self.remove_from_index(StorageKey::NewValidatorIndices, &validator_id.to_le_bytes())?;
        Ok(())
    }

    /// Migrates all new attestations to known attestations
    pub fn accept_new_attestations(&self) -> Result<(), String> {
        let new_attestations = self.load_new_attestations()?;

        for (validator_id, attestation) in new_attestations {
            self.save_known_attestation(validator_id, &attestation)?;
            self.delete_new_attestation(validator_id)?;
        }

        Ok(())
    }

    // ============ Private Helpers ============

    /// Fetches a single SSZ-encoded item from the database
    fn fetch_single_item<T: Decode>(
        &self,
        key: StorageKey,
        column: DBColumn,
    ) -> Result<Option<T>, String> {
        let bytes = self
            .db
            .get_bytes(column, &key.key())
            .map_err(|e| format!("Failed to fetch item: {:?}", e))?;

        match bytes {
            Some(data) => {
                let item = T::from_ssz_bytes(&data)
                    .map_err(|e| format!("Failed to decode item: {:?}", e))?;
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }

    /// Saves a single SSZ-encoded item to the database
    fn save_single_item<T: Encode>(
        &self,
        key: StorageKey,
        column: DBColumn,
        item: &T,
    ) -> Result<(), String> {
        let bytes = item.as_ssz_bytes();
        self.db
            .put_bytes(column, &key.key(), &bytes)
            .map_err(|e| format!("Failed to save item: {:?}", e))
    }

    /// Fetches an item using a specific key
    fn fetch_with_key<T: Decode>(&self, column: DBColumn, key: &[u8]) -> Result<Option<T>, String> {
        let bytes = self
            .db
            .get_bytes(column, key)
            .map_err(|e| format!("Failed to fetch item: {:?}", e))?;

        match bytes {
            Some(data) => {
                let item = T::from_ssz_bytes(&data)
                    .map_err(|e| format!("Failed to decode item: {:?}", e))?;
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }

    /// Saves a Hash256 item to the database
    fn save_hash256_item(&self, key: StorageKey, hash: Hash256) -> Result<(), String> {
        self.db
            .put_bytes(DBColumn::BeaconMeta, &key.key(), &hash.0)
            .map_err(|e| format!("Failed to save hash: {:?}", e))
    }

    /// Fetches a Hash256 item from the database
    fn fetch_hash256_item(&self, key: StorageKey) -> Result<Option<Hash256>, String> {
        let bytes = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &key.key())
            .map_err(|e| format!("Failed to fetch hash: {:?}", e))?;

        match bytes {
            Some(data) if data.len() == 32 => Ok(Some(Hash256::from_slice(&data))),
            _ => Ok(None),
        }
    }

    /// Saves an indexed item (with u64 key suffix)
    fn save_indexed_item<T: Encode>(
        &self,
        key_prefix: StorageKey,
        id: u64,
        item: &T,
    ) -> Result<(), String> {
        let key = key_prefix.key_with_id(id);
        let bytes = item.as_ssz_bytes();
        self.db
            .put_bytes(DBColumn::BeaconMeta, &key, &bytes)
            .map_err(|e| format!("Failed to save indexed item: {:?}", e))
    }

    /// Loads all indexed items for a given prefix
    fn load_indexed_items<T: Decode>(
        &self,
        item_key: StorageKey,
        index_key: StorageKey,
    ) -> Result<HashMap<u64, T>, String> {
        let indices = self.load_u64_index(index_key)?;
        let mut items = HashMap::new();

        for id in indices {
            let key = item_key.key_with_id(id);
            if let Some(item) = self.fetch_with_key(DBColumn::BeaconMeta, &key)? {
                items.insert(id, item);
            }
        }

        Ok(items)
    }

    /// Loads a u64 index from the database
    fn load_u64_index(&self, key: StorageKey) -> Result<Vec<u64>, String> {
        let bytes = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &key.key())
            .map_err(|e| format!("Failed to load index: {:?}", e))?;

        match bytes {
            Some(data) => {
                let count = data.len() / 8;
                let mut indices = Vec::with_capacity(count);
                for i in 0..count {
                    let start = i * 8;
                    let end = start + 8;
                    let bytes_array: [u8; 8] = data[start..end]
                        .try_into()
                        .map_err(|_| "Invalid index bytes".to_string())?;
                    indices.push(u64::from_le_bytes(bytes_array));
                }
                Ok(indices)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Saves a u64 index to the database
    fn save_u64_index(&self, key: StorageKey, indices: &[u64]) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(indices.len() * 8);
        for &index in indices {
            bytes.extend_from_slice(&index.to_le_bytes());
        }

        self.db
            .put_bytes(DBColumn::BeaconMeta, &key.key(), &bytes)
            .map_err(|e| format!("Failed to save index: {:?}", e))
    }

    /// Loads a Hash256 index from the database
    fn load_hash256_index(&self, key: StorageKey) -> Result<Vec<Hash256>, String> {
        let bytes = self
            .db
            .get_bytes(DBColumn::BeaconMeta, &key.key())
            .map_err(|e| format!("Failed to load index: {:?}", e))?;

        match bytes {
            Some(data) => {
                let count = data.len() / 32;
                let mut hashes = Vec::with_capacity(count);
                for i in 0..count {
                    let start = i * 32;
                    let end = start + 32;
                    hashes.push(Hash256::from_slice(&data[start..end]));
                }
                Ok(hashes)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Adds an item to an index if not already present
    fn add_to_index(&self, index_key: StorageKey, item_bytes: &[u8]) -> Result<(), String> {
        let item_len = match index_key {
            StorageKey::ValidatorIndices | StorageKey::NewValidatorIndices => 8,
            StorageKey::BlockRootsIndex => 32,
            _ => return Err("Invalid index key for add_to_index".to_string()),
        };

        if item_len == 8 {
            let id = u64::from_le_bytes(
                item_bytes
                    .try_into()
                    .map_err(|_| "Invalid id bytes".to_string())?,
            );
            let mut indices = match index_key {
                StorageKey::ValidatorIndices => self.load_u64_index(index_key)?,
                StorageKey::NewValidatorIndices => self.load_u64_index(index_key)?,
                _ => unreachable!(),
            };
            if !indices.contains(&id) {
                indices.push(id);
                self.save_u64_index(index_key, &indices)?;
            }
        } else {
            let hash = Hash256::from_slice(item_bytes);
            let mut hashes = self.load_hash256_index(index_key)?;
            if !hashes.contains(&hash) {
                hashes.push(hash);
                // Save Hash256 index
                let mut bytes = Vec::with_capacity(hashes.len() * 32);
                for h in &hashes {
                    bytes.extend_from_slice(&h.0);
                }
                self.db
                    .put_bytes(DBColumn::BeaconMeta, &index_key.key(), &bytes)
                    .map_err(|e| format!("Failed to save index: {:?}", e))?;
            }
        }

        Ok(())
    }

    /// Removes an item from an index
    fn remove_from_index(&self, index_key: StorageKey, item_bytes: &[u8]) -> Result<(), String> {
        let id = u64::from_le_bytes(
            item_bytes
                .try_into()
                .map_err(|_| "Invalid id bytes".to_string())?,
        );
        let mut indices = self.load_u64_index(index_key)?;
        indices.retain(|&i| i != id);
        self.save_u64_index(index_key, &indices)?;
        Ok(())
    }
}
