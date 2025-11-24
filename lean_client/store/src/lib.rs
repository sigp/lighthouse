use lean_consensus::attestation::SignedAttestation;
use lean_consensus::lean_block::LeanBlock;
use lean_consensus::lean_state::LeanState;
use ssz::{Decode, Encode};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{DBColumn, KeyValueStore};
use types::{EthSpec, Hash256};

/// Storage key definitions for the lean client
#[derive(Debug, Clone, Copy)]
enum StorageKey {
    /// Single-item keys
    State,
    HeadRoot,
    SafeTarget,
    /// Prefix-based keys with u64 suffix
    Block,
    Attestation,
    NewAttestation,
    /// Index keys
    BlockRootsIndex,
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
            StorageKey::Attestation => b"attestation_".to_vec(),
            StorageKey::NewAttestation => b"new_attestation_".to_vec(),
            StorageKey::BlockRootsIndex => b"block_roots_index".to_vec(),
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

    // ============ Block Management ============

    /// Saves a block to the database by its root and updates the block roots index
    pub fn save_block(&self, block_root: Hash256, block: &LeanBlock<E>) -> Result<(), String> {
        let key = StorageKey::Block.key_with_hash(&block_root);
        let bytes = block.as_ssz_bytes();
        self.db
            .put_bytes(DBColumn::BeaconBlock, &key, &bytes)
            .map_err(|e| format!("Failed to save block: {:?}", e))?;

        // Update block roots index
        self.add_to_index(StorageKey::BlockRootsIndex, &block_root.0)?;
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

    /// Loads all blocks from the database using the block roots index
    pub fn load_all_blocks(&self) -> Result<HashMap<Hash256, LeanBlock<E>>, String> {
        let block_roots = self.load_hash256_index(StorageKey::BlockRootsIndex)?;
        let mut blocks = HashMap::new();

        for block_root in block_roots {
            if let Some(block) = self.fetch_block(block_root)? {
                blocks.insert(block_root, block);
            }
        }

        Ok(blocks)
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
