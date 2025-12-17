use crate::attestation::{Attestation, Checkpoint, Slot};

use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use tracing::debug;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::lean_block::{
    LeanBlock, LeanBlockBody, LeanBlockHeader, SignedLeanBlockWithAttestation,
};
use crate::validator::Validator;
use crate::validator::ValidatorIndex;

use ssz_types::typenum::U1073741824;
use ssz_types::{BitList, VariableList};
use types::{EthSpec, Hash256};

#[derive(TreeHash, Encode, Decode, Debug)]
pub struct LeanState<E: EthSpec> {
    pub config: Config,
    pub slot: Slot,
    pub latest_block_header: LeanBlockHeader,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub historical_block_hashes: VariableList<Hash256, E::HistoricalRootsLimit>,
    pub justified_slots: BitList<E::HistoricalRootsLimit>,
    pub validators: VariableList<Validator, E::ValidatorRegistryLimit>,
    pub justifications_roots: VariableList<Hash256, E::HistoricalRootsLimit>,
    pub justifications_validators: BitList<U1073741824>,
}

impl<E: EthSpec> LeanState<E> {
    pub fn new(
        genesis_time: u64,
        justified_slots: BitList<E::HistoricalRootsLimit>,
        validators: VariableList<Validator, E::ValidatorRegistryLimit>,
    ) -> Self {
        let genesis_config = Config { genesis_time };
        let genesis_header = LeanBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            body_root: LeanBlockBody::<E> {
                attestations: VariableList::empty(),
            }
            .tree_hash_root(),
        };

        let genesis_checkpoint = Checkpoint {
            root: Hash256::ZERO,
            slot: Slot(0),
        };

        Self {
            config: genesis_config,
            slot: Slot(0),
            latest_block_header: genesis_header.clone(),
            latest_justified: genesis_checkpoint.clone(),
            latest_finalized: genesis_checkpoint,
            historical_block_hashes: VariableList::empty(),
            justified_slots: justified_slots.clone(),
            validators: validators.clone(),
            justifications_roots: VariableList::empty(),
            justifications_validators: BitList::with_capacity(0)
                .expect("Failed to create justifications_validators BitList"),
        }
    }

    pub fn generate_genesis(
        genesis_time: u64,
        validators: VariableList<Validator, E::ValidatorRegistryLimit>,
    ) -> Self {
        let genesis_config = Config { genesis_time };
        let genesis_header = LeanBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            body_root: LeanBlockBody::<E> {
                attestations: VariableList::empty(),
            }
            .tree_hash_root(),
        };

        // Initialize justified_slots as empty to align with the spec.
        // Justification occurs via attestations during block processing.
        let justified_slots =
            BitList::with_capacity(0).expect("Failed to create justified_slots BitList");

        // Initialize checkpoints to ZERO_HASH matching the spec.
        // This avoids circular dependencies in genesis state calculation.
        // Field order must match struct definition for correct SSZ encoding.
        let genesis_checkpoint = Checkpoint {
            root: Hash256::ZERO,
            slot: Slot(0),
        };

        Self {
            config: genesis_config,
            slot: Slot(0),
            latest_block_header: genesis_header.clone(),
            latest_justified: genesis_checkpoint.clone(),
            latest_finalized: genesis_checkpoint,
            historical_block_hashes: VariableList::empty(),
            justified_slots,
            validators,
            justifications_roots: VariableList::empty(),
            justifications_validators: BitList::with_capacity(0)
                .expect("Failed to create justifications_validators BitList"),
        }
    }

    pub fn is_proposer(&self, validator_index: ValidatorIndex) -> bool {
        self.slot.0 % self.validators.len() as u64 == validator_index.0
    }
    pub fn get_justifications(
        &self,
    ) -> Result<HashMap<Hash256, BitList<E::HistoricalRootsLimit>>, String> {
        if self.justifications_roots.is_empty() {
            return Ok(HashMap::new());
        }

        let validator_count = self.validators.len();

        self.justifications_roots
            .iter()
            .enumerate()
            .map(|(i, root)| {
                let start = i * validator_count;
                let end = (i + 1) * validator_count;

                let mut justifications = BitList::<E::HistoricalRootsLimit>::with_capacity(
                    validator_count,
                )
                .map_err(|e| {
                    format!(
                        "Failed to create BitList with capacity {}: {:?}",
                        validator_count, e
                    )
                })?;
                for (bit_idx, global_idx) in (start..end).enumerate() {
                    let bit_value =
                        self.justifications_validators
                            .get(global_idx)
                            .map_err(|e| {
                                format!("Failed to get bit at index {}: {:?}", global_idx, e)
                            })?;
                    justifications
                        .set(bit_idx, bit_value)
                        .map_err(|e| format!("Failed to set bit at index {}: {:?}", bit_idx, e))?;
                }

                Ok((*root, justifications))
            })
            .collect()
    }
    pub fn with_justification(
        &mut self,
        root: Hash256,
        validator_justifications: &BitList<E::HistoricalRootsLimit>,
    ) -> Result<(), String> {
        let validator_count = self.validators.len();

        if validator_justifications.len() < validator_count {
            return Err(format!(
                "Justifications vector length {} is less than validator count {}",
                validator_justifications.len(),
                validator_count
            ));
        }

        if self.justifications_roots.contains(&root) {
            return Err(format!(
                "Root {:?} already exists in justifications_roots",
                root
            ));
        }

        self.justifications_roots
            .push(root)
            .map_err(|e| format!("Failed to append root to justifications_roots: {:?}", e))?;

        for i in 0..validator_count {
            let bit_value = validator_justifications.get(i).map_err(|e| {
                format!(
                    "Failed to get bit at index {} from validator_justifications: {:?}",
                    i, e
                )
            })?;

            let current_len = self.justifications_validators.len();
            self.justifications_validators
                .set(current_len, bit_value)
                .map_err(|e| {
                    format!(
                        "Failed to append bit to justifications_validators at index {}: {:?}",
                        current_len, e
                    )
                })?;
        }

        Ok(())
    }
    pub fn process_slot(&mut self) -> Result<(), String> {
        // If state_root is unpopulated (e.g., genesis state), populate it now.
        // This ensures the header incorrectly reflects the state root for the transition to Slot 1,
        // while preserving pre-populated headers from `handle_block` for subsequent blocks.
        if self.latest_block_header.state_root == Hash256::ZERO {
            use tree_hash::TreeHash;
            let previous_state_root = self.tree_hash_root();
            self.latest_block_header.state_root = previous_state_root;
        }

        Ok(())
    }

    pub fn process_slots(&mut self, target_slot: Slot) -> Result<(), String> {
        if self.slot >= target_slot {
            return Err(format!(
                "Target slot must be in the future. Current slot: {}, target slot: {}",
                self.slot.0, target_slot.0
            ));
        }

        while self.slot < target_slot {
            self.process_slot()?;

            self.slot = Slot(self.slot.0 + 1);
        }

        Ok(())
    }
    pub fn process_block_header(&mut self, block: &LeanBlock<E>) -> Result<(), String> {
        let parent_header = &self.latest_block_header;
        let parent_root = parent_header.tree_hash_root();

        debug!(
            block_slot = block.slot.0,
            parent_header_slot = parent_header.slot.0,
            parent_header_state_root = ?parent_header.state_root,
            computed_parent_root = ?parent_root,
            block_parent_root = ?block.parent_root,
            "Processing block header - computing parent root"
        );

        if block.slot != self.slot {
            return Err(format!(
                "Block slot mismatch. Expected: {}, got: {}",
                self.slot.0, block.slot.0
            ));
        }

        if block.slot <= parent_header.slot {
            return Err(format!(
                "Block is not newer than latest header. Block slot: {}, latest header slot: {}",
                block.slot.0, parent_header.slot.0
            ));
        }

        if !self.is_proposer(ValidatorIndex(block.proposer_index)) {
            return Err(format!(
                "Incorrect block proposer. Expected proposer for slot {}, got validator {}",
                self.slot.0, block.proposer_index
            ));
        }

        if block.parent_root != parent_root {
            return Err(format!(
                "Block parent root mismatch. Expected: {:?}, got: {:?}",
                parent_root, block.parent_root
            ));
        }

        let is_genesis_parent = parent_header.slot == Slot(0);
        if is_genesis_parent {
            self.latest_justified.root = parent_root;
            self.latest_finalized.root = parent_root;
            debug!(
                genesis_root = ?parent_root,
                "Genesis block finalized and justified"
            );
        }

        let num_empty_slots = block.slot.0 - parent_header.slot.0 - 1;

        // Add parent root to historical_block_hashes (spec: leanSpec/state.py line 260)
        self.historical_block_hashes
            .push(parent_root)
            .map_err(|e| format!("Failed to append parent root to historical hashes: {:?}", e))?;

        // Add ZERO_HASH for each empty slot (spec: leanSpec/state.py line 260)
        for _ in 0..num_empty_slots {
            self.historical_block_hashes
                .push(Hash256::ZERO)
                .map_err(|e| format!("Failed to append ZERO_HASH for empty slot: {:?}", e))?;
        }

        // Force materialization of the list by serializing and deserializing it
        // This ensures pending updates are flushed before tree_hash is called
        let encoded_hashes = ssz::Encode::as_ssz_bytes(&self.historical_block_hashes);
        self.historical_block_hashes = ssz::Decode::from_ssz_bytes(&encoded_hashes)
            .map_err(|e| format!("Failed to rematerialize historical_block_hashes: {:?}", e))?;

        debug!(
            block_slot = block.slot.0,
            parent_header_slot = parent_header.slot.0,
            added_parent_root = ?parent_root,
            num_empty_slots = num_empty_slots,
            historical_hashes_len = self.historical_block_hashes.len(),
            "Updated historical_block_hashes"
        );

        // Following the spec pattern: build new justified_slots by growing the BitList
        //
        // The spec pattern: justified_slots + [Boolean(is_genesis_parent)] + ([Boolean(False)] * num_empty_slots)
        // This means justified_slots grows in parallel with historical_block_hashes.

        let current_len = self.justified_slots.len();
        let num_empty_slots_usize = num_empty_slots as usize;

        // Calculate total size of new BitList
        let new_len = current_len + 1 + num_empty_slots_usize;

        // Create a fresh BitList with the exact final size needed
        // We must create with the final size because .set() won't extend beyond capacity
        let mut new_justified_slots = BitList::with_capacity(new_len).map_err(|e| {
            format!(
                "Failed to create justified_slots BitList with capacity {}: {:?}",
                new_len, e
            )
        })?;

        // Only copy existing bits if there are any (avoid unnecessary work on first block)
        if current_len > 0 {
            for i in 0..current_len {
                let bit_value = self.justified_slots.get(i).map_err(|e| {
                    format!("Failed to read justified_slots bit at index {}: {:?}", i, e)
                })?;
                new_justified_slots
                    .set(i, bit_value)
                    .map_err(|e| format!("Failed to copy bit at index {}: {:?}", i, e))?;
            }

            debug!(
                "Copied {} existing bits to new justified_slots BitList",
                current_len
            );
        }

        // Set the parent slot bit (justified only if it's the genesis block)
        new_justified_slots
            .set(current_len, is_genesis_parent)
            .map_err(|e| format!("Failed to set parent bit in justified_slots: {:?}", e))?;

        debug!(
            "Set parent justified bit at index {}: is_genesis_parent={}",
            current_len, is_genesis_parent
        );

        // Set false for each empty slot
        for i in 0..num_empty_slots_usize {
            new_justified_slots
                .set(current_len + 1 + i, false)
                .map_err(|e| {
                    format!(
                        "Failed to set empty slot bit at index {}: {:?}",
                        current_len + 1 + i,
                        e
                    )
                })?;
        }

        debug!(
            "Set {} empty slot bits (all false) in justified_slots",
            num_empty_slots_usize
        );

        self.justified_slots = new_justified_slots;

        debug!(
            "Rebuilt justified_slots BitList: old_len={}, new_len={}, hist_block_hashes_len={}",
            current_len,
            self.justified_slots.len(),
            self.historical_block_hashes.len()
        );

        self.latest_block_header = LeanBlockHeader {
            slot: block.slot,
            proposer_index: ValidatorIndex(block.proposer_index),
            parent_root: block.parent_root,
            body_root: block.body.tree_hash_root(),
            state_root: Hash256::ZERO,
        };

        Ok(())
    }
    pub fn process_block(&mut self, block: &LeanBlock<E>) -> Result<(), String> {
        self.process_block_header(block)?;

        self.process_attestations(&block.body.attestations)?;

        Ok(())
    }
    pub fn process_attestations(
        &mut self,
        attestations: &VariableList<Attestation, E::ValidatorRegistryLimit>,
    ) -> Result<(), String> {
        for attestation in attestations.iter() {
            let attestation_data = &attestation.attestation_data;
            let source = &attestation_data.source;
            let target = &attestation_data.target;

            if source.slot >= target.slot {
                continue;
            }

            let source_slot_int = source.slot.0 as usize;
            let target_slot_int = target.slot.0 as usize;

            let source_is_justified = if source_slot_int < self.justified_slots.len() {
                self.justified_slots.get(source_slot_int).map_err(|e| {
                    format!(
                        "Failed to get justified slot at index {}: {:?}",
                        source_slot_int, e
                    )
                })?
            } else {
                continue;
            };

            let target_is_justified = if target_slot_int < self.justified_slots.len() {
                self.justified_slots.get(target_slot_int).map_err(|e| {
                    format!(
                        "Failed to get justified slot at index {}: {:?}",
                        target_slot_int, e
                    )
                })?
            } else {
                false
            };

            if source_is_justified && target_is_justified {
                if source.slot.0 + 1 == target.slot.0 && self.latest_justified.slot < target.slot {
                    self.latest_finalized = (*source).clone();
                    self.latest_justified = (*target).clone();
                    debug!(
                        finalized_slot = source.slot.0,
                        finalized_root = ?source.root,
                        justified_slot = target.slot.0,
                        justified_root = ?target.root,
                        "Chain finalized: consecutive justified checkpoints found"
                    );
                }
            } else if source_is_justified {
                while self.justified_slots.len() <= target_slot_int {
                    self.justified_slots
                        .set(self.justified_slots.len(), false)
                        .map_err(|e| format!("Failed to extend justified_slots: {:?}", e))?;
                }

                self.justified_slots
                    .set(target_slot_int, true)
                    .map_err(|e| {
                        format!(
                            "Failed to set justified slot at index {}: {:?}",
                            target_slot_int, e
                        )
                    })?;

                if target.slot > self.latest_justified.slot {
                    // When we justify a new checkpoint, finalize the previous justified checkpoint
                    // if it's at least 2 slots behind the new one (matches Ethereum finalization)
                    if target.slot.0 >= self.latest_justified.slot.0 + 2 {
                        self.latest_finalized = self.latest_justified.clone();
                        debug!(
                            finalized_slot = self.latest_justified.slot.0,
                            finalized_root = ?self.latest_justified.root,
                            "Chain finalized: previous justified checkpoint finalized after new justification"
                        );
                    }

                    self.latest_justified = (*target).clone();
                }
            }
        }

        Ok(())
    }
    pub fn state_transition(
        &mut self,
        signed_block: &SignedLeanBlockWithAttestation<E>,
        validate_signatures: bool,
    ) -> Result<(), String> {
        if validate_signatures {
            signed_block.verify_signatures(self)?;
        }

        let block = &signed_block.message.block;

        if self.slot < block.slot {
            self.process_slots(block.slot)?;
        }

        self.process_block(block)?;

        let computed_state_root = self.tree_hash_root();
        if block.state_root != computed_state_root {
            return Err(format!(
                "Invalid block state root. Expected: {:?}, got: {:?}",
                computed_state_root, block.state_root
            ));
        }

        Ok(())
    }
}

/// Configuration for the lean consensus protocol.
///
/// This struct contains chain-specific parameters that are part of the consensus state.
/// To match the spec's BeamStateConfig, this only contains genesis_time.
/// Other parameters are defined as constants (SECONDS_PER_SLOT, etc.)
#[derive(TreeHash, Encode, Decode, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Genesis time in seconds since Unix epoch.
    pub genesis_time: u64,
}

/// Configuration for genesis generation (YAML/JSON only, not part of chain state)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisConfig {
    /// Base chain configuration
    #[serde(flatten)]
    pub config: Config,
    /// Log2 of the number of active epochs for XMSS keys (e.g., 24 means 2^24 active epochs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_epoch: Option<u64>,
    /// Shuffle algorithm for validator assignment (e.g., "roundrobin").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shuffle: Option<String>,
}

impl From<Config> for GenesisConfig {
    fn from(config: Config) -> Self {
        Self {
            config,
            active_epoch: None,
            shuffle: Some("roundrobin".to_string()),
        }
    }
}

impl From<GenesisConfig> for Config {
    fn from(genesis_config: GenesisConfig) -> Self {
        genesis_config.config
    }
}

impl Config {
    /// Returns the devnet chain configuration.
    ///
    /// This is the default configuration for the lean consensus devnet.
    pub fn devnet() -> Self {
        Self {
            genesis_time: 0, // Default genesis time, should be set when creating genesis state
        }
    }

    /// Calculates genesis time as current time + offset seconds.
    ///
    /// This allows nodes to start before genesis and sync up.
    pub fn with_genesis_time_offset(offset_seconds: u64) -> Self {
        let mut config = Self::devnet();
        config.genesis_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + offset_seconds;
        config
    }

    /// Returns the number of seconds per forkchoice processing interval.
    ///
    /// This is derived from `SECONDS_PER_SLOT` and `intervals_per_slot`.
    pub fn seconds_per_interval(&self) -> u64 {
        SECONDS_PER_SLOT / INTERVALS_PER_SLOT
    }

    /// Returns the number of intervals per slot.
    ///
    /// This is a constant value defined by the lean consensus specification.
    pub fn intervals_per_slot(&self) -> u64 {
        INTERVALS_PER_SLOT
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

// --- Time Parameters ---

/// Number of intervals per slot for forkchoice processing.
pub const INTERVALS_PER_SLOT: u64 = 4;

/// The fixed duration of a single slot in seconds.
pub const SECONDS_PER_SLOT: u64 = 4;

/// Seconds per forkchoice processing interval.
pub const SECONDS_PER_INTERVAL: u64 = SECONDS_PER_SLOT / INTERVALS_PER_SLOT;

/// The number of slots to lookback for justification.
pub const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

// --- State List Length Presets ---

/// The maximum number of historical block roots to store in the state.
///
/// With a 4-second slot, this corresponds to a history of approximately 12.1 days.
pub const HISTORICAL_ROOTS_LIMIT: u64 = 1 << 18; // 2^18

/// The maximum number of validators that can be in the registry.
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 1 << 12; // 2^12
