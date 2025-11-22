use crate::attestation::{Attestation, Checkpoint, Slot};

use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use ssz_derive::{Encode, Decode};

use crate::lean_block::{LeanBlock, LeanBlockBody};
use crate::validator::ValidatorIndex;
use crate::validator::Validator;

use types::VariableList;
use crate::lean_block::LeanBlockHeader;
use milhouse::List;
use types::{BitVector, EthSpec, Hash256};


#[derive(TreeHash, Encode, Decode)]
pub struct LeanState<E: EthSpec> {
    pub config: Config,
    pub slot: Slot,

    pub latest_block_header: LeanBlockHeader,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    /// Historical block hashes stored in the state.
    /// Uses `E::HistoricalRootsLimit` from EthSpec for type-level size limits.
    pub historical_block_hashes: List<Hash256, E::HistoricalRootsLimit>,
    /// Justification tracking fields.
    /// NOTE: The justification structure may need refinement based on final spec requirements.
    /// Current implementation uses:
    /// - `justified_slots`: BitVector tracking which slots are justified
    /// - `justifications_roots`: List of checkpoint roots that have been justified
    /// - `justifications_validators`: BitVector tracking validator participation in justifications
    pub justified_slots: BitVector<E::HistoricalRootsLimit>,
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    pub justifications_roots: List<Hash256, E::HistoricalRootsLimit>,
    pub justifications_validators: BitVector<E::JustificationValidators>,
}

impl<E: EthSpec> LeanState<E> {
    /// Initializes a genesis state with default configuration and empty validators list
    pub fn genesis_default() -> Self {
        let genesis_config = Config::devnet();
        let genesis_header = LeanBlockHeader{
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            body_root: LeanBlockBody::<E> {
                attestations: VariableList::empty()
            }.tree_hash_root()
        };

        Self{
            config: genesis_config,
            slot: Slot(0),
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            latest_block_header: genesis_header,
            historical_block_hashes: List::empty(),
            justified_slots: BitVector::default(),
            validators: List::empty(),
            justifications_roots: List::empty(),
            justifications_validators: BitVector::default(),
        }
    }

    pub fn generate_genesis(&self, validators: List<Validator, E::ValidatorRegistryLimit>) -> Self {
        let genesis_config = Config::devnet();
        let genesis_header = LeanBlockHeader{
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            body_root: LeanBlockBody::<E> {

                attestations: VariableList::empty()
            }.tree_hash_root()
        };

        Self{
            config: genesis_config,
            slot:Slot(0),
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            latest_block_header: genesis_header,
            historical_block_hashes: List::empty(),
            justified_slots: BitVector::default(),
            validators,
            justifications_roots: List::empty(),
            justifications_validators: BitVector::default(),


        }
    }

    pub fn is_proposer(&self, validator_index: ValidatorIndex) -> bool {
        self.slot.0 %  self.validators.len() as u64 == validator_index.0

    }
    pub fn get_justifications(&self) ->
        Result<HashMap<Hash256, BitVector<E::HistoricalRootsLimit>>, String>
    {

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

            let mut justifications = BitVector::<E::HistoricalRootsLimit>::default();
            for (bit_idx, global_idx) in (start..end).enumerate() {
                let bit_value = self.justifications_validators.get(global_idx).map_err(|e| {
                    format!("Failed to get bit at index {}: {:?}", global_idx, e)
                })?;
                justifications.set(bit_idx, bit_value).map_err(|e| {
                    format!("Failed to set bit at index {}: {:?}", bit_idx, e)
                })?;
            }

            Ok((*root, justifications))
        })
        .collect()




    }
    pub fn with_justification(
        &mut self,
        root: Hash256,
        validator_justifications: &BitVector<E::HistoricalRootsLimit>,
    ) -> Result<(), String> {
        let validator_count = self.validators.len();

        if validator_justifications.len() < validator_count {
            return Err(format!(
                "Justifications vector length {} is less than validator count {}",
                validator_justifications.len(),
                validator_count
            ));
        }

        if self.justifications_roots.iter().any(|r| *r == root) {
            return Err(format!(
                "Root {:?} already exists in justifications_roots",
                root
            ));
        }

        self.justifications_roots.push(root).map_err(|e| {
            format!("Failed to append root to justifications_roots: {:?}", e)
        })?;

        for i in 0..validator_count {
            let bit_value = validator_justifications.get(i).map_err(|e| {
                format!("Failed to get bit at index {} from validator_justifications: {:?}", i, e)
            })?;

            let current_len = self.justifications_validators.len();
            self.justifications_validators.set(current_len, bit_value).map_err(|e| {
                format!("Failed to append bit to justifications_validators at index {}: {:?}", current_len, e)
            })?;
        }

        Ok(())
    }
    pub fn process_slot(&mut self) -> Result<(), String> {
        if self.latest_block_header.state_root == Hash256::ZERO{
            self.latest_block_header.state_root = self.tree_hash_root();
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
        }

        let num_empty_slots = block.slot.0 - parent_header.slot.0 - 1;

        self.historical_block_hashes.push(parent_root).map_err(|e| {
            format!("Failed to append parent root to historical hashes: {:?}", e)
        })?;

        self.justified_slots.set(self.historical_block_hashes.len() - 1, is_genesis_parent).map_err(|e| {
            format!("Failed to set justified slot: {:?}", e)
        })?;

        for _ in 0..num_empty_slots {
            self.historical_block_hashes.push(Hash256::ZERO).map_err(|e| {
                format!("Failed to append ZERO_HASH for empty slot: {:?}", e)
            })?;
            self.justified_slots.set(self.historical_block_hashes.len() - 1, false).map_err(|e| {
                format!("Failed to set justified slot for empty slot: {:?}", e)
            })?;
        }

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
    pub fn process_attestations(&mut self, attestations: &VariableList<Attestation, E::MaxAttestations>) -> Result<(), String> {
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
                    format!("Failed to get justified slot at index {}: {:?}", source_slot_int, e)
                })?
            } else {
                continue;
            };

            let target_is_justified = if target_slot_int < self.justified_slots.len() {
                self.justified_slots.get(target_slot_int).map_err(|e| {
                    format!("Failed to get justified slot at index {}: {:?}", target_slot_int, e)
                })?
            } else {
                false
            };

            if source_is_justified && target_is_justified {
                if source.slot.0 + 1 == target.slot.0
                    && self.latest_justified.slot < target.slot {
                    self.latest_finalized = (*source).clone();
                    self.latest_justified = (*target).clone();
                }
            } else if source_is_justified {
                while self.justified_slots.len() <= target_slot_int {
                    self.justified_slots.set(self.justified_slots.len(), false).map_err(|e| {
                        format!("Failed to extend justified_slots: {:?}", e)
                    })?;
                }

                self.justified_slots.set(target_slot_int, true).map_err(|e| {
                    format!("Failed to set justified slot at index {}: {:?}", target_slot_int, e)
                })?;

                if target.slot > self.latest_justified.slot {
                    self.latest_justified = (*target).clone();
                }
            }
        }

        Ok(())
    }
    pub fn state_transition(&mut self, block: &LeanBlock<E>, validate_signatures: bool) -> Result<(), String> {
        if validate_signatures {
            return Err("Signature validation not yet implemented".to_string());
        }

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

/// Chain configuration parameters for lean consensus.
///
/// This struct holds the canonical, immutable configuration constants for the chain.
/// It follows the lean consensus specification for chain configuration.
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// The fixed duration of a single slot in seconds.
    pub seconds_per_slot: u64,
    /// The number of slots to lookback for justification.
    pub justification_lookback_slots: u64,
    /// The maximum number of historical block roots to store in the state.
    pub historical_roots_limit: u64,
    /// The maximum number of validators that can be in the registry.
    pub validator_registry_limit: u64,
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
            seconds_per_slot: SECONDS_PER_SLOT,
            justification_lookback_slots: JUSTIFICATION_LOOKBACK_SLOTS,
            historical_roots_limit: HISTORICAL_ROOTS_LIMIT,
            validator_registry_limit: VALIDATOR_REGISTRY_LIMIT,
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
    /// This is derived from `seconds_per_slot` and `intervals_per_slot`.
    pub fn seconds_per_interval(&self) -> u64 {
        self.seconds_per_slot / INTERVALS_PER_SLOT
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
