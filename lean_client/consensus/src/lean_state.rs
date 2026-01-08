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
    pub justifications_validators: BitList<E::JustificationValidators>,
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

        // Genesis checkpoints use ZERO_HASH as root, matching the spec (mini3sf).
        // The actual genesis block root is set later during block processing when
        // the first block after genesis is processed.
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

        // Extend justifications_validators by creating a new BitList with larger capacity
        let current_len = self.justifications_validators.len();
        let new_len = current_len + validator_count;
        let mut new_justifications_validators =
            BitList::<E::JustificationValidators>::with_capacity(new_len).map_err(|e| {
                format!(
                    "Failed to create extended justifications_validators with capacity {}: {:?}",
                    new_len, e
                )
            })?;

        // Copy existing bits
        for i in 0..current_len {
            let bit = self.justifications_validators.get(i).map_err(|e| {
                format!(
                    "Failed to get justifications_validators bit at {}: {:?}",
                    i, e
                )
            })?;
            new_justifications_validators.set(i, bit).map_err(|e| {
                format!(
                    "Failed to copy justifications_validators bit at {}: {:?}",
                    i, e
                )
            })?;
        }

        // Append new bits from validator_justifications
        for i in 0..validator_count {
            let bit_value = validator_justifications.get(i).map_err(|e| {
                format!(
                    "Failed to get bit at index {} from validator_justifications: {:?}",
                    i, e
                )
            })?;

            new_justifications_validators
                .set(current_len + i, bit_value)
                .map_err(|e| {
                    format!(
                        "Failed to set bit at index {} in justifications_validators: {:?}",
                        current_len + i,
                        e
                    )
                })?;
        }

        self.justifications_validators = new_justifications_validators;

        Ok(())
    }

    /// Replaces all justifications with a new map.
    ///
    /// This is used after processing attestations to persist the updated justification state.
    /// The map is flattened into `justifications_roots` and `justifications_validators` with
    /// roots sorted lexicographically for deterministic ordering.
    pub fn update_justifications(
        &mut self,
        justifications: HashMap<Hash256, BitList<E::HistoricalRootsLimit>>,
    ) -> Result<(), String> {
        let num_validators = self.validators.len();

        // Sort roots for deterministic ordering
        let mut roots: Vec<_> = justifications.keys().cloned().collect();
        roots.sort();

        // Calculate total size needed for justifications_validators
        let total_bits = roots.len() * num_validators;

        // Create new structures
        let mut new_roots = VariableList::<Hash256, E::HistoricalRootsLimit>::empty();
        // Create BitList with exact capacity - with_capacity creates a list of that length
        let mut new_validators = BitList::<E::JustificationValidators>::with_capacity(total_bits)
            .map_err(|e| format!("Failed to create justifications_validators BitList: {:?}", e))?;

        // Track the current index for writing bits
        let mut bit_index = 0;

        for root in roots {
            new_roots
                .push(root)
                .map_err(|e| format!("Failed to push root to justifications_roots: {:?}", e))?;

            let votes = justifications.get(&root).ok_or_else(|| {
                format!("Root {:?} not found in justifications map", root)
            })?;

            for i in 0..num_validators {
                let bit = votes.get(i).unwrap_or(false);
                new_validators.set(bit_index, bit).map_err(|e| {
                    format!(
                        "Failed to set bit at index {} (total_bits={}): {:?}",
                        bit_index, total_bits, e
                    )
                })?;
                bit_index += 1;
            }
        }

        self.justifications_roots = new_roots;
        self.justifications_validators = new_validators;

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
    /// Process attestations with 2/3 supermajority check for justification.
    ///
    /// The justification algorithm:
    /// 1. Track which validators have attested to each target checkpoint
    /// 2. Only justify a target when 2/3+ of validators have attested (3 * count >= 2 * total)
    /// 3. Finalize the source when target is justified and no justifiable slots exist between them
    pub fn process_attestations(
        &mut self,
        attestations: &VariableList<Attestation, E::ValidatorRegistryLimit>,
    ) -> Result<(), String> {
        use crate::helpers::is_justifiable_slot;

        let num_validators = self.validators.len();
        if num_validators == 0 {
            return Ok(());
        }

        // Load existing justifications into working map
        let mut justifications = self.get_justifications()?;

        for attestation in attestations.iter() {
            let attestation_data = &attestation.attestation_data;
            let source = &attestation_data.source;
            let target = &attestation_data.target;
            let validator_id = attestation.validator_id as usize;

            // Validate attestation
            if source.slot >= target.slot {
                debug!(
                    source_slot = source.slot.0,
                    target_slot = target.slot.0,
                    "Skipping attestation: source slot >= target slot"
                );
                continue;
            }

            let source_slot = source.slot.0 as usize;
            let target_slot = target.slot.0 as usize;

            // Check source is justified
            let source_is_justified = if source_slot < self.justified_slots.len() {
                self.justified_slots.get(source_slot).map_err(|e| {
                    format!("Failed to get justified slot at index {}: {:?}", source_slot, e)
                })?
            } else {
                debug!(
                    source_slot = source_slot,
                    justified_slots_len = self.justified_slots.len(),
                    "Skipping attestation: source slot out of range"
                );
                continue;
            };

            if !source_is_justified {
                debug!(
                    source_slot = source_slot,
                    "Skipping attestation: source not justified"
                );
                continue;
            }

            // Check target not already justified
            let target_is_justified = if target_slot < self.justified_slots.len() {
                self.justified_slots.get(target_slot).unwrap_or(false)
            } else {
                false
            };

            if target_is_justified {
                debug!(
                    target_slot = target_slot,
                    "Skipping attestation: target already justified"
                );
                continue;
            }

            // Check roots match historical block hashes
            if source_slot >= self.historical_block_hashes.len() {
                continue;
            }
            if target_slot >= self.historical_block_hashes.len() {
                continue;
            }
            if self.historical_block_hashes[source_slot] != source.root {
                debug!(
                    source_slot = source_slot,
                    expected_root = ?self.historical_block_hashes[source_slot],
                    actual_root = ?source.root,
                    "Skipping attestation: source root mismatch"
                );
                continue;
            }
            if self.historical_block_hashes[target_slot] != target.root {
                debug!(
                    target_slot = target_slot,
                    expected_root = ?self.historical_block_hashes[target_slot],
                    actual_root = ?target.root,
                    "Skipping attestation: target root mismatch"
                );
                continue;
            }

            // Check target is justifiable based on the slot pattern
            match is_justifiable_slot(self.latest_finalized.slot.0, target.slot.0) {
                Ok(true) => {}
                Ok(false) => {
                    debug!(
                        target_slot = target.slot.0,
                        finalized_slot = self.latest_finalized.slot.0,
                        "Skipping attestation: target slot not justifiable"
                    );
                    continue;
                }
                Err(e) => {
                    debug!(
                        target_slot = target.slot.0,
                        finalized_slot = self.latest_finalized.slot.0,
                        error = ?e,
                        "Skipping attestation: is_justifiable_slot error"
                    );
                    continue;
                }
            }

            // Validate validator_id
            if validator_id >= num_validators {
                debug!(
                    validator_id = validator_id,
                    num_validators = num_validators,
                    "Skipping attestation: invalid validator_id"
                );
                continue;
            }

            // Track this validator's vote for target
            let target_votes = justifications.entry(target.root).or_insert_with(|| {
                BitList::<E::HistoricalRootsLimit>::with_capacity(num_validators)
                    .expect("Failed to create BitList for target votes")
            });

            target_votes
                .set(validator_id, true)
                .map_err(|e| format!("Failed to set vote for validator {}: {:?}", validator_id, e))?;

            // Count votes for this target
            let vote_count = (0..num_validators)
                .filter(|i| target_votes.get(*i).unwrap_or(false))
                .count();

            let threshold_2_3 = (2 * num_validators + 2) / 3; // Ceiling of 2/3

            debug!(
                target_slot = target.slot.0,
                vote_count = vote_count,
                threshold_2_3 = threshold_2_3,
                num_validators = num_validators,
                validator_id = validator_id,
                "Attestation processed"
            );

            // Check 2/3 supermajority: 3 * count >= 2 * total (equivalent to count >= 2/3 * total)
            if 3 * vote_count >= 2 * num_validators {
                // Extend justified_slots if needed by creating a larger BitList
                if self.justified_slots.len() <= target_slot {
                    let new_len = target_slot + 1;
                    let mut new_justified_slots =
                        BitList::<E::HistoricalRootsLimit>::with_capacity(new_len).map_err(
                            |e| {
                                format!(
                                    "Failed to create extended justified_slots with capacity {}: {:?}",
                                    new_len, e
                                )
                            },
                        )?;

                    // Copy existing bits
                    for i in 0..self.justified_slots.len() {
                        let bit = self.justified_slots.get(i).map_err(|e| {
                            format!("Failed to get justified_slots bit at {}: {:?}", i, e)
                        })?;
                        new_justified_slots.set(i, bit).map_err(|e| {
                            format!("Failed to copy justified_slots bit at {}: {:?}", i, e)
                        })?;
                    }

                    // Fill remaining slots with false
                    for i in self.justified_slots.len()..new_len {
                        new_justified_slots.set(i, false).map_err(|e| {
                            format!("Failed to initialize justified_slots bit at {}: {:?}", i, e)
                        })?;
                    }

                    self.justified_slots = new_justified_slots;

                    debug!(
                        old_len = target_slot,
                        new_len = new_len,
                        "Extended justified_slots BitList"
                    );
                }

                // Justify target
                self.justified_slots
                    .set(target_slot, true)
                    .map_err(|e| format!("Failed to set justified slot: {:?}", e))?;

                debug!(
                    target_slot = target.slot.0,
                    vote_count = vote_count,
                    threshold_2_3 = threshold_2_3,
                    "JUSTIFIED: 2/3 supermajority reached"
                );

                if target.slot > self.latest_justified.slot {
                    // Check if we can finalize source
                    // Source can be finalized if there are no justifiable slots between source and target
                    let can_finalize = self.can_finalize_source(source, target)?;

                    if can_finalize {
                        self.latest_finalized = source.clone();
                        debug!(
                            finalized_slot = source.slot.0,
                            finalized_root = ?source.root,
                            "FINALIZED: source checkpoint finalized via 2/3 supermajority"
                        );
                    }

                    self.latest_justified = target.clone();
                    debug!(
                        justified_slot = target.slot.0,
                        justified_root = ?target.root,
                        "Latest justified updated"
                    );
                }

                // Remove from tracking (already justified)
                justifications.remove(&target.root);
            }
        }

        // Persist updated justifications back to state
        self.update_justifications(justifications)?;

        Ok(())
    }

    /// Check if source can be finalized based on target justification.
    ///
    /// Source can be finalized if there are no justifiable slots between source and target.
    fn can_finalize_source(&self, source: &Checkpoint, target: &Checkpoint) -> Result<bool, String> {
        use crate::helpers::is_justifiable_slot;

        for check_slot in (source.slot.0 + 1)..target.slot.0 {
            match is_justifiable_slot(self.latest_finalized.slot.0, check_slot) {
                Ok(true) => return Ok(false), // Found a justifiable slot in between
                Ok(false) => continue,
                Err(e) => return Err(format!("is_justifiable_slot error: {}", e)),
            }
        }
        Ok(true)
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
