use crate::attestation::{Attestation, Checkpoint, Slot};

use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::lean_block::{LeanBlock, LeanBlockBody};
use crate::validator::ValidatorIndex;
use crate::validator::Validator;

use types::VariableList;
use crate::lean_block::LeanBlockHeader;
use milhouse::List;
use types::{BitVector, EthSpec, Hash256};


#[derive(TreeHash)]
pub struct LeanState<E: EthSpec> {
    pub config: Config,
    pub slot: Slot,

    pub latest_block_header: LeanBlockHeader,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    //TODO: deal with this E: EthSpec
    pub historical_block_hashes: List<Hash256, E::HistoricalRootsLimit>,
    //TODO: the Justification needs to be different
    pub justified_slots: BitVector<E::JustificationBitsLength>,
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    pub justifications_roots: List<Hash256, E::JustificationBitsLength>,
    pub justifications_validators: BitVector<E::ValidatorRegistryLimit>,
}

impl<E: EthSpec> LeanState<E> {
    pub fn generate_genesis(&self, validators: List<Validator, E::ValidatorRegistryLimit>) -> Self {
        let genesis_config = Config {


        };
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
        Result<HashMap<Hash256, BitVector<E::ValidatorRegistryLimit>>, String>
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

            let mut justifications = BitVector::<E::ValidatorRegistryLimit>::default();
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
        validator_justifications: &BitVector<E::ValidatorRegistryLimit>,
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

#[derive(TreeHash)]
pub struct Config {}
