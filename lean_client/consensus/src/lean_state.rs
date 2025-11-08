use crate::attestation::{Checkpoint, Slot};
use crate::validator::Validator;

use crate::lean_block::LeanBlockHeader;
use milhouse::List;
use types::{BitVector, EthSpec, Hash256};

pub struct LeanState<E: EthSpec> {
    config: Config,
    slot: Slot,
    latest_block_header: LeanBlockHeader,
    latest_justified: Checkpoint,
    latest_finalized: Checkpoint,
    //TODO: deal with this E: EthSpec
    historical_block_hashes: List<Hash256, E::HistoricalRootsLimit>,
    //TODO: the Justification needs to be different
    justified_slots: BitVector<E::JustificationBitsLength>,
    validators: List<Validator, E::ValidatorRegistryLimit>,
    justifications_roots: List<Hash256, E::JustificationBitsLength>,
    justifications_validators: BitVector<E::ValidatorRegistryLimit>,
}

impl<E: EthSpec> LeanState<E> {
    pub fn generate_genesis(&self) {}

    pub fn is_proposer(&self) {}
    pub fn get_justifications(&self) {}
    pub fn with_justification(&self) {}
    pub fn process_slot(&self) {}
    pub fn process_slots(&self) {}
    pub fn process_block_header(&self) {}
    pub fn process_block(&self) {}
    pub fn process_attestations(&self) {}
    pub fn state_transistion(&self) {}
}

pub struct Config {}
