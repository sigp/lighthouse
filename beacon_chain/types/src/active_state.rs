use super::Hash256;
use super::{Attestation, SpecialRecord};

#[derive(Debug, PartialEq)]
pub struct ActiveState {
    pub pending_attestations: Vec<Attestation>,
    pub pending_specials: Vec<SpecialRecord>,
    pub recent_block_hashes: Vec<Hash256>,
    pub randao_mix: Hash256,
}

impl ActiveState {
    // TODO: implement this.
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::zero()
    }
}
