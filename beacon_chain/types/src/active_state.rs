use super::Hash256;
use super::{
    AttestationRecord,
    SpecialRecord,
};

#[derive(Debug, PartialEq)]
pub struct ActiveState {
    pub pending_attestations: Vec<AttestationRecord>,
    pub pending_specials: Vec<SpecialRecord>,
    pub recent_block_hashes: Vec<Hash256>,
    pub randao_mix: Hash256,
}
