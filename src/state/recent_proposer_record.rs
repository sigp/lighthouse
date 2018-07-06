use super::utils::types::*;

pub struct RecentPropserRecord {
    pub index: u32,     // TODO: make u24
    pub randao_commitment: Sha256Digest,
    pub balance_delta: u32, // TODO: make u24
}

impl RecentPropserRecord {
    pub fn new(index: u32, 
               randao_commitment: Sha256Digest, 
               balance_delta: u32) -> RecentPropserRecord {
        RecentPropserRecord {
            index: index,
            randao_commitment: randao_commitment,
            balance_delta: balance_delta
        }
    }
}
