extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

mod blocks;
mod genesis;

use std::collections::HashMap;
use types::{
    ActiveState,
    ChainConfig,
    CrystallizedState,
    Hash256,
};

pub enum BeaconChainError {
    InvalidGenesis,
    DBError(String),
}

pub struct BeaconChain {
    pub last_finalized_slot: Option<u64>,
    pub canonical_latest_block_hash: Hash256,
    pub fork_latest_block_hashes: Vec<Hash256>,
    pub active_states: HashMap<Hash256, ActiveState>,
    pub crystallized_states: HashMap<Hash256, CrystallizedState>,
}

impl BeaconChain {
    pub fn new(config: ChainConfig)
        -> Result<Self, BeaconChainError>
    {
        let initial_validators = vec![];
        let (active_state, crystallized_state) = BeaconChain::genesis_states(
            &initial_validators, &config)?;

        let canonical_latest_block_hash = Hash256::zero();
        let fork_latest_block_hashes = vec![];
        let mut active_states = HashMap::new();
        let mut crystallized_states = HashMap::new();

        active_states.insert(canonical_latest_block_hash, active_state);
        crystallized_states.insert(canonical_latest_block_hash, crystallized_state);

        Ok(Self{
            last_finalized_slot: None,
            canonical_latest_block_hash,
            fork_latest_block_hashes,
            active_states,
            crystallized_states,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_chain() {
        assert_eq!(2 + 2, 4);
    }
}
