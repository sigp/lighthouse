extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

mod genesis;

use std::collections::HashMap;
use types::{
    ActiveState,
    ChainConfig,
    CrystallizedState,
    Hash256,
};

#[derive(Debug, PartialEq)]
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
    pub config: ChainConfig,
}

impl BeaconChain {
    pub fn new(config: ChainConfig)
        -> Result<Self, BeaconChainError>
    {
        let (active_state, crystallized_state) = BeaconChain::genesis_states(&config)?;

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
            config,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use types::ValidatorRegistration;

    #[test]
    fn test_new_chain() {
        let mut config = ChainConfig::standard();

        for _ in 0..4 {
            config.initial_validators.push(ValidatorRegistration::random())
        }

        let chain = BeaconChain::new(config.clone()).unwrap();
        let (act, cry) = BeaconChain::genesis_states(&config).unwrap();

        assert_eq!(chain.last_finalized_slot, None);
        assert_eq!(chain.canonical_latest_block_hash, Hash256::zero());

        let stored_act = chain.active_states.get(&Hash256::zero()).unwrap();
        assert_eq!(act, *stored_act);

        let stored_cry = chain.crystallized_states.get(&Hash256::zero()).unwrap();
        assert_eq!(cry, *stored_cry);
    }
}
