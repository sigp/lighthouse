use super::utils::types::U256;

pub struct Config {
    pub attester_count: u64,
    pub max_validators: u64,
    pub shard_count: u16,
    pub epoch_length: u64,
    pub notaries_per_crosslink: u16,
    pub default_balance: U256,
    pub eject_balance: U256,
    pub attester_reward: i64,
}

impl Config {
    pub fn standard() -> Self {
        Self {
            attester_count: 32,
            max_validators: 2u64.pow(24),
            shard_count: 20,
            epoch_length: 5,
            notaries_per_crosslink: 100,
            default_balance: U256::from(32000),
            eject_balance: U256::from(16000),
            attester_reward: 1,
        }
    }
}
