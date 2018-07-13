pub struct Config {
    pub attester_count: u64,
    pub max_validators: u64,
    pub shard_count: u16,
    pub notaries_per_crosslink: u16
}

impl Config {
    pub fn standard() -> Self {
        Self {
            attester_count: 32,
            max_validators: 2u64.pow(24),
            shard_count: 20,
            notaries_per_crosslink: 100
        }
    }
}
