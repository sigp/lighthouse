pub struct ChainConfig {
    pub cycle_length: u8,
    pub shard_count: u16,
    pub min_committee_size: u64,
}

impl ChainConfig {
    pub fn standard() -> Self {
        Self {
            cycle_length: 8,
            shard_count: 1024,
            min_committee_size: 128,
        }
    }
}
