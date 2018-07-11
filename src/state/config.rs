pub struct Config {
    pub attester_count: u64,
    pub max_validators: u64
}

impl Config {
    pub fn standard() -> Self {
        Self {
            attester_count: 32,
            max_validators: 2u64.pow(24)
        }
    }
}
