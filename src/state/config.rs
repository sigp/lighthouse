pub struct Config {
    pub attester_count: u32,
    pub max_validators: u32
}

impl Config {
    pub fn standard() -> Self {
        Self {
            attester_count: 32,
            max_validators: 2u32.pow(24)
        }
    }
}
