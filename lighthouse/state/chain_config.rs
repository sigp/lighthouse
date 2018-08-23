pub struct ChainConfig {
    pub cycle_length: u8,
}

impl ChainConfig {
    pub fn standard() -> Self {
        Self {
            cycle_length: 8,
        }
    }
}
