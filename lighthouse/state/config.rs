pub struct Config {
    pub cycle_length: u8,
}

impl Config {
    pub fn standard() -> Self {
        Self {
            cycle_length: 8,
        }
    }
}
