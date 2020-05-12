use std::fmt;
use std::iter::Iterator;

pub const PURPOSE: u32 = 12381;
pub const COIN_TYPE: u32 = 3600;

pub enum KeyType {
    Voting,
    Withdrawal,
}

pub struct ValidatorPath(Vec<u32>);

impl ValidatorPath {
    pub fn new(index: u32, key_type: KeyType) -> Self {
        let mut vec = vec![PURPOSE, COIN_TYPE, index, 0];

        match key_type {
            KeyType::Voting => vec.push(0),
            KeyType::Withdrawal => {}
        }

        Self(vec)
    }

    pub fn iter_nodes(&self) -> impl Iterator<Item = &u32> {
        self.0.iter()
    }
}

impl fmt::Display for ValidatorPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;

        for node in self.iter_nodes() {
            write!(f, "/{}", node)?;
        }

        Ok(())
    }
}
