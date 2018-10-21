use super::ValidatorRegistration;

#[derive(Debug, Clone, PartialEq)]
pub struct ChainConfig {
    pub cycle_length: u8,
    pub shard_count: u16,
    pub min_committee_size: u64,
    pub genesis_time: u64,
    pub initial_validators: Vec<ValidatorRegistration>,
}

/*
 * Presently this is just some arbitrary time in Sept 2018.
 */
const GENESIS_TIME: u64 = 1_537_488_655;

impl ChainConfig {
    pub fn standard() -> Self {
        Self {
            cycle_length: 64,
            shard_count: 1024,
            min_committee_size: 128,
            genesis_time: GENESIS_TIME,   // arbitrary
            initial_validators: vec![],
        }
    }

    pub fn validate(&self) -> bool {
	    // criteria that ensure the config is valid

	    // shard_count / cycle_length > 0 otherwise validator delegation
	    // will fail.
	    if self.shard_count / self.cycle_length as u16 == 0  {
		    return false;
	    }

	    true
    }



    #[cfg(test)]
    pub fn super_fast_tests() -> Self {
        Self {
            cycle_length: 2,
            shard_count: 2,
            min_committee_size: 2,
            genesis_time: GENESIS_TIME,   // arbitrary
            initial_validators: vec![],
        }
    }
}
