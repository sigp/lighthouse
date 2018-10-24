use super::ValidatorRegistration;

#[derive(Debug, Clone, PartialEq)]
pub struct ChainConfig {
    pub cycle_length: u8,
    pub deposit_size_gwei: u64,
    pub shard_count: u16,
    pub min_committee_size: u64,
    pub max_validator_churn_quotient: u64,
    pub genesis_time: u64,
    pub slot_duration_millis: u64,
    pub initial_validators: Vec<ValidatorRegistration>,
}

/*
 * Presently this is just some arbitrary time in Sept 2018.
 */
const TEST_GENESIS_TIME: u64 = 1_537_488_655;

impl ChainConfig {
    pub fn standard() -> Self {
        Self {
            cycle_length: 64,
            deposit_size_gwei: 32 * (10^9),
            shard_count: 1024,
            min_committee_size: 128,
            max_validator_churn_quotient: 32,
            genesis_time: TEST_GENESIS_TIME,
            slot_duration_millis: 16 * 1000,
            initial_validators: vec![],
        }
    }

    pub fn validate(&self) -> bool {
	    // criteria that ensure the config is valid

	    // shard_count / cycle_length > 0 otherwise validator delegation
	    // will fail.
	    if self.shard_count / u16::from(self.cycle_length) == 0  {
		    return false;
	    }

	    true
    }



    #[cfg(test)]
    pub fn super_fast_tests() -> Self {
        Self {
            cycle_length: 2,
            deposit_size_gwei: 32 * (10^9),
            shard_count: 2,
            min_committee_size: 2,
            max_validator_churn_quotient: 32,
            genesis_time: TEST_GENESIS_TIME,   // arbitrary
            slot_duration_millis: 16 * 1000,
            initial_validators: vec![],
        }
    }
}
