use super::{
    BeaconChain,
    BeaconChainError,
};

impl BeaconChain {
    pub fn validate_serialized_block(&self, ssz: &[u8])
        -> Result<(), BeaconChainError>
    {
        Ok(())
    }
}
