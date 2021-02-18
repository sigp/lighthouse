use crate::{errors::BeaconChainError as Error, BeaconChain, BeaconChainTypes};
use types::SignedBeaconBlock;

// TODO(sproul): implement and use in sync
impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn import_historical_block_batch(
        &self,
        _blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
