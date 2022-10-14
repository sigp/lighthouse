use crate::EpochProcessingError;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;

pub fn process_partial_withdrawals<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    todo!("implement this");
    Ok(())
}
