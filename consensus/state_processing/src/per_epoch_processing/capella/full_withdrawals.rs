use crate::EpochProcessingError;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;

pub fn process_full_withdrawals<T: EthSpec>(
    _state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    todo!("implement this");
    Ok(())
}
