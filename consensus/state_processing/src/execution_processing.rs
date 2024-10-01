use crate::BlockProcessingError;
use types::{BeaconState, ChainSpec, EthSpec, SignedExecutionEnvelope};

pub fn process_execution_payload_envelope<E: EthSpec>(
    state: &mut BeaconState<E>,
    signed_envelope: SignedExecutionEnvelope<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    Ok(())
}
