use crate::per_block_processing::errors::{
    BlockOperationError, PayloadAttestationInvalid as Invalid,
};
use types::*;

pub fn get_indexed_payload_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    payload_attestation: &PayloadAttestation<E>,
) -> Result<IndexedPayloadAttestation<E>, BlockOperationError<Invalid>> {
    let attesting_indices = get_payload_attesting_indices(state, slot, payload_attestation)?;

    Ok(IndexedPayloadAttestation {
        attesting_indices: VariableList::new(attesting_indices)?,
        data: payload_attestation.data.clone(),
        signature: payload_attestation.signature.clone(),
    })
}

pub fn get_payload_attesting_indices<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    payload_attestation: &PayloadAttestation<E>,
) -> Result<Vec<u64>, BeaconStateError> {
    let ptc = state.get_ptc(slot)?;
    let bitlist = &payload_attestation.aggregation_bits;
    if bitlist.len() != ptc.len() {
        return Err(BeaconStateError::InvalidBitfield);
    }

    let mut attesting_indices = Vec::<u64>::new();
    for (i, index) in ptc.into_iter().enumerate() {
        if let Ok(true) = bitlist.get(i) {
            attesting_indices.push(*index as u64);
        }
    }
    attesting_indices.sort_unstable();

    Ok(attesting_indices)
}
