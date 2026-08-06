use crate::per_block_processing::errors::{
    BlockOperationError, PayloadAttestationInvalid as Invalid,
};
use ssz_types::VariableList;
use types::{
    BeaconState, BeaconStateError, ChainSpec, IndexedPayloadAttestation, PayloadAttestation,
};

pub fn get_indexed_payload_attestation(
    state: &BeaconState,
    payload_attestation: &PayloadAttestation,
    spec: &ChainSpec,
) -> Result<IndexedPayloadAttestation, BlockOperationError<Invalid>> {
    let attesting_indices = get_payload_attesting_indices(state, payload_attestation, spec)?;

    Ok(IndexedPayloadAttestation {
        attesting_indices: VariableList::new(attesting_indices)?,
        data: payload_attestation.data.clone(),
        signature: payload_attestation.signature.clone(),
    })
}

pub fn get_payload_attesting_indices(
    state: &BeaconState,
    payload_attestation: &PayloadAttestation,
    spec: &ChainSpec,
) -> Result<Vec<u64>, BeaconStateError> {
    let slot = payload_attestation.data.slot;
    let ptc = state.get_ptc(slot, spec)?;
    let bits = &payload_attestation.aggregation_bits;

    let mut attesting_indices = vec![];
    for (i, index) in ptc.into_iter().enumerate() {
        if let Ok(true) = bits.get(i) {
            attesting_indices.push(index as u64);
        }
    }
    attesting_indices.sort_unstable();

    Ok(attesting_indices)
}
