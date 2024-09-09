use super::errors::{BlockOperationError, PayloadAttestationInvalid as Invalid};
use super::VerifySignatures;
use crate::per_block_processing::is_valid_indexed_payload_attestation;
use crate::ConsensusContext;
use types::*;

pub fn verify_payload_attestation<'ctxt, E: EthSpec>(
    state: &BeaconState<E>,
    payload_attestation: &'ctxt PayloadAttestation<E>,
    ctxt: &'ctxt mut ConsensusContext<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<&'ctxt IndexedPayloadAttestation<E>, BlockOperationError<Invalid>> {
    // Check that the attestation is for the parent beacon block
    let data = &payload_attestation.data;
    verify!(
        data.beacon_block_root == state.latest_block_header().parent_root,
        Invalid::BlockRootMismatch {
            expected: state.latest_block_header().parent_root,
            found: data.beacon_block_root,
        }
    );
    // Check that the attestation is for the previous slot
    verify!(
        data.slot + 1 == state.slot(),
        Invalid::SlotMismatch {
            expected: state.slot().saturating_sub(Slot::new(1)),
            found: data.slot,
        }
    );

    let indexed_payload_attestation =
        ctxt.get_indexed_payload_attestation(state, data.slot, &payload_attestation)?;
    is_valid_indexed_payload_attestation(
        state,
        &indexed_payload_attestation,
        verify_signatures,
        spec,
    )?;

    Ok(indexed_payload_attestation)
}
