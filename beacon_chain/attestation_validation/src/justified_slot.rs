use super::types::{AttestationData, BeaconState};
use super::{Error, Invalid, Outcome};

/// Verify that an attestation's `data.justified_slot` matches the justified slot known to the
/// `state`.
///
/// In the case that an attestation references a slot _before_ the latest state transition, is
/// acceptable for the attestation to reference the previous known `justified_slot`. If this were
/// not the case, all attestations created _prior_ to the last state recalculation would be rejected
/// if a block was justified in that state recalculation. It is both ideal and likely that blocks
/// will be justified during a state recalcuation.
pub fn validate_attestation_justified_slot(
    data: &AttestationData,
    state: &BeaconState,
) -> Result<Outcome, Error> {
    let permissable_justified_slot = if data.slot >= state.latest_state_recalculation_slot {
        state.justified_slot
    } else {
        state.previous_justified_slot
    };
    verify_or!(
        data.justified_slot == permissable_justified_slot,
        reject!(Invalid::JustifiedSlotImpermissable)
    );
    accept!()
}

#[cfg(test)]
mod tests {
    /*
     * TODO: Implement tests.
     *
     * These tests will require the `BeaconBlock` and `BeaconBlockBody` updates, which are not
     * yet included in the code base. Adding tests now will result in duplicated work.
     *
     * https://github.com/sigp/lighthouse/issues/97
     */
}
