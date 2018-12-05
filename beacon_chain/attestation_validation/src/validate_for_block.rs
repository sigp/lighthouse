use super::{Error, Invalid, Outcome};

/// Check that an attestation is valid to be included in some block.
pub fn validate_attestation_for_block<T>(
    attestation_slot: u64,
    block_slot: u64,
    parent_block_slot: u64,
    min_attestation_inclusion_delay: u64,
    epoch_length: u64,
) -> Result<Outcome, Error> {
    /*
     * There is a delay before an attestation may be included in a block, quantified by
     * `slots` and defined as `min_attestation_inclusion_delay`.
     *
     * So, an attestation must be at least `min_attestation_inclusion_delay` slots "older" than the
     * block it is contained in.
     */
    verify_or!(
        attestation_slot <= block_slot.saturating_sub(min_attestation_inclusion_delay),
        reject!(Invalid::AttestationTooRecent)
    );

    /*
     * A block may not include attestations reference slots more than an epoch length + 1 prior to
     * the block slot.
     */
    verify_or!(
        attestation_slot >= parent_block_slot.saturating_sub(epoch_length + 1),
        reject!(Invalid::AttestationTooOld)
    );

    accept!()
}
