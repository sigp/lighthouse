use super::{Error, Invalid, Outcome};

/// Check that an attestation is valid to be included in some block.
pub fn validate_attestation_for_block(
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
        // TODO: this differs from the spec as it does not handle underflows correctly.
        // https://github.com/sigp/lighthouse/issues/95
        attestation_slot < block_slot.saturating_sub(min_attestation_inclusion_delay - 1),
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

#[cfg(test)]
mod tests {
    use super::*;
    /*
     * Invalid::AttestationTooOld tests.
     */

    #[test]
    fn test_inclusion_too_old_minimal() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = 100;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = block_slot - min_attestation_inclusion_delay;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_old_maximal() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = 100;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = block_slot - epoch_length + 1;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_old_saturating_non_zero_attestation_slot() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = epoch_length + 1;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = block_slot - min_attestation_inclusion_delay;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_old_saturating_zero_attestation_slot() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = epoch_length + 1;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = 0;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_old() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = epoch_length * 2;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = parent_block_slot - (epoch_length + 2);

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Invalid(Invalid::AttestationTooOld)));
    }

    /*
     * Invalid::AttestationTooRecent tests.
     */

    #[test]
    fn test_inclusion_too_recent_minimal() {
        let parent_block_slot = 99;
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = 100;
        let attestation_slot = block_slot - min_attestation_inclusion_delay;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_recent_maximal() {
        let parent_block_slot = 99;
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = 100;
        let attestation_slot = block_slot - epoch_length;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_recent_insufficient() {
        let parent_block_slot = 99;
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = 100;
        let attestation_slot = block_slot - (min_attestation_inclusion_delay - 1);

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Invalid(Invalid::AttestationTooRecent)));
    }

    #[test]
    fn test_inclusion_too_recent_first_possible_slot() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = min_attestation_inclusion_delay;
        let attestation_slot = 0;
        let parent_block_slot = block_slot - 1;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Valid));
    }

    #[test]
    fn test_inclusion_too_recent_saturation_non_zero_slot() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = min_attestation_inclusion_delay - 1;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = 0;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Invalid(Invalid::AttestationTooRecent)));
    }

    #[test]
    fn test_inclusion_too_recent_saturation_zero_slot() {
        let min_attestation_inclusion_delay = 10;
        let epoch_length = 20;
        let block_slot = min_attestation_inclusion_delay - 1;
        let parent_block_slot = block_slot - 1;
        let attestation_slot = 0;

        let outcome = validate_attestation_for_block(
            attestation_slot,
            block_slot,
            parent_block_slot,
            min_attestation_inclusion_delay,
            epoch_length,
        );
        assert_eq!(outcome, Ok(Outcome::Invalid(Invalid::AttestationTooRecent)));
    }
}
