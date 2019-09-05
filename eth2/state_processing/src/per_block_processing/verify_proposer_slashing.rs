use super::errors::{BlockOperationError, ProposerSlashingInvalid as Invalid};
use super::signature_sets::proposer_slashing_signature_set;
use crate::VerifySignatures;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if a `ProposerSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `ProposerSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.8.0
pub fn verify_proposer_slashing<T: EthSpec>(
    proposer_slashing: &ProposerSlashing,
    state: &BeaconState<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let proposer = state
        .validators
        .get(proposer_slashing.proposer_index as usize)
        .ok_or_else(|| error(Invalid::ProposerUnknown(proposer_slashing.proposer_index)))?;

    // Verify that the epoch is the same
    verify!(
        proposer_slashing.header_1.slot.epoch(T::slots_per_epoch())
            == proposer_slashing.header_2.slot.epoch(T::slots_per_epoch()),
        Invalid::ProposalEpochMismatch(
            proposer_slashing.header_1.slot,
            proposer_slashing.header_2.slot
        )
    );

    // But the headers are different
    verify!(
        proposer_slashing.header_1 != proposer_slashing.header_2,
        Invalid::ProposalsIdentical
    );

    // Check proposer is slashable
    verify!(
        proposer.is_slashable_at(state.current_epoch()),
        Invalid::ProposerNotSlashable(proposer_slashing.proposer_index)
    );

    if verify_signatures.is_true() {
        let (signature_set_1, signature_set_2) =
            proposer_slashing_signature_set(state, proposer_slashing, spec)?;
        verify!(signature_set_1.is_valid(), Invalid::BadProposal1Signature);
        verify!(signature_set_2.is_valid(), Invalid::BadProposal2Signature);
    }

    Ok(())
}
