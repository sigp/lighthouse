use super::errors::{ProposerSlashingInvalid as Invalid, ProposerSlashingValidationError as Error};
use tree_hash::SignedRoot;
use types::*;

/// Indicates if a `ProposerSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `ProposerSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.8.0
pub fn verify_proposer_slashing<T: EthSpec>(
    proposer_slashing: &ProposerSlashing,
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let proposer = state
        .validators
        .get(proposer_slashing.proposer_index as usize)
        .ok_or_else(|| {
            Error::Invalid(Invalid::ProposerUnknown(proposer_slashing.proposer_index))
        })?;

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

    verify!(
        verify_header_signature::<T>(
            &proposer_slashing.header_1,
            &proposer.pubkey,
            &state.fork,
            spec
        ),
        Invalid::BadProposal1Signature
    );
    verify!(
        verify_header_signature::<T>(
            &proposer_slashing.header_2,
            &proposer.pubkey,
            &state.fork,
            spec
        ),
        Invalid::BadProposal2Signature
    );

    Ok(())
}

/// Verifies the signature of a proposal.
///
/// Returns `true` if the signature is valid.
///
/// Spec v0.8.0
fn verify_header_signature<T: EthSpec>(
    header: &BeaconBlockHeader,
    pubkey: &PublicKey,
    fork: &Fork,
    spec: &ChainSpec,
) -> bool {
    let message = header.signed_root();
    let domain = spec.get_domain(
        header.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        fork,
    );
    header.signature.verify(&message[..], domain, pubkey)
}
