use crate::errors::{ProposerSlashingInvalid as Invalid, ProposerSlashingValidationError as Error};
use ssz::SignedRoot;
use types::*;

/// Indicates if a `ProposerSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `ProposerSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.4.0
pub fn verify_proposer_slashing(
    proposer_slashing: &ProposerSlashing,
    state: &BeaconState,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let proposer = state
        .validator_registry
        .get(proposer_slashing.proposer_index as usize)
        .ok_or(Error::Invalid(Invalid::ProposerUnknown(
            proposer_slashing.proposer_index,
        )))?;

    verify!(
        proposer_slashing.proposal_1.slot == proposer_slashing.proposal_2.slot,
        Invalid::ProposalSlotMismatch(
            proposer_slashing.proposal_1.slot,
            proposer_slashing.proposal_2.slot
        )
    );

    verify!(
        proposer_slashing.proposal_1.shard == proposer_slashing.proposal_2.shard,
        Invalid::ProposalShardMismatch(
            proposer_slashing.proposal_1.shard,
            proposer_slashing.proposal_2.shard
        )
    );

    verify!(
        proposer_slashing.proposal_1.block_root != proposer_slashing.proposal_2.block_root,
        Invalid::ProposalBlockRootMismatch(
            proposer_slashing.proposal_1.block_root,
            proposer_slashing.proposal_2.block_root
        )
    );

    verify!(!proposer.slashed, Invalid::ProposerAlreadySlashed);

    verify!(
        verify_proposal_signature(
            &proposer_slashing.proposal_1,
            &proposer.pubkey,
            &state.fork,
            spec
        ),
        Invalid::BadProposal1Signature
    );
    verify!(
        verify_proposal_signature(
            &proposer_slashing.proposal_2,
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
fn verify_proposal_signature(
    proposal: &Proposal,
    pubkey: &PublicKey,
    fork: &Fork,
    spec: &ChainSpec,
) -> bool {
    let message = proposal.signed_root();
    let domain = spec.get_domain(
        proposal.slot.epoch(spec.slots_per_epoch),
        Domain::Proposal,
        fork,
    );
    proposal.signature.verify(&message[..], domain, pubkey)
}
