use crate::errors::{ProposerSlashingInvalid as Invalid, ProposerSlashingValidationError as Error};
use ssz::SignedRoot;
use types::*;

/// Returns `Ok(())` if some `ProposerSlashing` is valid to be included in some `BeaconState`,
/// otherwise returns an `Err`.
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
        .ok_or(Error::Invalid(Invalid::ProposerUnknown))?;

    verify!(
        proposer_slashing.proposal_1.slot == proposer_slashing.proposal_2.slot,
        Invalid::ProposalSlotMismatch
    );

    verify!(
        proposer_slashing.proposal_1.shard == proposer_slashing.proposal_2.shard,
        Invalid::ProposalShardMismatch
    );

    verify!(
        proposer_slashing.proposal_1.block_root != proposer_slashing.proposal_2.block_root,
        Invalid::ProposalBlockRootMismatch
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
