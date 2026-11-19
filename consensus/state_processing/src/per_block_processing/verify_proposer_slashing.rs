use super::errors::{BlockOperationError, ProposerSlashingInvalid as Invalid};
use super::signature_sets::{get_bls_pubkey_from_state, proposer_slashing_signature_set};
use crate::VerifySignatures;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if a `ProposerSlashingBase` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `ProposerSlashingBase` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.12.1
pub fn verify_proposer_slashing<E: EthSpec>(
    proposer_slashing: &ProposerSlashingBase,
    state: &BeaconState<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let header_1 = &proposer_slashing.signed_header_1.message;
    let header_2 = &proposer_slashing.signed_header_2.message;

    check_headers(state, header_1, header_2)?;
    if verify_signatures.is_true() {
        let (signature_set_1, signature_set_2) = proposer_slashing_signature_set(
            state,
            |i| get_bls_pubkey_from_state(state, i),
            proposer_slashing,
            spec,
        )?;
        verify!(signature_set_1.verify(), Invalid::BadProposal1Signature);
        verify!(signature_set_2.verify(), Invalid::BadProposal2Signature);
    }
    Ok(())
}

pub fn verify_proposer_slashing_pq<E: EthSpec>(
    slashing: &ProposerSlashingPq,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<()> {
    let header_1 = &slashing.signed_header_1.message;
    let header_2 = &slashing.signed_header_2.message;
    let proposer = check_headers(state, header_1, header_2)?;
    let domain = spec.get_domain(
        header_1.slot.epoch(E::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let leaf = crate::pq::slot_leaf_index(header_1.slot, crate::pq::LEAF_OFFSET_BEACON_PROPOSER)?;
    verify!(
        crate::pq::verify_signature(
            &proposer.pubkey,
            leaf,
            header_1.signing_root(domain),
            &slashing.signed_header_1.signature
        ),
        Invalid::BadProposal1Signature
    );
    verify!(
        crate::pq::verify_signature(
            &proposer.pubkey,
            leaf,
            header_2.signing_root(domain),
            &slashing.signed_header_2.signature
        ),
        Invalid::BadProposal2Signature
    );
    Ok(())
}

fn check_headers<'a, E: EthSpec>(
    state: &'a BeaconState<E>,
    header_1: &BeaconBlockHeader,
    header_2: &BeaconBlockHeader,
) -> Result<&'a Validator> {
    // Verify slots match
    verify!(
        header_1.slot == header_2.slot,
        Invalid::ProposalSlotMismatch(header_1.slot, header_2.slot)
    );

    // Verify header proposer indices match
    verify!(
        header_1.proposer_index == header_2.proposer_index,
        Invalid::ProposerIndexMismatch(header_1.proposer_index, header_2.proposer_index)
    );

    // But the headers are different
    verify!(header_1 != header_2, Invalid::ProposalsIdentical);

    // Check proposer is slashable
    let proposer = state
        .validators()
        .get(header_1.proposer_index as usize)
        .ok_or_else(|| error(Invalid::ProposerUnknown(header_1.proposer_index)))?;

    verify!(
        proposer.is_slashable_at(state.current_epoch()),
        Invalid::ProposerNotSlashable(header_1.proposer_index)
    );

    Ok(proposer)
}
