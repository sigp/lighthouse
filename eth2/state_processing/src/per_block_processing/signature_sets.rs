//! A `SignatureSet` is an abstraction over the components of a signature. A `SignatureSet` may be
//! validated individually, or alongside in others in a potentially cheaper bulk operation.
//!
//! This module exposes one function to extract each type of `SignatureSet` from a `BeaconBlock`.
use bls::SignatureSet;
use std::convert::TryInto;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    AggregateSignature, AttestationDataAndCustodyBit, AttesterSlashing, BeaconBlock,
    BeaconBlockHeader, BeaconState, BeaconStateError, ChainSpec, Deposit, Domain, EthSpec, Fork,
    Hash256, IndexedAttestation, ProposerSlashing, PublicKey, RelativeEpoch, Signature, Transfer,
    VoluntaryExit,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Signature verification failed. The block is invalid.
    SignatureInvalid,
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(BeaconStateError),
    /// Attempted to find the public key of a validator that does not exist. You cannot distinguish
    /// between an error and an invalid block in this case.
    ValidatorUnknown(u64),
    /// The public keys supplied do not match the number of objects requiring keys. Block validity
    /// was not determined.
    MismatchedPublicKeyLen { pubkey_len: usize, other_len: usize },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

/// A signature set that is valid if a block was signed by the expected block producer.
pub fn block_proposal_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    block: &'a BeaconBlock<T>,
    block_signed_root: Option<Hash256>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let proposer_index =
        state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?;
    let block_proposer = &state
        .validators
        .get(proposer_index)
        .ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?;

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = if let Some(root) = block_signed_root {
        root.as_bytes().to_vec()
    } else {
        block.signed_root()
    };

    Ok(SignatureSet::single(
        &block.signature,
        &block_proposer.pubkey,
        message,
        domain,
    ))
}

/// A signature set that is valid if the block proposers randao reveal signature is correct.
pub fn randao_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    block: &'a BeaconBlock<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let block_proposer = &state.validators
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::Randao,
        &state.fork,
    );

    let message = state.current_epoch().tree_hash_root();

    Ok(SignatureSet::single(
        &block.body.randao_reveal,
        &block_proposer.pubkey,
        message,
        domain,
    ))
}

/// Returns two signature sets, one for each `BlockHeader` included in the `ProposerSlashing`.
pub fn proposer_slashing_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    proposer_slashing: &'a ProposerSlashing,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)> {
    let proposer = state
        .validators
        .get(proposer_slashing.proposer_index as usize)
        .ok_or_else(|| Error::ValidatorUnknown(proposer_slashing.proposer_index))?;

    Ok((
        block_header_signature_set(state, &proposer_slashing.header_1, &proposer.pubkey, spec)?,
        block_header_signature_set(state, &proposer_slashing.header_2, &proposer.pubkey, spec)?,
    ))
}

/// Returns a signature set that is valid if the given `pubkey` signed the `header`.
fn block_header_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    header: &'a BeaconBlockHeader,
    pubkey: &'a PublicKey,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let domain = spec.get_domain(
        header.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = header.signed_root();

    Ok(SignatureSet::single(
        &header.signature,
        pubkey,
        message,
        domain,
    ))
}

/// Returns the signature set for the given `indexed_attestation`.
pub fn indexed_attestation_signature_set<'a, 'b, T: EthSpec>(
    state: &'a BeaconState<T>,
    signature: &'a AggregateSignature,
    indexed_attestation: &'b IndexedAttestation<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let message_0 = AttestationDataAndCustodyBit {
        data: indexed_attestation.data.clone(),
        custody_bit: false,
    }
    .tree_hash_root();
    let message_1 = AttestationDataAndCustodyBit {
        data: indexed_attestation.data.clone(),
        custody_bit: true,
    }
    .tree_hash_root();

    let domain = spec.get_domain(
        indexed_attestation.data.target.epoch,
        Domain::Attestation,
        &state.fork,
    );

    Ok(SignatureSet::dual(
        signature,
        message_0,
        get_pubkeys(state, &indexed_attestation.custody_bit_0_indices)?,
        message_1,
        get_pubkeys(state, &indexed_attestation.custody_bit_1_indices)?,
        domain,
    ))
}

/// Returns the signature set for the given `attester_slashing` and corresponding `pubkeys`.
pub fn attester_slashing_signature_sets<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    attester_slashing: &'a AttesterSlashing<T>,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)> {
    Ok((
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_1.signature,
            &attester_slashing.attestation_1,
            spec,
        )?,
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_2.signature,
            &attester_slashing.attestation_2,
            spec,
        )?,
    ))
}

/// Returns the BLS values in a `Deposit`, if they're all valid. Otherwise, returns `None`.
///
/// This method is separate to `deposit_signature_set` to satisfy lifetime requirements.
pub fn deposit_pubkey_signature_message(
    deposit: &Deposit,
) -> Option<(PublicKey, Signature, Vec<u8>)> {
    let pubkey = (&deposit.data.pubkey).try_into().ok()?;
    let signature = (&deposit.data.signature).try_into().ok()?;
    let message = deposit.data.signed_root();
    Some((pubkey, signature, message))
}

/// Returns the signature set for some set of deposit signatures, made with
/// `deposit_pubkey_signature_message`.
pub fn deposit_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    pubkey_signature_message: &'a (PublicKey, Signature, Vec<u8>),
    spec: &'a ChainSpec,
) -> SignatureSet<'a> {
    let (pubkey, signature, message) = pubkey_signature_message;

    // Note: Deposits are valid across forks, thus the deposit domain is computed
    // with the fork zeroed.
    let domain = spec.get_domain(state.current_epoch(), Domain::Deposit, &Fork::default());

    SignatureSet::single(signature, pubkey, message.clone(), domain)
}

/// Returns a signature set that is valid if the `VoluntaryExit` was signed by the indicated
/// validator.
pub fn exit_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    exit: &'a VoluntaryExit,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let validator = state
        .validators
        .get(exit.validator_index as usize)
        .ok_or_else(|| Error::ValidatorUnknown(exit.validator_index))?;

    let domain = spec.get_domain(exit.epoch, Domain::VoluntaryExit, &state.fork);

    let message = exit.signed_root();

    Ok(SignatureSet::single(
        &exit.signature,
        &validator.pubkey,
        message,
        domain,
    ))
}

/// Returns a signature set that is valid if the `Transfer` was signed by `transfer.pubkey`.
pub fn transfer_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    transfer: &'a Transfer,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let domain = spec.get_domain(
        transfer.slot.epoch(T::slots_per_epoch()),
        Domain::Transfer,
        &state.fork,
    );

    let message = transfer.signed_root();

    Ok(SignatureSet::single(
        &transfer.signature,
        &transfer.pubkey,
        message,
        domain,
    ))
}

/// Maps validator indices to public keys.
fn get_pubkeys<'a, 'b, T, I>(
    state: &'a BeaconState<T>,
    validator_indices: I,
) -> Result<Vec<&'a PublicKey>>
where
    I: IntoIterator<Item = &'b u64>,
    T: EthSpec,
{
    validator_indices
        .into_iter()
        .map(|&validator_idx| {
            state
                .validators
                .get(validator_idx as usize)
                .ok_or_else(|| Error::ValidatorUnknown(validator_idx))
                .map(|validator| &validator.pubkey)
        })
        .collect()
}
