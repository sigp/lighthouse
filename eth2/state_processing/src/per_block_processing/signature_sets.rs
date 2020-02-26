//! A `SignatureSet` is an abstraction over the components of a signature. A `SignatureSet` may be
//! validated individually, or alongside in others in a potentially cheaper bulk operation.
//!
//! This module exposes one function to extract each type of `SignatureSet` from a `BeaconBlock`.
use bls::{SignatureSet, SignedMessage};
use ssz::DecodeError;
use std::borrow::Cow;
use tree_hash::TreeHash;
use types::{
    AttesterSlashing, BeaconBlock, BeaconState, BeaconStateError, ChainSpec, DepositData, Domain,
    EthSpec, Fork, Hash256, IndexedAttestation, ProposerSlashing, PublicKey, Signature,
    SignedBeaconBlock, SignedBeaconBlockHeader, SignedRoot, SignedVoluntaryExit, SigningRoot,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Signature verification failed. The block is invalid.
    SignatureInvalid(DecodeError),
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(BeaconStateError),
    /// Attempted to find the public key of a validator that does not exist. You cannot distinguish
    /// between an error and an invalid block in this case.
    ValidatorUnknown(u64),
    /// The public keys supplied do not match the number of objects requiring keys. Block validity
    /// was not determined.
    MismatchedPublicKeyLen { pubkey_len: usize, other_len: usize },
    /// The public key bytes stored in the `BeaconState` were not valid. This is a serious internal
    /// error.
    BadBlsBytes { validator_index: u64 },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

pub fn get_pubkey_from_state<'a, T>(
    state: &'a BeaconState<T>,
) -> impl Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone
where
    T: EthSpec,
{
    move |validator_index: usize| -> Option<Cow<'a, PublicKey>> {
        state
            .validators
            .get(validator_index)
            .and_then(|v| {
                let pk: Option<PublicKey> = (&v.pubkey).decompress().ok();
                pk
            })
            .map(Cow::Owned)
    }
}

/// A signature set that is valid if a block was signed by the expected block producer.
pub fn block_proposal_signature_set<'a, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    signed_block: &'a SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let block = &signed_block.message;
    let proposer_index = state.get_beacon_proposer_index(block.slot, spec)?;

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = if let Some(root) = block_root {
        SigningRoot {
            object_root: root,
            domain,
        }
        .tree_hash_root()
    } else {
        block.signing_root(domain)
    };

    Ok(SignatureSet::single(
        &signed_block.signature,
        get_pubkey(proposer_index).ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?,
        message.to_fixed_bytes(),
    ))
}

/// A signature set that is valid if the block proposers randao reveal signature is correct.
pub fn randao_signature_set<'a, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    block: &'a BeaconBlock<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let proposer_index = state.get_beacon_proposer_index(block.slot, spec)?;

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::Randao,
        &state.fork,
    );

    let message = state.current_epoch().signing_root(domain);

    Ok(SignatureSet::single(
        &block.body.randao_reveal,
        get_pubkey(proposer_index).ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?,
        message.to_fixed_bytes(),
    ))
}

/// Returns two signature sets, one for each `BlockHeader` included in the `ProposerSlashing`.
pub fn proposer_slashing_signature_set<'a, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    proposer_slashing: &'a ProposerSlashing,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let proposer_index = proposer_slashing.proposer_index as usize;

    Ok((
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_1,
            get_pubkey(proposer_index)
                .ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?,
            spec,
        )?,
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_2,
            get_pubkey(proposer_index)
                .ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?,
            spec,
        )?,
    ))
}

/// Returns a signature set that is valid if the given `pubkey` signed the `header`.
fn block_header_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    signed_header: &'a SignedBeaconBlockHeader,
    pubkey: Cow<'a, PublicKey>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let domain = spec.get_domain(
        signed_header.message.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = signed_header.message.signing_root(domain);

    Ok(SignatureSet::single(
        &signed_header.signature,
        pubkey,
        message.to_fixed_bytes(),
    ))
}

/// Returns the signature set for the given `indexed_attestation`.
pub fn indexed_attestation_signature_set<'a, 'b, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    signature: &'a Signature,
    indexed_attestation: &'b IndexedAttestation<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let pubkeys = indexed_attestation
        .attesting_indices
        .into_iter()
        .map(|&validator_idx| {
            Ok(get_pubkey(validator_idx as usize)
                .ok_or_else(|| Error::ValidatorUnknown(validator_idx))?)
        })
        .collect::<Result<_>>()?;

    let domain = spec.get_domain(
        indexed_attestation.data.target.epoch,
        Domain::BeaconAttester,
        &state.fork,
    );

    let message = indexed_attestation.data.signing_root(domain);
    let signed_message = SignedMessage::new(pubkeys, message.to_fixed_bytes());

    Ok(SignatureSet::new(signature, vec![signed_message]))
}

// TODO: try and combine this and the above function into one.
/// Returns the signature set for the given `indexed_attestation` but pubkeys are supplied directly
/// instead of from the state.
pub fn indexed_attestation_signature_set_from_pubkeys<'a, 'b, T, F>(
    get_pubkey: F,
    signature: &'a Signature,
    indexed_attestation: &'b IndexedAttestation<T>,
    fork: &Fork,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let pubkeys = indexed_attestation
        .attesting_indices
        .into_iter()
        .map(|&validator_idx| {
            Ok(get_pubkey(validator_idx as usize)
                .ok_or_else(|| Error::ValidatorUnknown(validator_idx))?)
        })
        .collect::<Result<_>>()?;

    let domain = spec.get_domain(
        indexed_attestation.data.target.epoch,
        Domain::BeaconAttester,
        &fork,
    );

    let message = indexed_attestation.data.signing_root(domain);
    let signed_message = SignedMessage::new(pubkeys, message.to_fixed_bytes());

    Ok(SignatureSet::new(signature, vec![signed_message]))
}

/// Returns the signature set for the given `attester_slashing` and corresponding `pubkeys`.
pub fn attester_slashing_signature_sets<'a, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    attester_slashing: &'a AttesterSlashing<T>,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
{
    Ok((
        indexed_attestation_signature_set(
            state,
            get_pubkey.clone(),
            &attester_slashing.attestation_1.signature,
            &attester_slashing.attestation_1,
            spec,
        )?,
        indexed_attestation_signature_set(
            state,
            get_pubkey,
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
    deposit_data: &DepositData,
    spec: &ChainSpec,
) -> Option<(PublicKey, Signature, Hash256)> {
    let pubkey = deposit_data.pubkey.decompress().ok()?;
    let signature = deposit_data.signature.decompress().ok()?;
    let domain = spec.get_deposit_domain();
    let message = deposit_data.as_deposit_message().signing_root(domain);
    Some((pubkey, signature, message))
}

/// Returns the signature set for some set of deposit signatures, made with
/// `deposit_pubkey_signature_message`.
pub fn deposit_signature_set<'a>(
    pubkey_signature_message: &'a (PublicKey, Signature, Hash256),
) -> SignatureSet<'a> {
    let (pubkey, signature, message) = pubkey_signature_message;

    // Note: Deposits are valid across forks, thus the deposit domain is computed
    // with the fork zeroed.
    SignatureSet::single(signature, Cow::Borrowed(pubkey), message.to_fixed_bytes())
}

/// Returns a signature set that is valid if the `SignedVoluntaryExit` was signed by the indicated
/// validator.
pub fn exit_signature_set<'a, T, F>(
    state: &'a BeaconState<T>,
    get_pubkey: F,
    signed_exit: &'a SignedVoluntaryExit,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>>,
{
    let exit = &signed_exit.message;
    let proposer_index = exit.validator_index as usize;

    let domain = spec.get_domain(exit.epoch, Domain::VoluntaryExit, &state.fork);

    let message = exit.signing_root(domain);

    Ok(SignatureSet::single(
        &signed_exit.signature,
        get_pubkey(proposer_index).ok_or_else(|| Error::ValidatorUnknown(proposer_index as u64))?,
        message.to_fixed_bytes(),
    ))
}

/*
/// Maps a validator index to a `PublicKey`.
pub fn validator_pubkey<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    validator_index: usize,
) -> Result<Cow<'a, PublicKey>> {
    let pubkey_bytes = &state
        .validators
        .get(validator_index)
        .ok_or_else(|| Error::ValidatorUnknown(validator_index as u64))?
        .pubkey;

    if let Some(pubkey) = pubkey_bytes.decompressed() {
        Ok(Cow::Borrowed(&pubkey.as_raw().point))
    } else {
        pubkey_bytes
            .try_into()
            .map(|pubkey: PublicKey| Cow::Owned(pubkey.as_raw().point.clone()))
            .map_err(|_| Error::BadBlsBytes {
                validator_index: validator_index as u64,
            })
    }
}
*/
