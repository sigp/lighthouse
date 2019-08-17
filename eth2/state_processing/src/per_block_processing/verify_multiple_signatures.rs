use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::AttestationValidationError;
use bls::{G1Point, SignatureSet};
use tree_hash::{SignedRoot, TreeHash};
use types::{
    AggregatePublicKey, AggregateSignature, AttestationDataAndCustodyBit, BeaconBlock,
    BeaconBlockHeader, BeaconState, BeaconStateError, ChainSpec, Domain, EthSpec, Hash256,
    IndexedAttestation, ProposerSlashing, PublicKey, RelativeEpoch, SecretKey, Signature,
};

const SIGNATURES_PER_PROPOSER_SLASHING: usize = 2;
const SIGNATURES_PER_INDEXED_ATTESTATION: usize = 2;
// FIXME: set this to something reasonable.
const MAX_POSSIBLE_AGGREGATE_PUBKEYS: usize = 10;

pub enum Error {
    BeaconStateError(BeaconStateError),
    AttestationValidationError(AttestationValidationError),
    InsufficentPubkeys,
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<AttestationValidationError> for Error {
    fn from(e: AttestationValidationError) -> Error {
        Error::AttestationValidationError(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

pub struct EntireBlockSignatureVerifier<'a, T: EthSpec> {
    block: &'a BeaconBlock<T>,
    state: &'a BeaconState<T>,
    spec: &'a ChainSpec,
    sets: Vec<SignatureSet<'a>>,
}

impl<'a, T: EthSpec> EntireBlockSignatureVerifier<'a, T> {
    pub fn new(state: &'a BeaconState<T>, block: &'a BeaconBlock<T>, spec: &'a ChainSpec) -> Self {
        Self {
            block,
            state,
            spec,
            sets: vec![],
        }
    }

    pub fn include_block_proposal(&mut self) -> Result<()> {
        let set = block_proposal_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    pub fn include_randao_reveal(&mut self) -> Result<()> {
        let set = randao_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    pub fn include_proposer_slashings(&mut self) -> Result<()> {
        let mut sets: Vec<SignatureSet> = self
            .block
            .body
            .proposer_slashings
            .iter()
            .map(|proposer_slashing| {
                proposer_slashing_signature_set(self.state, proposer_slashing, self.spec)
                    .map(|a| a.to_vec())
            })
            .collect::<Result<Vec<Vec<SignatureSet>>>>()?
            .iter()
            .flatten()
            .cloned()
            .collect();

        self.sets.append(&mut sets);
        Ok(())
    }

    // FIXME: attester slashings

    pub fn produce_indexed_attestations(&mut self) -> Result<Vec<IndexedAttestation<T>>> {
        self.block
            .body
            .attestations
            .iter()
            .map(|attestation| get_indexed_attestation(self.state, attestation))
            .collect::<std::result::Result<Vec<IndexedAttestation<T>>, AttestationValidationError>>(
            )
            .map_err(Into::into)
    }

    pub fn produce_indexed_attestation_aggregate_public_keys(
        &mut self,
        indexed_attestations: &'a [IndexedAttestation<T>],
    ) -> Result<Vec<[AggregatePublicKey; SIGNATURES_PER_INDEXED_ATTESTATION]>> {
        indexed_attestations
            .iter()
            .map(|indexed_attestation| indexed_attestation_pubkeys(self.state, indexed_attestation))
            .collect::<Result<_>>()
    }

    pub fn include_indexed_attestations(
        &mut self,
        indexed_attestations: &'a [IndexedAttestation<T>],
        indexed_attestation_aggregate_public_keys: &'a [[&'a AggregatePublicKey;
                 SIGNATURES_PER_INDEXED_ATTESTATION]],
    ) -> Result<()> {
        // FIXME: compare input lengths

        let mut sets: Vec<SignatureSet> = indexed_attestations
            .into_iter()
            .zip(indexed_attestation_aggregate_public_keys)
            .map(|(indexed_attestation, pubkeys)| {
                indexed_attestation_signature_set(
                    self.state,
                    indexed_attestation,
                    pubkeys,
                    self.spec,
                )
            })
            .collect::<Result<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    fn into_iter(self) -> impl Iterator<Item = SignatureSet<'a>> {
        self.sets.into_iter()
    }
}

// TODO: unify with block_header_signature_set?
fn block_proposal_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    block: &'a BeaconBlock<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let block_proposer = &state.validators
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = block.signed_root();

    Ok(SignatureSet::new(
        &block.signature,
        vec![&block_proposer.pubkey],
        vec![message],
        domain,
    ))
}

fn randao_signature_set<'a, T: EthSpec>(
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

    Ok(SignatureSet::new(
        &block.body.randao_reveal,
        vec![&block_proposer.pubkey],
        vec![message],
        domain,
    ))
}

fn proposer_slashing_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    proposer_slashing: &'a ProposerSlashing,
    spec: &'a ChainSpec,
) -> Result<[SignatureSet<'a>; SIGNATURES_PER_PROPOSER_SLASHING]> {
    let proposer = state
        .validators
        .get(proposer_slashing.proposer_index as usize)
        .ok_or_else(|| BeaconStateError::UnknownValidator)?;

    Ok([
        block_header_signature_set(state, &proposer_slashing.header_1, &proposer.pubkey, spec)?,
        block_header_signature_set(state, &proposer_slashing.header_2, &proposer.pubkey, spec)?,
    ])
}

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

    Ok(SignatureSet::new(
        &header.signature,
        vec![pubkey],
        vec![message],
        domain,
    ))
}

fn indexed_attestation_pubkeys<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    indexed_attestation: &'a IndexedAttestation<T>,
) -> Result<[AggregatePublicKey; SIGNATURES_PER_INDEXED_ATTESTATION]> {
    Ok([
        create_aggregate_pubkey(state, &indexed_attestation.custody_bit_0_indices)?,
        create_aggregate_pubkey(state, &indexed_attestation.custody_bit_1_indices)?,
    ])
}

fn indexed_attestation_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    indexed_attestation: &'a IndexedAttestation<T>,
    pubkeys: &'a [&'a AggregatePublicKey; SIGNATURES_PER_INDEXED_ATTESTATION],
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

    Ok(SignatureSet::new(
        &indexed_attestation.signature,
        pubkeys.to_vec(),
        vec![message_0, message_1],
        domain,
    ))
}

/// Create an aggregate public key for a list of validators, failing if any key can't be found.
fn create_aggregate_pubkey<'a, T, I>(
    state: &BeaconState<T>,
    validator_indices: I,
) -> Result<AggregatePublicKey>
where
    I: IntoIterator<Item = &'a u64>,
    T: EthSpec,
{
    let mut aggregate_pubkey = validator_indices.into_iter().try_fold(
        AggregatePublicKey::new(),
        |mut aggregate_pubkey, &validator_idx| {
            state
                .validators
                .get(validator_idx as usize)
                .ok_or_else(|| BeaconStateError::UnknownValidator)
                .map(|validator| {
                    aggregate_pubkey.add_without_affine(&validator.pubkey);
                    aggregate_pubkey
                })
        },
    )?;

    aggregate_pubkey.affine();

    Ok(aggregate_pubkey)
}
