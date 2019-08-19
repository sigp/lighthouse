use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::AttestationValidationError;
use bls::{verify_signature_sets, SignatureSet};
use core::borrow::Borrow;
use std::convert::TryInto;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    AggregatePublicKey, AttestationDataAndCustodyBit, AttesterSlashing, BeaconBlock,
    BeaconBlockHeader, BeaconState, BeaconStateError, ChainSpec, Deposit, Domain, EthSpec, Fork,
    IndexedAttestation, ProposerSlashing, PublicKey, RelativeEpoch, Signature, Transfer,
    VoluntaryExit,
};

type Message = Vec<u8>;

const SIGNATURES_PER_PROPOSER_SLASHING: usize = 2;
const SIGNATURES_PER_INDEXED_ATTESTATION: usize = 2;
const INDEXED_ATTESTATIONS_PER_ATTESTER_SLASHING: usize = 2;

pub type IndexedAttestationPublicKeys = [AggregatePublicKey; SIGNATURES_PER_INDEXED_ATTESTATION];
pub type AttesterSlashingPublicKeys =
    [IndexedAttestationPublicKeys; INDEXED_ATTESTATIONS_PER_ATTESTER_SLASHING];

pub enum Error {
    BeaconStateError(BeaconStateError),
    AttestationValidationError(AttestationValidationError),
    InsufficentPubkeys,
    ValidatorUnknown(u64),
    MismatchedPublicKeyLen { pubkey_len: usize, other_len: usize },
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

    pub fn verify_all(
        state: &'a BeaconState<T>,
        block: &'a BeaconBlock<T>,
        spec: &'a ChainSpec,
    ) -> Result<bool> {
        let mut s = Self::new(state, block, spec);

        s.include_block_proposal()?;
        s.include_randao_reveal()?;
        s.include_proposer_slashings()?;

        let attester_slashing_aggregate_public_keys =
            s.produce_attester_slashings_aggregate_public_keys()?;
        s.include_attester_slashing_indexed_attestations(&attester_slashing_aggregate_public_keys)?;

        // ## Attestation signatures
        //
        // Map `block.body.attestations` to `IndexedAttestations`, then produce the respective `AggregatePublicKeys`
        //  and add the signature sets to `s`.
        //
        // The reason for the 3-step process for attestation verification is to ensure that the
        // `Signature` from `IndexedAttestation` and the newly-created `AggregatePublicKey` can
        // live long enough.
        let indexed_attestations = s.produce_indexed_attestations()?;
        let indexed_attestation_aggregate_public_keys =
            s.produce_indexed_attestation_aggregate_public_keys(&indexed_attestations)?;
        s.include_indexed_attestations(
            &indexed_attestations,
            &indexed_attestation_aggregate_public_keys,
        )?;

        // ## Deposit signatures
        //
        // Collect all the valid pubkeys, signatures and messages from the block, then include them
        // in `s`.
        //
        // Deposits with invalid pubkeys/signatures are simply ignored here. It is important to
        // ensure that the downstream function checks again to ensure a validators key/sig is
        // valid. Otherwise, it may be possible to induct validators with invalid keys/sigs.
        let deposit_pubkeys_signatures_messages = s.produce_deposit_pubkeys_and_signatures();
        s.include_deposits(&deposit_pubkeys_signatures_messages)?;

        Ok(verify_signature_sets(s.into_iter()))
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

    pub fn produce_attester_slashings_aggregate_public_keys(
        &self,
    ) -> Result<Vec<AttesterSlashingPublicKeys>> {
        self.block
            .body
            .attester_slashings
            .iter()
            .map(|attester_slashing| {
                Ok([
                    indexed_attestation_pubkeys(&self.state, &attester_slashing.attestation_1)?,
                    indexed_attestation_pubkeys(&self.state, &attester_slashing.attestation_2)?,
                ])
            })
            .collect::<Result<_>>()
    }

    pub fn include_attester_slashing_indexed_attestations(
        &mut self,
        attester_slashings_aggregate_public_keys: &'a [AttesterSlashingPublicKeys],
    ) -> Result<()> {
        let pubkey_len = attester_slashings_aggregate_public_keys.len();
        let other_len = self.block.body.attester_slashings.len();

        if pubkey_len != other_len {
            return Err(Error::MismatchedPublicKeyLen {
                pubkey_len,
                other_len,
            });
        }

        let mut sets: Vec<SignatureSet> = self
            .block
            .body
            .attester_slashings
            .iter()
            .zip(attester_slashings_aggregate_public_keys)
            .map(|(attester_slashing, public_keys)| {
                attester_slashing_signature_set(
                    &self.state,
                    &attester_slashing,
                    public_keys,
                    &self.spec,
                )
                .map(|set| set.to_vec())
            })
            .collect::<Result<Vec<Vec<SignatureSet>>>>()?
            .iter()
            .flatten()
            .cloned()
            .collect();

        self.sets.append(&mut sets);

        Ok(())
    }

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
    ) -> Result<Vec<IndexedAttestationPublicKeys>> {
        indexed_attestations
            .iter()
            .map(|indexed_attestation| indexed_attestation_pubkeys(self.state, indexed_attestation))
            .collect::<Result<_>>()
    }

    pub fn include_indexed_attestations(
        &mut self,
        indexed_attestations: &'a [IndexedAttestation<T>],
        indexed_attestation_aggregate_public_keys: &'a [IndexedAttestationPublicKeys],
    ) -> Result<()> {
        let pubkey_len = indexed_attestation_aggregate_public_keys.len();
        let other_len = self.block.body.attestations.len();

        if pubkey_len != other_len {
            return Err(Error::MismatchedPublicKeyLen {
                pubkey_len,
                other_len,
            });
        }

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

    pub fn produce_deposit_pubkeys_and_signatures(
        &mut self,
    ) -> Vec<(PublicKey, Signature, Message)> {
        deposit_pubkeys_signatures_messages(&self.block.body.deposits)
    }

    pub fn include_deposits(
        &mut self,
        pubkeys_signatures_messages: &'a [(PublicKey, Signature, Message)],
    ) -> Result<()> {
        let mut sets = pubkeys_signatures_messages
            .iter()
            .map(|pubkey_signature_message| {
                deposit_signature_set(&self.state, pubkey_signature_message, &self.spec)
            })
            .collect();

        self.sets.append(&mut sets);

        Ok(())
    }

    pub fn include_exits(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .voluntary_exits
            .iter()
            .map(|exit| exit_signature_set(&self.state, exit, &self.spec))
            .collect::<Result<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    pub fn include_transfers(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .transfers
            .iter()
            .map(|transfer| transfer_signature_set(&self.state, transfer, &self.spec))
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
        .ok_or_else(|| Error::ValidatorUnknown(proposer_slashing.proposer_index))?;

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
) -> Result<IndexedAttestationPublicKeys> {
    Ok([
        create_aggregate_pubkey(state, &indexed_attestation.custody_bit_0_indices)?,
        create_aggregate_pubkey(state, &indexed_attestation.custody_bit_1_indices)?,
    ])
}

fn indexed_attestation_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    indexed_attestation: &'a IndexedAttestation<T>,
    pubkeys: &'a IndexedAttestationPublicKeys,
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
        pubkeys.iter().map(Borrow::borrow).collect(),
        vec![message_0, message_1],
        domain,
    ))
}

fn attester_slashing_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    attester_slashing: &'a AttesterSlashing<T>,
    pubkeys: &'a AttesterSlashingPublicKeys,
    spec: &'a ChainSpec,
) -> Result<[SignatureSet<'a>; INDEXED_ATTESTATIONS_PER_ATTESTER_SLASHING]> {
    Ok([
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_1,
            &pubkeys[0],
            spec,
        )?,
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_2,
            &pubkeys[1],
            spec,
        )?,
    ])
}

fn deposit_pubkeys_signatures_messages(
    deposits: &[Deposit],
) -> Vec<(PublicKey, Signature, Message)> {
    deposits
        .iter()
        .filter_map(|deposit| {
            let pubkey = (&deposit.data.pubkey).try_into().ok()?;
            let signature = (&deposit.data.signature).try_into().ok()?;
            let message = deposit.data.signed_root();
            Some((pubkey, signature, message))
        })
        .collect()
}

fn deposit_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    pubkey_signature_message: &'a (PublicKey, Signature, Message),
    spec: &'a ChainSpec,
) -> SignatureSet<'a> {
    // Note: Deposits are valid across forks, thus the deposit domain is computed
    // with the fork zeroed.
    let domain = spec.get_domain(state.current_epoch(), Domain::Deposit, &Fork::default());
    let (pubkey, signature, message) = pubkey_signature_message;

    SignatureSet::new(signature, vec![pubkey], vec![message.clone()], domain)
}

fn exit_signature_set<'a, T: EthSpec>(
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

    Ok(SignatureSet::new(
        &exit.signature,
        vec![&validator.pubkey],
        vec![message],
        domain,
    ))
}

fn transfer_signature_set<'a, T: EthSpec>(
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

    Ok(SignatureSet::new(
        &transfer.signature,
        vec![&transfer.pubkey],
        vec![message],
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
                .ok_or_else(|| Error::ValidatorUnknown(validator_idx))
                .map(|validator| {
                    aggregate_pubkey.add_without_affine(&validator.pubkey);
                    aggregate_pubkey
                })
        },
    )?;

    aggregate_pubkey.affine();

    Ok(aggregate_pubkey)
}
