#![allow(clippy::integer_arithmetic)]

use super::signature_sets::{Error as SignatureSetError, *};
use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::{AttestationInvalid, BlockOperationError};
use bls::{verify_signature_sets, PublicKey, PublicKeyBytes, SignatureSet};
use rayon::prelude::*;
use std::borrow::Cow;
use types::{
    BeaconState, BeaconStateError, ChainSpec, EthSpec, Hash256, IndexedAttestation,
    SignedBeaconBlock,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// All public keys were found but signature verification failed. The block is invalid.
    SignatureInvalid,
    /// An attestation in the block was invalid. The block is invalid.
    AttestationValidationError(BlockOperationError<AttestationInvalid>),
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(BeaconStateError),
    /// The `BeaconBlock` has a `proposer_index` that does not match the index we computed locally.
    ///
    /// The block is invalid.
    IncorrectBlockProposer { block: u64, local_shuffling: u64 },
    /// Failed to load a signature set. The block may be invalid or we failed to process it.
    SignatureSetError(SignatureSetError),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<SignatureSetError> for Error {
    fn from(e: SignatureSetError) -> Error {
        match e {
            // Make a special distinction for `IncorrectBlockProposer` since it indicates an
            // invalid block, not an internal error.
            SignatureSetError::IncorrectBlockProposer {
                block,
                local_shuffling,
            } => Error::IncorrectBlockProposer {
                block,
                local_shuffling,
            },
            e => Error::SignatureSetError(e),
        }
    }
}

impl From<BlockOperationError<AttestationInvalid>> for Error {
    fn from(e: BlockOperationError<AttestationInvalid>) -> Error {
        Error::AttestationValidationError(e)
    }
}

/// Reads the BLS signatures and keys from a `SignedBeaconBlock`, storing them as a `Vec<SignatureSet>`.
///
/// This allows for optimizations related to batch BLS operations (see the
/// `Self::verify_entire_block(..)` function).
pub struct BlockSignatureVerifier<'a, T, F, D>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    get_pubkey: F,
    decompressor: D,
    state: &'a BeaconState<T>,
    spec: &'a ChainSpec,
    sets: ParallelSignatureSets<'a>,
}

#[derive(Default)]
pub struct ParallelSignatureSets<'a> {
    sets: Vec<SignatureSet<'a>>,
}

impl<'a> From<Vec<SignatureSet<'a>>> for ParallelSignatureSets<'a> {
    fn from(sets: Vec<SignatureSet<'a>>) -> Self {
        Self { sets }
    }
}

impl<'a, T, F, D> BlockSignatureVerifier<'a, T, F, D>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    /// Create a new verifier without any included signatures. See the `include...` functions to
    /// add signatures, and the `verify`
    pub fn new(
        state: &'a BeaconState<T>,
        get_pubkey: F,
        decompressor: D,
        spec: &'a ChainSpec,
    ) -> Self {
        Self {
            get_pubkey,
            decompressor,
            state,
            spec,
            sets: ParallelSignatureSets::default(),
        }
    }

    /// Verify all* the signatures in the given `SignedBeaconBlock`, returning `Ok(())` if the signatures
    /// are valid.
    ///
    /// * : _Does not verify any signatures in `block.body.deposits`. A block is still valid if it
    /// contains invalid signatures on deposits._
    ///
    /// See `Self::verify` for more detail.
    pub fn verify_entire_block(
        state: &'a BeaconState<T>,
        get_pubkey: F,
        decompressor: D,
        block: &'a SignedBeaconBlock<T>,
        block_root: Option<Hash256>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, get_pubkey, decompressor, spec);
        verifier.include_all_signatures(block, block_root)?;
        verifier.verify()
    }

    /// Includes all signatures on the block (except the deposit signatures) for verification.
    pub fn include_all_signatures(
        &mut self,
        block: &'a SignedBeaconBlock<T>,
        block_root: Option<Hash256>,
    ) -> Result<()> {
        self.include_block_proposal(block, block_root)?;
        self.include_all_signatures_except_proposal(block)?;

        Ok(())
    }

    /// Includes all signatures on the block (except the deposit signatures and the proposal
    /// signature) for verification.
    pub fn include_all_signatures_except_proposal(
        &mut self,
        block: &'a SignedBeaconBlock<T>,
    ) -> Result<()> {
        self.include_randao_reveal(block)?;
        self.include_proposer_slashings(block)?;
        self.include_attester_slashings(block)?;
        self.include_attestations(block)?;
        // Deposits are not included because they can legally have invalid signatures.
        self.include_exits(block)?;
        self.include_sync_aggregate(block)?;

        Ok(())
    }

    /// Includes the block signature for `self.block` for verification.
    pub fn include_block_proposal(
        &mut self,
        block: &'a SignedBeaconBlock<T>,
        block_root: Option<Hash256>,
    ) -> Result<()> {
        let set = block_proposal_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block,
            block_root,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes the randao signature for `self.block` for verification.
    pub fn include_randao_reveal(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        let set = randao_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block.message(),
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes all signatures in `self.block.body.proposer_slashings` for verification.
    pub fn include_proposer_slashings(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().proposer_slashings().len() * 2);

        block
            .message()
            .body()
            .proposer_slashings()
            .iter()
            .try_for_each(|proposer_slashing| {
                let (set_1, set_2) = proposer_slashing_signature_set(
                    self.state,
                    self.get_pubkey.clone(),
                    proposer_slashing,
                    self.spec,
                )?;

                self.sets.push(set_1);
                self.sets.push(set_2);

                Ok(())
            })
    }

    /// Includes all signatures in `self.block.body.attester_slashings` for verification.
    pub fn include_attester_slashings(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().attester_slashings().len() * 2);

        block
            .message()
            .body()
            .attester_slashings()
            .iter()
            .try_for_each(|attester_slashing| {
                let (set_1, set_2) = attester_slashing_signature_sets(
                    self.state,
                    self.get_pubkey.clone(),
                    attester_slashing,
                    self.spec,
                )?;

                self.sets.push(set_1);
                self.sets.push(set_2);

                Ok(())
            })
    }

    /// Includes all signatures in `self.block.body.attestations` for verification.
    pub fn include_attestations(
        &mut self,
        block: &'a SignedBeaconBlock<T>,
    ) -> Result<Vec<IndexedAttestation<T>>> {
        self.sets
            .sets
            .reserve(block.message().body().attestations().len());

        block
            .message()
            .body()
            .attestations()
            .iter()
            .try_fold(
                Vec::with_capacity(block.message().body().attestations().len()),
                |mut vec, attestation| {
                    let committee = self
                        .state
                        .get_beacon_committee(attestation.data.slot, attestation.data.index)?;
                    let indexed_attestation =
                        get_indexed_attestation(committee.committee, attestation)?;

                    self.sets.push(indexed_attestation_signature_set(
                        self.state,
                        self.get_pubkey.clone(),
                        &attestation.signature,
                        &indexed_attestation,
                        self.spec,
                    )?);

                    vec.push(indexed_attestation);

                    Ok(vec)
                },
            )
            .map_err(Error::into)
    }

    /// Includes all signatures in `self.block.body.voluntary_exits` for verification.
    pub fn include_exits(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().voluntary_exits().len());

        block
            .message()
            .body()
            .voluntary_exits()
            .iter()
            .try_for_each(|exit| {
                let exit =
                    exit_signature_set(self.state, self.get_pubkey.clone(), exit, self.spec)?;

                self.sets.push(exit);

                Ok(())
            })
    }

    /// Include the signature of the block's sync aggregate (if it exists) for verification.
    pub fn include_sync_aggregate(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        if let Some(sync_aggregate) = block.message().body().sync_aggregate() {
            if let Some(signature_set) = sync_aggregate_signature_set(
                &self.decompressor,
                sync_aggregate,
                block.slot(),
                block.parent_root(),
                self.state,
                self.spec,
            )? {
                self.sets.push(signature_set);
            }
        }
        Ok(())
    }

    /// Verify all the signatures that have been included in `self`, returning `true` if and only if
    /// all the signatures are valid.
    ///
    /// See `ParallelSignatureSets::verify` for more info.
    pub fn verify(self) -> Result<()> {
        if self.sets.verify() {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }
}

impl<'a> ParallelSignatureSets<'a> {
    pub fn push(&mut self, set: SignatureSet<'a>) {
        self.sets.push(set);
    }

    /// Verify all the signatures that have been included in `self`, returning `true` if and only if
    /// all the signatures are valid.
    ///
    /// ## Notes
    ///
    /// Signature validation will take place in accordance to the [Faster verification of multiple
    /// BLS signatures](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)
    /// optimization proposed by Vitalik Buterin.
    ///
    /// It is not possible to know exactly _which_ signature is invalid here, just that
    /// _at least one_ was invalid.
    ///
    /// Uses `rayon` to do a map-reduce of Vitalik's method across multiple cores.
    #[must_use]
    pub fn verify(self) -> bool {
        let num_sets = self.sets.len();
        let num_chunks = std::cmp::max(1, num_sets / rayon::current_num_threads());
        self.sets
            .into_par_iter()
            .chunks(num_chunks)
            .map(|chunk| verify_signature_sets(chunk.iter()))
            .reduce(|| true, |current, this| current && this)
    }
}
