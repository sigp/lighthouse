use super::signature_sets::{Error as SignatureSetError, Result as SignatureSetResult, *};
use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::{AttestationInvalid, BlockOperationError};
use bls::{verify_signature_sets, SignatureSet};
use rayon::prelude::*;
use std::borrow::Cow;
use types::{
    BeaconState, BeaconStateError, ChainSpec, EthSpec, Hash256, IndexedAttestation,
    SignedBeaconBlock,
};

pub use bls::G1Point;

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
        Error::SignatureSetError(e)
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
pub struct BlockSignatureVerifier<'a, T, F>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, G1Point>> + Clone,
{
    get_pubkey: F,
    state: &'a BeaconState<T>,
    spec: &'a ChainSpec,
    sets: Vec<SignatureSet<'a>>,
}

impl<'a, T, F> BlockSignatureVerifier<'a, T, F>
where
    T: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, G1Point>> + Clone,
{
    /// Create a new verifier without any included signatures. See the `include...` functions to
    /// add signatures, and the `verify`
    pub fn new(state: &'a BeaconState<T>, get_pubkey: F, spec: &'a ChainSpec) -> Self {
        Self {
            get_pubkey: get_pubkey,
            state,
            spec,
            sets: vec![],
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
        block: &'a SignedBeaconBlock<T>,
        block_root: Option<Hash256>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, get_pubkey, spec);
        verifier.include_all_signatures(block, block_root)?;
        verifier.verify()
    }

    /// Verify all* the signatures that have been included in `self`, returning `Ok(())` if the
    /// signatures are all valid.
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
    pub fn verify(self) -> Result<()> {
        let num_sets = self.sets.len();
        let num_chunks = std::cmp::max(1, num_sets / rayon::current_num_threads());
        let result: bool = self
            .sets
            .into_par_iter()
            .chunks(num_chunks)
            .map(|chunk| verify_signature_sets(chunk.into_iter()))
            .reduce(|| true, |current, this| current && this);

        if result {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

    /// Includes all signatures on the block (except the deposit signatures) for verification.
    pub fn include_all_signatures(
        &mut self,
        block: &'a SignedBeaconBlock<T>,
        block_root: Option<Hash256>,
    ) -> Result<()> {
        self.include_block_proposal(block, block_root)?;
        self.include_randao_reveal(block)?;
        self.include_proposer_slashings(block)?;
        self.include_attester_slashings(block)?;
        self.include_attestations(block)?;
        // Deposits are not included because they can legally have invalid signatures.
        self.include_exits(block)?;

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
            &block.message,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes all signatures in `self.block.body.proposer_slashings` for verification.
    pub fn include_proposer_slashings(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        let mut sets: Vec<SignatureSet> = block
            .message
            .body
            .proposer_slashings
            .iter()
            .map(|proposer_slashing| {
                let (set_1, set_2) = proposer_slashing_signature_set(
                    self.state,
                    self.get_pubkey.clone(),
                    proposer_slashing,
                    self.spec,
                )?;
                Ok(vec![set_1, set_2])
            })
            .collect::<SignatureSetResult<Vec<Vec<SignatureSet>>>>()?
            .into_iter()
            .flatten()
            .collect();

        self.sets.append(&mut sets);
        Ok(())
    }

    /// Includes all signatures in `self.block.body.attester_slashings` for verification.
    pub fn include_attester_slashings(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        block
            .message
            .body
            .attester_slashings
            .iter()
            .try_for_each(|attester_slashing| {
                let (set_1, set_2) = attester_slashing_signature_sets(
                    &self.state,
                    self.get_pubkey.clone(),
                    attester_slashing,
                    &self.spec,
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
        block
            .message
            .body
            .attestations
            .iter()
            .map(|attestation| {
                let committee = self
                    .state
                    .get_beacon_committee(attestation.data.slot, attestation.data.index)?;
                let indexed_attestation =
                    get_indexed_attestation(committee.committee, attestation)?;

                self.sets.push(indexed_attestation_signature_set(
                    &self.state,
                    self.get_pubkey.clone(),
                    &attestation.signature,
                    &indexed_attestation,
                    &self.spec,
                )?);

                Ok(indexed_attestation)
            })
            .collect::<Result<_>>()
            .map_err(Into::into)
    }

    /// Includes all signatures in `self.block.body.voluntary_exits` for verification.
    pub fn include_exits(&mut self, block: &'a SignedBeaconBlock<T>) -> Result<()> {
        let mut sets = block
            .message
            .body
            .voluntary_exits
            .iter()
            .map(|exit| exit_signature_set(&self.state, self.get_pubkey.clone(), exit, &self.spec))
            .collect::<SignatureSetResult<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }
}
