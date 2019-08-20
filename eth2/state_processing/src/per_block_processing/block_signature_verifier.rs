use super::signature_sets::{Error as SignatureSetError, Result as SignatureSetResult, *};
use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::{AttestationInvalid, BlockOperationError};
use bls::{verify_signature_sets, SignatureSet};
use rayon::prelude::*;
use types::{BeaconBlock, BeaconState, BeaconStateError, ChainSpec, EthSpec, IndexedAttestation};

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
    /// Failed to load a signature set. The block may been invalid, or we failed to process it.
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

/// Reads the BLS signatures and keys from a `BeaconBlock`, storing them as a `Vec<SignatureSet>`.
///
/// This allows for optimizations related to batch BLS operations (see the
/// `Self::verify_entire_block(..)` function).
pub struct BlockSignatureVerifier<'a, T: EthSpec> {
    block: &'a BeaconBlock<T>,
    state: &'a BeaconState<T>,
    spec: &'a ChainSpec,
    sets: Vec<SignatureSet<'a>>,
}

impl<'a, T: EthSpec> BlockSignatureVerifier<'a, T> {
    fn new(state: &'a BeaconState<T>, block: &'a BeaconBlock<T>, spec: &'a ChainSpec) -> Self {
        Self {
            block,
            state,
            spec,
            sets: vec![],
        }
    }

    /// Verify all* the signatures in the given `BeaconBlock`, returning `Ok(())` if the signatures
    /// are valid.
    ///
    /// * : _Does not verify any signatures in `block.body.deposits`. A block is still valid if it
    /// contains invalid signatures on deposits._
    ///
    /// ## Notes
    ///
    /// Signature validation will take place in accordance to the [Faster verification of multiple
    /// BLS signatures](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)
    /// optimization proposed by Vitalik Buterin.
    ///
    /// It is not possible to know exactly _which_ signature is invalid here, just that
    /// _at least one_ was invalid.
    pub fn verify_entire_block(
        state: &'a BeaconState<T>,
        block: &'a BeaconBlock<T>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, block, spec);

        verifier.include_block_proposal()?;
        verifier.include_randao_reveal()?;
        verifier.include_proposer_slashings()?;
        verifier.include_attester_slashings()?;
        verifier.include_attestations()?;
        /*
         * Deposits are not included because they can legally have invalid signatures.
         */
        verifier.include_exits()?;
        verifier.include_transfers()?;

        let num_sets = verifier.sets.len();
        let result: bool = verifier
            .sets
            .into_par_iter()
            .chunks(num_sets / rayon::current_num_threads())
            .map(|chunk| verify_signature_sets(chunk.into_iter()))
            .reduce(|| true, |current, this| current && this);

        if result {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

    fn include_block_proposal(&mut self) -> Result<()> {
        let set = block_proposal_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    fn include_randao_reveal(&mut self) -> Result<()> {
        let set = randao_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    fn include_proposer_slashings(&mut self) -> Result<()> {
        let mut sets: Vec<SignatureSet> = self
            .block
            .body
            .proposer_slashings
            .iter()
            .map(|proposer_slashing| {
                let (set_1, set_2) =
                    proposer_slashing_signature_set(self.state, proposer_slashing, self.spec)?;
                Ok(vec![set_1, set_2])
            })
            .collect::<SignatureSetResult<Vec<Vec<SignatureSet>>>>()?
            .iter()
            .flatten()
            .cloned()
            .collect();

        self.sets.append(&mut sets);
        Ok(())
    }

    fn include_attester_slashings(&mut self) -> Result<()> {
        self.block
            .body
            .attester_slashings
            .iter()
            .try_for_each(|attester_slashing| {
                let (set_1, set_2) =
                    attester_slashing_signature_sets(&self.state, attester_slashing, &self.spec)?;

                self.sets.push(set_1);
                self.sets.push(set_2);

                Ok(())
            })
    }

    fn include_attestations(&mut self) -> Result<Vec<IndexedAttestation<T>>> {
        self.block
            .body
            .attestations
            .iter()
            .map(|attestation| {
                let indexed_attestation = get_indexed_attestation(self.state, attestation)?;

                self.sets.push(indexed_attestation_signature_set(
                    &self.state,
                    &attestation.signature,
                    &indexed_attestation,
                    &self.spec,
                )?);

                Ok(indexed_attestation)
            })
            .collect::<Result<_>>()
            .map_err(Into::into)
    }

    fn include_exits(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .voluntary_exits
            .iter()
            .map(|exit| exit_signature_set(&self.state, exit, &self.spec))
            .collect::<SignatureSetResult<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    fn include_transfers(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .transfers
            .iter()
            .map(|transfer| transfer_signature_set(&self.state, transfer, &self.spec))
            .collect::<SignatureSetResult<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }
}
