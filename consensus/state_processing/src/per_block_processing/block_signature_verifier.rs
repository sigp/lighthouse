#![allow(clippy::arithmetic_side_effects)]

use super::signature_sets::{Error as SignatureSetError, *};
use crate::per_block_processing::errors::{AttestationInvalid, BlockOperationError};
use crate::{ConsensusContext, ContextError};
use bls::{verify_signature_sets, PublicKey, PublicKeyBytes, SignatureSet};
use std::borrow::Cow;
use types::{
    AbstractExecPayload, BeaconState, BeaconStateError, ChainSpec, EthSpec, Hash256,
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
    /// Error related to the consensus context, likely the proposer index or block root calc.
    ContextError(ContextError),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<ContextError> for Error {
    fn from(e: ContextError) -> Error {
        Error::ContextError(e)
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
pub struct BlockSignatureVerifier<'a, E, F, D>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    get_pubkey: F,
    decompressor: D,
    state: &'a BeaconState<E>,
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

impl<'a, E, F, D> BlockSignatureVerifier<'a, E, F, D>
where
    E: EthSpec,
    F: Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    D: Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
{
    /// Create a new verifier without any included signatures. See the `include...` functions to
    /// add signatures, and the `verify`
    pub fn new(
        state: &'a BeaconState<E>,
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
    ///   contains invalid signatures on deposits._
    ///
    /// See `Self::verify` for more detail.
    pub fn verify_entire_block<Payload: AbstractExecPayload<E>>(
        state: &'a BeaconState<E>,
        get_pubkey: F,
        decompressor: D,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, get_pubkey, decompressor, spec);
        verifier.include_all_signatures(block, ctxt)?;
        verifier.verify()
    }

    /// Includes all signatures on the block (except the deposit signatures) for verification.
    pub fn include_all_signatures<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        let block_root = Some(ctxt.get_current_block_root(block)?);
        let verified_proposer_index =
            Some(ctxt.get_proposer_index_from_epoch_state(self.state, self.spec)?);

        self.include_block_proposal(block, block_root, verified_proposer_index)?;
        self.include_all_signatures_except_proposal(block, ctxt)?;

        Ok(())
    }

    /// Includes all signatures on the block (except the deposit signatures and the proposal
    /// signature) for verification.
    pub fn include_all_signatures_except_proposal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        let verified_proposer_index =
            Some(ctxt.get_proposer_index_from_epoch_state(self.state, self.spec)?);
        self.include_randao_reveal(block, verified_proposer_index)?;
        self.include_proposer_slashings(block)?;
        self.include_attester_slashings(block)?;
        self.include_attestations(block, ctxt)?;
        // Deposits are not included because they can legally have invalid signatures.
        self.include_exits(block)?;
        self.include_sync_aggregate(block)?;
        self.include_bls_to_execution_changes(block)?;

        Ok(())
    }

    /// Includes the block signature for `self.block` for verification.
    pub fn include_block_proposal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        block_root: Option<Hash256>,
        verified_proposer_index: Option<u64>,
    ) -> Result<()> {
        let set = block_proposal_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block,
            block_root,
            verified_proposer_index,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes the randao signature for `self.block` for verification.
    pub fn include_randao_reveal<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        verified_proposer_index: Option<u64>,
    ) -> Result<()> {
        let set = randao_signature_set(
            self.state,
            self.get_pubkey.clone(),
            block.message(),
            verified_proposer_index,
            self.spec,
        )?;
        self.sets.push(set);
        Ok(())
    }

    /// Includes all signatures in `self.block.body.proposer_slashings` for verification.
    pub fn include_proposer_slashings<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
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
    pub fn include_attester_slashings<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().attester_slashings_len() * 2);

        block
            .message()
            .body()
            .attester_slashings()
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
    pub fn include_attestations<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
        ctxt: &mut ConsensusContext<E>,
    ) -> Result<()> {
        self.sets
            .sets
            .reserve(block.message().body().attestations_len());

        block
            .message()
            .body()
            .attestations()
            .try_for_each(|attestation| {
                let indexed_attestation =
                    ctxt.get_indexed_attestation(self.state, attestation, self.spec)?;

                self.sets.push(indexed_attestation_signature_set(
                    self.state,
                    self.get_pubkey.clone(),
                    attestation.signature(),
                    indexed_attestation,
                    self.spec,
                )?);
                Ok(())
            })
            .map_err(Error::into)
    }

    /// Includes all signatures in `self.block.body.voluntary_exits` for verification.
    pub fn include_exits<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
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
    pub fn include_sync_aggregate<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        if let Ok(sync_aggregate) = block.message().body().sync_aggregate() {
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

    /// Include the signature of the block's BLS to execution changes for verification.
    pub fn include_bls_to_execution_changes<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &'a SignedBeaconBlock<E, Payload>,
    ) -> Result<()> {
        // To improve performance we might want to decompress the withdrawal pubkeys in parallel.
        if let Ok(bls_to_execution_changes) = block.message().body().bls_to_execution_changes() {
            for bls_to_execution_change in bls_to_execution_changes {
                self.sets.push(bls_execution_change_signature_set(
                    self.state,
                    bls_to_execution_change,
                    self.spec,
                )?);
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
    /// Blst library spreads the signature verification work across multiple available cores, so
    /// this function is already parallelized.
    #[must_use]
    pub fn verify(self) -> bool {
        verify_signature_sets(self.sets.iter())
    }
}
