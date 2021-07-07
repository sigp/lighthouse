use errors::{BlockOperationError, BlockProcessingError, HeaderInvalid};
use safe_arith::{ArithError, SafeArith};
use signature_sets::{block_proposal_signature_set, get_pubkey_from_state, randao_signature_set};
use tree_hash::TreeHash;
use types::*;

pub use self::verify_attester_slashing::{
    get_slashable_indices, get_slashable_indices_modular, verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use altair::sync_committee::process_sync_aggregate;
pub use block_signature_verifier::BlockSignatureVerifier;
pub use is_valid_indexed_attestation::is_valid_indexed_attestation;
pub use process_operations::process_operations;
pub use verify_attestation::{
    verify_attestation_for_block_inclusion, verify_attestation_for_state,
};
pub use verify_deposit::{
    get_existing_validator_index, verify_deposit_merkle_proof, verify_deposit_signature,
};
pub use verify_exit::{verify_exit, verify_exit_time_independent_only};

pub mod altair;
pub mod block_signature_verifier;
pub mod errors;
mod is_valid_indexed_attestation;
pub mod process_operations;
pub mod signature_sets;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;

#[cfg(feature = "arbitrary-fuzz")]
use arbitrary::Arbitrary;

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum BlockSignatureStrategy {
    /// Do not validate any signature. Use with caution.
    NoVerification,
    /// Validate each signature individually, as its object is being processed.
    VerifyIndividual,
    /// Verify all signatures in bulk at the beginning of block processing.
    VerifyBulk,
}

pub struct VerificationStrategy {
    /// Verification to apply to signatures.
    signatures: BlockSignatureStrategy,
    /// Whether to verify the proposer index, or trust the index in the block.
    proposer_index: bool,
    /// Whether to verify the parent block root against the state's latest block header.
    parent_block_root: bool,
    /// Whether to verify the merkle proofs for deposits, or assume their validity.
    deposit_merkle_proofs: bool,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        VerificationStrategy {
            signatures: BlockSignatureStrategy::VerifyIndividual,
            proposer_index: true,
            parent_block_root: true,
            deposit_merkle_proofs: true,
        }
    }
}

impl VerificationStrategy {
    pub fn bulk_signatures() -> Self {
        Self {
            signatures: BlockSignatureStrategy::VerifyBulk,
            ..Self::default()
        }
    }

    pub fn individual_signatures() -> Self {
        Self {
            signatures: BlockSignatureStrategy::VerifyIndividual,
            ..Self::default()
        }
    }

    pub fn no_signatures() -> Self {
        Self {
            signatures: BlockSignatureStrategy::NoVerification,
            ..Self::default()
        }
    }

    /// XXX: dangerous function to disable the maximum number of block verifications.
    ///
    /// This should *only* be used for blocks that have already been fully verified, e.g.
    /// ones read from the database.
    pub fn no_verification() -> Self {
        Self {
            signatures: BlockSignatureStrategy::NoVerification,
            proposer_index: false,
            parent_block_root: false,
            deposit_merkle_proofs: false,
        }
    }

    pub fn verify_sigs(&self) -> VerifySignatures {
        match self.signatures {
            BlockSignatureStrategy::VerifyBulk | BlockSignatureStrategy::NoVerification => {
                VerifySignatures::False
            }
            BlockSignatureStrategy::VerifyIndividual => VerifySignatures::True,
        }
    }
}

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifySignatures {
    /// Validate all signatures encountered.
    True,
    /// Do not validate any signature. Use with caution.
    False,
}

impl VerifySignatures {
    pub fn is_true(self) -> bool {
        self == VerifySignatures::True
    }
}

/// Updates the state for a new block, whilst validating that the block is valid, optionally
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// If `block_root` is `Some`, this root is used for verification of the proposer's signature. If it
/// is `None` the signing root is computed from scratch. This parameter only exists to avoid
/// re-calculating the root when it is already known. Note `block_root` should be equal to the
/// tree hash root of the block, NOT the signing root of the block. This function takes
/// care of mixing in the domain.
pub fn per_block_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    signed_block: &SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    verification: VerificationStrategy,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let block = signed_block.message();

    // Verify that the `SignedBeaconBlock` instantiation matches the fork at `signed_block.slot()`.
    signed_block
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentBlockFork)?;

    // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    state
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentStateFork)?;

    if let BlockSignatureStrategy::VerifyBulk = verification.signatures {
        // Verify all signatures in the block at once.
        block_verify!(
            BlockSignatureVerifier::verify_entire_block(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_block,
                block_root,
                spec
            )
            .is_ok(),
            BlockProcessingError::BulkSignatureVerificationFailed
        );
    }
    let verify_signatures = verification.verify_sigs();

    let proposer_index = process_block_header(state, block, &verification, spec)?;

    if verify_signatures.is_true() {
        verify_block_signature(state, signed_block, block_root, spec)?;
    }

    // Ensure the current and previous epoch caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    process_randao(state, block, verify_signatures, spec)?;
    process_eth1_data(state, block.body().eth1_data())?;
    process_operations(state, block.body(), proposer_index, &verification, spec)?;

    if let BeaconBlockRef::Altair(inner) = block {
        process_sync_aggregate(state, &inner.body.sync_aggregate, proposer_index, spec)?;
    }

    Ok(())
}

/// Processes the block header, returning the proposer index.
pub fn process_block_header<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: BeaconBlockRef<'_, T>,
    verification: &VerificationStrategy,
    spec: &ChainSpec,
) -> Result<u64, BlockOperationError<HeaderInvalid>> {
    // Verify that the slots match
    verify!(
        block.slot() == state.slot(),
        HeaderInvalid::StateSlotMismatch
    );

    // Verify that the block is newer than the latest block header
    verify!(
        block.slot() > state.latest_block_header().slot,
        HeaderInvalid::OlderThanLatestBlockHeader {
            block_slot: block.slot(),
            latest_block_header_slot: state.latest_block_header().slot,
        }
    );

    // Verify that proposer index is the correct index
    let proposer_index = block.proposer_index() as usize;
    if verification.proposer_index {
        let state_proposer_index = state.get_beacon_proposer_index(block.slot(), spec)?;
        verify!(
            proposer_index == state_proposer_index,
            HeaderInvalid::ProposerIndexMismatch {
                block_proposer_index: proposer_index,
                state_proposer_index,
            }
        );
    }

    if verification.parent_block_root {
        let expected_previous_block_root = state.latest_block_header().tree_hash_root();
        verify!(
            block.parent_root() == expected_previous_block_root,
            HeaderInvalid::ParentBlockRootMismatch {
                state: expected_previous_block_root,
                block: block.parent_root(),
            }
        );
    }

    *state.latest_block_header_mut() = block.temporary_block_header();

    // Verify proposer is not slashed
    verify!(
        !state.get_validator(proposer_index)?.slashed,
        HeaderInvalid::ProposerSlashed(proposer_index)
    );

    Ok(block.proposer_index())
}

/// Verifies the signature of a block.
///
/// Spec v0.12.1
pub fn verify_block_signature<T: EthSpec>(
    state: &BeaconState<T>,
    block: &SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    verify!(
        block_proposal_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            block,
            block_root,
            spec
        )?
        .verify(),
        HeaderInvalid::ProposalSignatureInvalid
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
pub fn process_randao<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: BeaconBlockRef<'_, T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if verify_signatures.is_true() {
        // Verify RANDAO reveal signature.
        block_verify!(
            randao_signature_set(state, |i| get_pubkey_from_state(state, i), block, spec)?.verify(),
            BlockProcessingError::RandaoSignatureInvalid
        );
    }

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(), block.body().randao_reveal())?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
pub fn process_eth1_data<T: EthSpec>(
    state: &mut BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<(), Error> {
    if let Some(new_eth1_data) = get_new_eth1_data(state, eth1_data)? {
        *state.eth1_data_mut() = new_eth1_data;
    }

    state.eth1_data_votes_mut().push(eth1_data.clone())?;

    Ok(())
}

/// Returns `Ok(Some(eth1_data))` if adding the given `eth1_data` to `state.eth1_data_votes` would
/// result in a change to `state.eth1_data`.
pub fn get_new_eth1_data<T: EthSpec>(
    state: &BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<Option<Eth1Data>, ArithError> {
    let num_votes = state
        .eth1_data_votes()
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count();

    // The +1 is to account for the `eth1_data` supplied to the function.
    if num_votes.safe_add(1)?.safe_mul(2)? > T::SlotsPerEth1VotingPeriod::to_usize() {
        Ok(Some(eth1_data.clone()))
    } else {
        Ok(None)
    }
}
