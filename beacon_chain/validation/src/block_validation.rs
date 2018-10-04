extern crate rayon;

use self::rayon::prelude::*;

use std::sync::{
    Arc,
    RwLock,
};
use super::attestation_validation::{
    AttestationValidationContext,
    AttestationValidationError,
};
use super::types::{
    AttestationRecord,
    AttesterMap,
    Block,
    ProposerMap,
};
use super::ssz_helpers::attestation_ssz_splitter::{
    split_one_attestation,
    split_all_attestations,
    AttestationSplitError,
};
use super::ssz_helpers::ssz_block::{
    SszBlock,
    SszBlockError,
};
use super::db::{
    ClientDB,
    DBError,
};
use super::db::stores::{
    BlockStore,
    PoWChainStore,
    ValidatorStore,
};
use super::ssz::{
    Decodable,
    DecodeError,
};
use super::types::Hash256;

#[derive(Debug, PartialEq)]
pub enum BlockStatus {
    NewBlock,
    KnownBlock,
}

#[derive(Debug, PartialEq)]
pub enum SszBlockValidationError {
    FutureSlot,
    SlotAlreadyFinalized,
    UnknownPoWChainRef,
    UnknownParentHash,
    BadAttestationSsz,
    AttestationValidationError(AttestationValidationError),
    AttestationSignatureFailed,
    ProposerAttestationHasObliqueHashes,
    NoProposerSignature,
    BadProposerMap,
    RwLockPoisoned,
    DBError(String),
}

/// The context against which a block should be validated.
pub struct BlockValidationContext<T>
    where T: ClientDB + Sized
{
    /// The slot as determined by the system time.
    pub present_slot: u64,
    /// The cycle_length as determined by the chain configuration.
    pub cycle_length: u8,
    /// The last justified slot as per the client's view of the canonical chain.
    pub last_justified_slot: u64,
    /// The last finalized slot as per the client's view of the canonical chain.
    pub last_finalized_slot: u64,
    /// A vec of the hashes of the blocks preceeding the present slot.
    pub parent_hashes: Arc<Vec<Hash256>>,
    /// A map of slots to a block proposer validation index.
    pub proposer_map: Arc<ProposerMap>,
    /// A map of (slot, shard_id) to the attestation set of validation indices.
    pub attester_map: Arc<AttesterMap>,
    /// The store containing block information.
    pub block_store: Arc<BlockStore<T>>,
    /// The store containing validator information.
    pub validator_store: Arc<ValidatorStore<T>>,
    /// The store containing information about the proof-of-work chain.
    pub pow_store: Arc<PoWChainStore<T>>,
}

impl<T> BlockValidationContext<T>
    where T: ClientDB
{
    /// Validate some SszBlock against a block validation context. An SszBlock varies from a Block in
    /// that is a read-only structure that reads directly from encoded SSZ.
    ///
    /// The reason to validate an SzzBlock is to avoid decoding it in its entirety if there is
    /// a suspicion that the block might be invalid. Such a suspicion should be applied to
    /// all blocks coming from the network.
    ///
    /// This function will determine if the block is new, already known or invalid (either
    /// intrinsically or due to some application error.)
    ///
    /// Note: this function does not implement randao_reveal checking as it is not in the
    /// specification.
    #[allow(dead_code)]
    pub fn validate_ssz_block(&self, b: &SszBlock)
        -> Result<(BlockStatus, Option<Block>), SszBlockValidationError>
        where T: ClientDB + Sized
    {

        /*
         * If this block is already known, return immediately and indicate the the block is
         * known. Don't attempt to deserialize the block.
         */
        let block_hash = &b.block_hash();
        if self.block_store.block_exists(&block_hash)? {
            return Ok((BlockStatus::KnownBlock, None));
        }

        /*
         * If the block slot corresponds to a slot in the future, return immediately with an error.
         *
         * It is up to the calling fn to determine what should be done with "future" blocks (e.g.,
         * cache or discard).
         */
        let block_slot = b.slot_number();
        if block_slot > self.present_slot {
            return Err(SszBlockValidationError::FutureSlot);
        }

        /*
         * If the block is unknown (assumed unknown because we checked the db earlier in this
         * function) and it comes from a slot that is already finalized, drop the block.
         *
         * If a slot is finalized, there's no point in considering any other blocks for that slot.
         */
        if block_slot <= self.last_finalized_slot {
            return Err(SszBlockValidationError::SlotAlreadyFinalized);
        }

        /*
         * If the PoW chain hash is not known to us, drop it.
         *
         * We only accept blocks that reference a known PoW hash.
         *
         * Note: it is not clear what a "known" PoW chain ref is. Likely it means the block hash is
         * "sufficienty deep in the canonical PoW chain". This should be clarified as the spec
         * crystallizes.
         */
        let pow_chain_ref = b.pow_chain_ref();
        if !self.pow_store.block_hash_exists(b.pow_chain_ref())? {
            return Err(SszBlockValidationError::UnknownPoWChainRef);
        }

        /*
         * Store a slice of the serialized attestations from the block SSZ.
         */
        let attestations_ssz = &b.attestations();

        /*
         * Get a slice of the first serialized attestation (the 0'th) and decode it into
         * a full AttestationRecord object.
         *
         * The first attestation must be validated separately as it must contain a signature of the
         * proposer of the previous block (this is checked later in this function).
         */
        let (first_attestation_ssz, next_index) = split_one_attestation(
            &attestations_ssz,
            0)?;
        let (first_attestation, _) = AttestationRecord::ssz_decode(
            &first_attestation_ssz, 0)?;

        /*
         * The first attestation may not have oblique hashes.
         *
         * The presence of oblique hashes in the first attestation would indicate that the proposer
         * of the previous block is attesting to some other block than the one they produced.
         */
        if first_attestation.oblique_parent_hashes.len() > 0 {
            return Err(SszBlockValidationError::ProposerAttestationHasObliqueHashes);
        }

        /*
         * Read the parent hash from the block we are validating then attempt to load
         * that parent block ssz from the database.
         *
         * If that parent doesn't exist in the database or is invalid, reject the block.
         *
         * Also, read the slot from the parent block for later use.
         */
        let parent_hash = b.parent_hash();
        let parent_slot = match self.block_store.get_serialized_block(&parent_hash)? {
            None => return Err(SszBlockValidationError::UnknownParentHash),
            Some(ssz) => {
                let parent_block = SszBlock::from_slice(&ssz[..])?;
                parent_block.slot_number()
            }
        };

        /*
         * Generate the context in which attestations will be validated.
         */
        let attestation_validation_context = Arc::new(AttestationValidationContext {
            block_slot,
            cycle_length: self.cycle_length,
            last_justified_slot: self.last_justified_slot,
            parent_hashes: self.parent_hashes.clone(),
            block_store: self.block_store.clone(),
            validator_store: self.validator_store.clone(),
            attester_map: self.attester_map.clone(),
        });

        /*
         * Validate this first attestation.
         */
        let attestation_voters = attestation_validation_context
            .validate_attestation(&first_attestation)?;

        /*
         * Attempt to read load the parent block proposer from the proposer map. Return with an
         * error if it fails.
         *
         * If the signature of proposer for the parent slot was not present in the first (0'th)
         * attestation of this block, reject the block.
         */
        let parent_block_proposer = self.proposer_map.get(&parent_slot)
            .ok_or(SszBlockValidationError::BadProposerMap)?;
        if !attestation_voters.contains(&parent_block_proposer) {
            return Err(SszBlockValidationError::NoProposerSignature);
        }

        /*
         * Split the remaining attestations into a vector of slices, each containing
         * a single serialized attestation record.
         */
        let other_attestations = split_all_attestations(attestations_ssz,
                                                        next_index)?;

        /*
         * Verify each other AttestationRecord.
         *
         * This uses the `rayon` library to do "sometimes" parallelization. Put simply,
         * if there are some spare threads, the verification of attestation records will happen
         * concurrently.
         *
         * There is a thread-safe `failure` variable which is set whenever an attestation fails
         * validation. This is so all attestation validation is halted if a single bad attestation
         * is found.
         */
        let failure: RwLock<Option<SszBlockValidationError>> = RwLock::new(None);
        let mut deserialized_attestations: Vec<AttestationRecord> = other_attestations
            .par_iter()
            .filter_map(|attestation_ssz| {
                /*
                 * If some thread has set the `failure` variable to `Some(error)` the abandon
                 * attestation serialization and validation.
                 */
                if let Some(_) = *failure.read().unwrap() {
                    return None;
                }
                /*
                 * If there has not been a failure yet, attempt to serialize and validate the
                 * attestation.
                 */
                match AttestationRecord::ssz_decode(&attestation_ssz, 0) {
                    /*
                     * Deserialization failed, therefore the block is invalid.
                     */
                    Err(e) => {
                        let mut failure = failure.write().unwrap();
                        *failure = Some(SszBlockValidationError::from(e));
                        None
                    }
                    /*
                     * Deserialization succeeded and the attestation should be validated.
                     */
                    Ok((attestation, _)) => {
                        match attestation_validation_context.validate_attestation(&attestation) {
                            /*
                             * Attestation validation failed with some error.
                             */
                            Err(e) => {
                                let mut failure = failure.write().unwrap();
                                *failure = Some(SszBlockValidationError::from(e));
                                None
                            }
                            /*
                             * Attestation validation succeded.
                             */
                            Ok(_) => Some(attestation)
                        }
                    }
                }
            })
            .collect();

        match failure.into_inner() {
            Err(_) => return Err(SszBlockValidationError::RwLockPoisoned),
            Ok(failure) => {
                match failure {
                    Some(error) => return Err(error),
                    _ => ()
                }

            }
        }

        /*
         * Add the first attestation to the vec of deserialized attestations at
         * index 0.
         */
        deserialized_attestations.insert(0, first_attestation);

        /*
         * If we have reached this point, the block is a new valid block that is worthy of
         * processing.
         */
        let block = Block {
            parent_hash: Hash256::from(parent_hash),
            slot_number: block_slot,
            randao_reveal: Hash256::from(b.randao_reveal()),
            attestations: deserialized_attestations,
            pow_chain_ref: Hash256::from(pow_chain_ref),
            active_state_root: Hash256::from(b.act_state_root()),
            crystallized_state_root: Hash256::from(b.cry_state_root()),
        };
        Ok((BlockStatus::NewBlock, Some(block)))
    }
}

impl From<DBError> for SszBlockValidationError {
    fn from(e: DBError) -> Self {
        SszBlockValidationError::DBError(e.message)
    }
}

impl From<AttestationSplitError> for SszBlockValidationError {
    fn from(e: AttestationSplitError) -> Self {
        match e {
            AttestationSplitError::TooShort =>
                SszBlockValidationError::BadAttestationSsz
        }
    }
}

impl From<SszBlockError> for SszBlockValidationError {
    fn from(e: SszBlockError) -> Self {
        match e {
            SszBlockError::TooShort =>
                SszBlockValidationError::DBError("Bad parent block in db.".to_string()),
            SszBlockError::TooLong =>
                SszBlockValidationError::DBError("Bad parent block in db.".to_string()),
        }
    }
}

impl From<DecodeError> for SszBlockValidationError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::TooShort =>
                SszBlockValidationError::BadAttestationSsz,
            DecodeError::TooLong =>
                SszBlockValidationError::BadAttestationSsz,
        }
    }
}

impl From<AttestationValidationError> for SszBlockValidationError {
    fn from(e: AttestationValidationError) -> Self {
        SszBlockValidationError::AttestationValidationError(e)
    }
}

/*
 * Tests for block validation are contained in the root directory "tests" directory (AKA
 * "integration tests directory").
 */
