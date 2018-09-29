extern crate rayon;
use self::rayon::prelude::*;

use std::sync::{
    Arc,
    RwLock,
};
use super::attestation_record::{
    validate_attestation,
    AttestationValidationError,
};
use super::attestation_record::{
    AttestationRecord,
    split_one_attestation,
    split_all_attestations,
    AttestationSplitError,
};
use super::{
    AttesterMap,
    ProposerMap,
};
use super::{
    SszBlock,
    Block,
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
use super::utils::types::Hash256;

#[derive(Debug, PartialEq)]
pub enum BlockStatus {
    NewBlockInCanonicalChain,
    NewBlockInForkChain,
    KnownBlock,
}

#[derive(Debug, PartialEq)]
pub enum SszBlockValidationError {
    FutureSlot,
    UnknownPoWChainRef,
    UnknownParentHash,
    BadAttestationSsz,
    AttestationValidationError(AttestationValidationError),
    AttestationSignatureFailed,
    FirstAttestationSignatureFailed,
    NoProposerSignature,
    BadProposerMap,
    RwLockPoisoned,
    DatabaseError(String),
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
    /// Of course, this function will only be more efficient if a block is already serialized.
    /// Serializing a complete block and then validating with this function will be less
    /// efficient than just validating the original block.
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
         * If the block slot corresponds to a slot in the future (according to the local time),
         * drop it.
         */
        let block_slot = b.slot_number();
        if block_slot > self.present_slot {
            return Err(SszBlockValidationError::FutureSlot);
        }

        /*
         * If this block is already known, return immediately.
         */
        let block_hash = &b.block_hash();
        if self.block_store.block_exists(&block_hash)? {
            return Ok((BlockStatus::KnownBlock, None));
        }


        /*
         * If the PoW chain hash is not known to us, drop it.
         *
         * We only accept blocks that reference a known PoW hash.
         *
         * Note: it is not clear what a "known" PoW chain ref is. Likely,
         * it means "sufficienty deep in the canonical PoW chain".
         */
        let pow_chain_ref = b.pow_chain_ref();
        if !self.pow_store.block_hash_exists(b.pow_chain_ref())? {
            return Err(SszBlockValidationError::UnknownPoWChainRef);
        }

        /*
         * Store a reference to the serialized attestations from the block.
         */
        let attestations_ssz = &b.attestations();

        /*
         * Get a slice of the first serialized attestation (the 0th) and decode it into
         * a full AttestationRecord object.
         */
        let (first_attestation_ssz, next_index) = split_one_attestation(
            &attestations_ssz,
            0)?;
        let (first_attestation, _) = AttestationRecord::ssz_decode(
            &first_attestation_ssz, 0)?;

        /*
         * Validate this first attestation.
         *
         * It is a requirement that the block proposer for this slot
         * must have signed the 0th attestation record.
         */
        let attestation_voters = validate_attestation(
            &first_attestation,
            block_slot,
            self.cycle_length,
            self.last_justified_slot,
            &self.parent_hashes,
            &self.block_store,
            &self.validator_store,
            &self.attester_map)?;

        /*
         * If the set of voters is None, the attestation was invalid.
         */
        let attestation_voters = attestation_voters
            .ok_or(SszBlockValidationError::
                   FirstAttestationSignatureFailed)?;

        /*
         * Read the proposer from the map of slot -> validator index.
         */
        let proposer = self.proposer_map.get(&block_slot)
            .ok_or(SszBlockValidationError::BadProposerMap)?;

        /*
         * If the proposer for this slot was not a voter, reject the block.
         */
        if !attestation_voters.contains(&proposer) {
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
        let deserialized_attestations: Vec<AttestationRecord> = other_attestations
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
                        let result = validate_attestation(
                            &attestation,
                            block_slot,
                            self.cycle_length,
                            self.last_justified_slot,
                            &self.parent_hashes,
                            &self.block_store,
                            &self.validator_store,
                            &self.attester_map);
                        match result {
                            /*
                             * Attestation validation failed with some error.
                             */
                            Err(e) => {
                                let mut failure = failure.write().unwrap();
                                *failure = Some(SszBlockValidationError::from(e));
                                None
                            }
                            /*
                             * Attestation validation failed due to a bad signature.
                             */
                            Ok(None) => {
                                let mut failure = failure.write().unwrap();
                                *failure = Some(SszBlockValidationError::AttestationSignatureFailed);
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
         * If we have reached this point, the block is a new valid block that is worthy of
         * processing.
         */

        /*
         * If the block's parent_hash _is_ in the canonical chain, the block is a
         * new block in the canonical chain. Otherwise, it's a new block in a fork chain.
         */
        let parent_hash = b.parent_hash();
        let status = if self.block_store.block_exists_in_canonical_chain(&parent_hash)? {
            BlockStatus::NewBlockInCanonicalChain
        } else {
            BlockStatus::NewBlockInForkChain
        };
        let block = Block {
            parent_hash: Hash256::from(parent_hash),
            slot_number: block_slot,
            randao_reveal: Hash256::from(b.randao_reveal()),
            attestations: deserialized_attestations,
            pow_chain_ref: Hash256::from(pow_chain_ref),
            active_state_root: Hash256::from(b.act_state_root()),
            crystallized_state_root: Hash256::from(b.cry_state_root()),
        };
        Ok((status, Some(block)))
    }
}

impl From<DBError> for SszBlockValidationError {
    fn from(e: DBError) -> Self {
        SszBlockValidationError::DatabaseError(e.message)
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
