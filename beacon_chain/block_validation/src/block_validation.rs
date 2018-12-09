extern crate rayon;

use self::rayon::prelude::*;

use super::attestation_validation::{AttestationValidationContext, AttestationValidationError};
use super::db::stores::{BeaconBlockStore, PoWChainStore, ValidatorStore};
use super::db::{ClientDB, DBError};
use super::ssz::{Decodable, DecodeError};
use super::ssz_helpers::attestation_ssz_splitter::{
    split_all_attestations, split_one_attestation, AttestationSplitError,
};
use super::ssz_helpers::ssz_beacon_block::{SszBeaconBlock, SszBeaconBlockError};
use super::types::Hash256;
use super::types::{AttestationRecord, AttesterMap, BeaconBlock, ProposerMap};
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq)]
pub enum SszBeaconBlockValidationError {
    FutureSlot,
    SlotAlreadyFinalized,
    UnknownPoWChainRef,
    UnknownParentHash,
    BadAttestationSsz,
    BadAncestorHashesSsz,
    BadSpecialsSsz,
    ParentSlotHigherThanBlockSlot,
    AttestationValidationError(AttestationValidationError),
    AttestationSignatureFailed,
    ProposerAttestationHasObliqueHashes,
    NoProposerSignature,
    BadProposerMap,
    RwLockPoisoned,
    DBError(String),
}

/// The context against which a block should be validated.
pub struct BeaconBlockValidationContext<T>
where
    T: ClientDB + Sized,
{
    /// The slot as determined by the system time.
    pub present_slot: u64,
    /// The cycle_length as determined by the chain configuration.
    pub cycle_length: u8,
    /// The last justified slot as per the client's view of the canonical chain.
    pub last_justified_slot: u64,
    /// The last justified block hash as per the client's view of the canonical chain.
    pub last_justified_block_hash: Hash256,
    /// The last finalized slot as per the client's view of the canonical chain.
    pub last_finalized_slot: u64,
    /// A vec of the hashes of the blocks preceeding the present slot.
    pub recent_block_hashes: Arc<Vec<Hash256>>,
    /// A map of slots to a block proposer validation index.
    pub proposer_map: Arc<ProposerMap>,
    /// A map of (slot, shard_id) to the attestation set of validation indices.
    pub attester_map: Arc<AttesterMap>,
    /// The store containing block information.
    pub block_store: Arc<BeaconBlockStore<T>>,
    /// The store containing validator information.
    pub validator_store: Arc<ValidatorStore<T>>,
    /// The store containing information about the proof-of-work chain.
    pub pow_store: Arc<PoWChainStore<T>>,
}

impl<T> BeaconBlockValidationContext<T>
where
    T: ClientDB,
{
    /// Validate some SszBeaconBlock against a block validation context. An SszBeaconBlock varies from a BeaconBlock in
    /// that is a read-only structure that reads directly from encoded SSZ.
    ///
    /// The reason to validate an SzzBeaconBlock is to avoid decoding it in its entirety if there is
    /// a suspicion that the block might be invalid. Such a suspicion should be applied to
    /// all blocks coming from the network.
    ///
    /// This function will determine if the block is new, already known or invalid (either
    /// intrinsically or due to some application error.)
    ///
    /// Note: this function does not implement randao_reveal checking as it is not in the
    /// specification.
    #[allow(dead_code)]
    pub fn validate_ssz_block(
        &self,
        b: &SszBeaconBlock,
    ) -> Result<BeaconBlock, SszBeaconBlockValidationError>
    where
        T: ClientDB + Sized,
    {
        /*
         * If the block slot corresponds to a slot in the future, return immediately with an error.
         *
         * It is up to the calling fn to determine what should be done with "future" blocks (e.g.,
         * cache or discard).
         */
        let block_slot = b.slot();
        if block_slot > self.present_slot {
            return Err(SszBeaconBlockValidationError::FutureSlot);
        }

        /*
         * If the block is unknown (assumed unknown because we checked the db earlier in this
         * function) and it comes from a slot that is already finalized, drop the block.
         *
         * If a slot is finalized, there's no point in considering any other blocks for that slot.
         *
         * TODO: We can more strongly throw away blocks based on the `last_finalized_block` related
         * to this `last_finalized_slot`. Namely, any block in a future slot must include the
         * `last_finalized_block` in it's chain.
         */
        if block_slot <= self.last_finalized_slot {
            return Err(SszBeaconBlockValidationError::SlotAlreadyFinalized);
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
        let pow_chain_reference = b.pow_chain_reference();
        if !self.pow_store.block_hash_exists(b.pow_chain_reference())? {
            return Err(SszBeaconBlockValidationError::UnknownPoWChainRef);
        }

        /*
         * Store a slice of the serialized attestations from the block SSZ.
         */
        let attestations_ssz = &b.attestations_without_length();

        /*
         * Get a slice of the first serialized attestation (the 0'th) and decode it into
         * a full AttestationRecord object.
         *
         * The first attestation must be validated separately as it must contain a signature of the
         * proposer of the previous block (this is checked later in this function).
         */
        let (first_attestation_ssz, next_index) = split_one_attestation(&attestations_ssz, 0)?;
        let (first_attestation, _) = AttestationRecord::ssz_decode(&first_attestation_ssz, 0)?;

        /*
         * The first attestation may not have oblique hashes.
         *
         * The presence of oblique hashes in the first attestation would indicate that the proposer
         * of the previous block is attesting to some other block than the one they produced.
         */
        if !first_attestation.oblique_parent_hashes.is_empty() {
            return Err(SszBeaconBlockValidationError::ProposerAttestationHasObliqueHashes);
        }

        /*
         * Read the parent hash from the block we are validating then attempt to load
         * that parent block ssz from the database.
         *
         * If that parent doesn't exist in the database or is invalid, reject the block.
         *
         * Also, read the slot from the parent block for later use.
         */
        let parent_hash = b
            .parent_hash()
            .ok_or(SszBeaconBlockValidationError::BadAncestorHashesSsz)?;
        let parent_block_slot = match self.block_store.get_serialized_block(&parent_hash)? {
            None => return Err(SszBeaconBlockValidationError::UnknownParentHash),
            Some(ssz) => {
                let parent_block = SszBeaconBlock::from_slice(&ssz[..])?;
                parent_block.slot()
            }
        };

        /*
         * The parent block slot must be less than the block slot.
         *
         * In other words, the parent must come before the child.
         */
        if parent_block_slot >= block_slot {
            return Err(SszBeaconBlockValidationError::ParentSlotHigherThanBlockSlot);
        }

        /*
         * TODO: Validate the first attestation.
         */

        /*
         * Attempt to read load the parent block proposer from the proposer map. Return with an
         * error if it fails.
         *
         * If the signature of proposer for the parent slot was not present in the first (0'th)
         * attestation of this block, reject the block.
         */
        let parent_block_proposer = self
            .proposer_map
            .get(&parent_block_slot)
            .ok_or(SszBeaconBlockValidationError::BadProposerMap)?;
        if !attestation_voters.contains(&parent_block_proposer) {
            return Err(SszBeaconBlockValidationError::NoProposerSignature);
        }

        /*
         * Split the remaining attestations into a vector of slices, each containing
         * a single serialized attestation record.
         */
        let other_attestations = split_all_attestations(attestations_ssz, next_index)?;

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
        let failure: RwLock<Option<SszBeaconBlockValidationError>> = RwLock::new(None);
        let mut deserialized_attestations: Vec<AttestationRecord> = other_attestations
            .par_iter()
            .filter_map(|attestation_ssz| {
                /*
                 * If some thread has set the `failure` variable to `Some(error)` the abandon
                 * attestation serialization and validation. Also, fail early if the lock has been
                 * poisoned.
                 */
                match failure.read() {
                    Ok(ref option) if option.is_none() => (),
                    _ => return None,
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
                        /*
                         * If the failure lock isn't poisoned, set it to some error.
                         */
                        if let Ok(mut f) = failure.write() {
                            *f = Some(SszBeaconBlockValidationError::from(e));
                        }
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
                                /*
                                 * If the failure lock isn't poisoned, set it to some error.
                                 */
                                if let Ok(mut f) = failure.write() {
                                    *f = Some(SszBeaconBlockValidationError::from(e));
                                }
                                None
                            }
                            /*
                             * Attestation validation succeded.
                             */
                            Ok(_) => Some(attestation),
                        }
                    }
                }
            }).collect();

        match failure.into_inner() {
            Err(_) => return Err(SszBeaconBlockValidationError::RwLockPoisoned),
            Ok(failure) => match failure {
                Some(error) => return Err(error),
                _ => (),
            },
        }

        /*
         * Add the first attestation to the vec of deserialized attestations at
         * index 0.
         */
        deserialized_attestations.insert(0, first_attestation);

        let (ancestor_hashes, _) = Decodable::ssz_decode(&b.ancestor_hashes(), 0)
            .map_err(|_| SszBeaconBlockValidationError::BadAncestorHashesSsz)?;
        let (specials, _) = Decodable::ssz_decode(&b.specials(), 0)
            .map_err(|_| SszBeaconBlockValidationError::BadSpecialsSsz)?;

        /*
         * If we have reached this point, the block is a new valid block that is worthy of
         * processing.
         */
        let block = BeaconBlock {
            slot: block_slot,
            randao_reveal: Hash256::from(b.randao_reveal()),
            pow_chain_reference: Hash256::from(pow_chain_reference),
            ancestor_hashes,
            active_state_root: Hash256::from(b.act_state_root()),
            crystallized_state_root: Hash256::from(b.cry_state_root()),
            attestations: deserialized_attestations,
            specials,
        };
        Ok(block)
    }
}

impl From<DBError> for SszBeaconBlockValidationError {
    fn from(e: DBError) -> Self {
        SszBeaconBlockValidationError::DBError(e.message)
    }
}

impl From<AttestationSplitError> for SszBeaconBlockValidationError {
    fn from(e: AttestationSplitError) -> Self {
        match e {
            AttestationSplitError::TooShort => SszBeaconBlockValidationError::BadAttestationSsz,
        }
    }
}

impl From<SszBeaconBlockError> for SszBeaconBlockValidationError {
    fn from(e: SszBeaconBlockError) -> Self {
        match e {
            SszBeaconBlockError::TooShort => {
                SszBeaconBlockValidationError::DBError("Bad parent block in db.".to_string())
            }
            SszBeaconBlockError::TooLong => {
                SszBeaconBlockValidationError::DBError("Bad parent block in db.".to_string())
            }
        }
    }
}

impl From<DecodeError> for SszBeaconBlockValidationError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::TooShort => SszBeaconBlockValidationError::BadAttestationSsz,
            DecodeError::TooLong => SszBeaconBlockValidationError::BadAttestationSsz,
        }
    }
}

impl From<AttestationValidationError> for SszBeaconBlockValidationError {
    fn from(e: AttestationValidationError) -> Self {
        SszBeaconBlockValidationError::AttestationValidationError(e)
    }
}

/*
 * Tests for block validation are contained in the root directory "tests" directory (AKA
 * "integration tests directory").
 */
