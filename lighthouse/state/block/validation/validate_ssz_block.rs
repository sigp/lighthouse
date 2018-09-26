use std::sync::Arc;
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
use super::SszBlock;
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
    NewBlock,
    KnownBlock,
}

#[derive(Debug, PartialEq)]
pub enum SszBlockValidationError {
    FutureSlot,
    UnknownPoWChainRef,
    BadAttestationSsz,
    AttestationValidationError(AttestationValidationError),
    AttestationSignatureFailed,
    FirstAttestationSignatureFailed,
    NoProposerSignature,
    BadProposerMap,
    DatabaseError(String),
}

/// Validate some SszBlock. An SszBlock varies from a Block in that is a read-only structure
/// that reads directly from encoded SSZ.
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
#[allow(dead_code)]
pub fn validate_ssz_block<T>(b: &SszBlock,
                             expected_slot: u64,
                             cycle_length: u8,
                             last_justified_slot: u64,
                             parent_hashes: &Arc<Vec<Hash256>>,
                             proposer_map: &Arc<ProposerMap>,
                             attester_map: &Arc<AttesterMap>,
                             block_store: &Arc<BlockStore<T>>,
                             validator_store: &Arc<ValidatorStore<T>>,
                             pow_store: &Arc<PoWChainStore<T>>)
    -> Result<BlockStatus, SszBlockValidationError>
    where T: ClientDB + Sized
{
    /*
     * If this block is already known, return immediately.
     */
    if block_store.block_exists(&b.block_hash())? {
        return Ok(BlockStatus::KnownBlock);
    }

    /*
     * Copy the block slot (will be used multiple times)
     */
    let block_slot = b.slot_number();

    /*
     * If the block slot corresponds to a slot in the future (according to the local time),
     * drop it.
     */
    if block_slot > expected_slot {
        return Err(SszBlockValidationError::FutureSlot);
    }

    /*
     * If the PoW chain hash is not known to us, drop it.
     *
     * We only accept blocks that reference a known PoW hash.
     *
     * Note: it is not clear what a "known" PoW chain ref is. Likely,
     * it means "sufficienty deep in the canonical PoW chain".
     */
    if !pow_store.block_hash_exists(b.pow_chain_ref())? {
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
        cycle_length,
        last_justified_slot,
        &parent_hashes,
        &block_store,
        &validator_store,
        &attester_map)?;

    /*
     * If the set of voters is None, the attestation was invalid.
     */
    let attestation_voters = attestation_voters
        .ok_or(SszBlockValidationError::
               FirstAttestationSignatureFailed)?;

    /*
     * Read the proposer from the map of slot -> validator index.
     */
    let proposer = proposer_map.get(&block_slot)
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
     * TODO: make this parallelized.
     */
    for attestation in other_attestations {
        let (a, _) = AttestationRecord::ssz_decode(&attestation, 0)?;
        let attestation_voters = validate_attestation(
            &a,
            block_slot,
            cycle_length,
            last_justified_slot,
            &parent_hashes,
            &block_store,
            &validator_store,
            &attester_map)?;
        if attestation_voters.is_none() {
            return Err(SszBlockValidationError::
                       AttestationSignatureFailed);
        }
    }

    /*
     * If we have reached this point, the block is a new valid block that is worthy of
     * processing.
     */
    Ok(BlockStatus::NewBlock)
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
