use std::sync::Arc;
use super::attestation::{
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
use super::block::SszBlock;
use super::db::{
    ClientDB,
    DBError,
};
use super::Logger;
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

pub enum BlockStatus {
    NewBlock,
    KnownBlock,
}

pub enum SszBlockValidationError {
    FutureSlot,
    UnknownPoWChainRef,
    BadAttestationSsz,
    AttestationValidationError(AttestationValidationError),
    InvalidAttestation,
    NoProposerSignature,
    BadProposerMap,
    DatabaseError(String),
}

#[allow(dead_code)]
pub fn validate_ssz_block<T>(b: &SszBlock,
                             expected_slot: u64,
                             pow_store: &PoWChainStore<T>,
                             cycle_length: u8,
                             last_justified_slot: u64,
                             parent_hashes: Arc<Vec<Hash256>>,
                             proposer_map: Arc<ProposerMap>,
                             attester_map: Arc<AttesterMap>,
                             block_store: Arc<BlockStore<T>>,
                             validator_store: Arc<ValidatorStore<T>>,
                             _log: &Logger)
    -> Result<BlockStatus, SszBlockValidationError>
    where T: ClientDB + Sized
{
    if block_store.block_exists(&b.block_hash())? {
        return Ok(BlockStatus::KnownBlock);
    }

    let block_slot = b.slot_number();
    if block_slot > expected_slot {
        return Err(SszBlockValidationError::FutureSlot);
    }

    if pow_store.block_hash_exists(b.pow_chain_ref())? == false {
        return Err(SszBlockValidationError::UnknownPoWChainRef);
    }

    let attestations_ssz = &b.attestations();

    let (first_attestation_ssz, next_index) = split_one_attestation(
        &attestations_ssz,
        0)?;
    let (first_attestation, _) = AttestationRecord::ssz_decode(
        &first_attestation_ssz, 0)?;

    let attestation_voters = validate_attestation(
        &first_attestation,
        block_slot,
        cycle_length,
        last_justified_slot,
        parent_hashes.clone(),
        block_store.clone(),
        validator_store.clone(),
        attester_map.clone())?;

    let attestation_voters = attestation_voters
        .ok_or(SszBlockValidationError::InvalidAttestation)?;

    let proposer = proposer_map.get(&block_slot)
        .ok_or(SszBlockValidationError::BadProposerMap)?;

    if !attestation_voters.contains(&proposer) {
        return Err(SszBlockValidationError::NoProposerSignature);
    }

    let other_attestations = split_all_attestations(attestations_ssz,
                                                    next_index)?;

    for attestation in other_attestations {
        let (a, _) = AttestationRecord::ssz_decode(&attestation, 0)?;
        let attestation_voters = validate_attestation(
            &a,
            block_slot,
            cycle_length,
            last_justified_slot,
            parent_hashes.clone(),
            block_store.clone(),
            validator_store.clone(),
            attester_map.clone())?;
        if attestation_voters.is_none() {
            return Err(SszBlockValidationError::InvalidAttestation);
        }
    }

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
