use super::AttestationRecord;
use super::attestation_parent_hashes::{
    attestation_parent_hashes,
    ParentHashesError,
};
use super::db::{
    ClientDB,
    DBError
};
use super::db::stores::{
    BlockStore,
    ValidatorStore,
};
use super::ssz::SszStream;
use super::bls::{
    AggregateSignature,
    AggregatePublicKey,
    PublicKey,
};
use super::utils::hash::canonical_hash;
use super::utils::types::{
    Hash256,
    Bitfield,
};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug,PartialEq)]
pub enum AttestationValidationError {
    SlotTooHigh,
    SlotTooLow,
    JustifiedSlotTooHigh,
    TooManyObliqueHashes,
    BadCurrentHashes,
    BadObliqueHashes,
    BadAttesterMap,
    IntWrapping,
    IncorrectBitField,
    NoSignatures,
    NonZeroTrailingBits,
    AggregateSignatureFail
}

type Slot = u64;
type ShardId = u64;
type AttesterMap = HashMap<(Slot, ShardId), Vec<usize>>;

fn bytes_for_bits(bits: usize) -> usize {
    (bits.saturating_sub(1) / 8) + 1
}

pub fn validate_attestation<T>(a: &AttestationRecord,
                               block_slot: u64,
                               cycle_length: u8,
                               known_last_justified_slot: u64,
                               known_parent_hashes: Arc<Vec<Hash256>>,
                               block_store: BlockStore<T>,
                               attester_map: Arc<AttesterMap>)
    -> Result<bool, AttestationValidationError>
    where T: ClientDB + Sized
{
    /*
     * The attesation slot must not be higher than the block that contained it.
     */
    if a.slot > block_slot {
        return Err(AttestationValidationError::SlotTooHigh);
    }

    /*
     * The slot of this attestation must not be more than cycle_length + 1 distance
     * from the block that contained it.
     *
     * The below code stays overflow-safe as long as cycle length is a < 64 bit integer.
     */
    if a.slot < block_slot.saturating_sub(u64::from(cycle_length) + 1) {
        return Err(AttestationValidationError::SlotTooLow);
    }

    /*
     * The attestation must indicate that its last justified slot is the same as the last justified
     * slot known to us.
     */
    if a.justified_slot > known_last_justified_slot {
        return Err(AttestationValidationError::JustifiedSlotTooHigh);
    }

    /*
     * There is no need to include more oblique parents hashes than there are blocks
     * in a cycle.
     */
    if a.oblique_parent_hashes.len() > usize::from(cycle_length) {
        return Err(AttestationValidationError::TooManyObliqueHashes);
    }

    let attestation_indices = attester_map.get(&(a.slot, a.shard_id.into()))
        .ok_or(AttestationValidationError::BadAttesterMap)?;

    if a.attester_bitfield.num_bytes() !=
        bytes_for_bits(attestation_indices.len())
    {
        return Err(AttestationValidationError::IncorrectBitField);
    }

    let signed_message = {
        let parent_hashes = attestation_parent_hashes(
            cycle_length,
            block_slot,
            a.slot,
            &known_parent_hashes,
            &a.oblique_parent_hashes)?;
        generate_signed_message(
            a.slot,
            &parent_hashes,
            a.shard_id,
            &a.shard_block_hash,
            a.justified_slot)
    };

    Ok(false)
}

fn collect_pub_keys(attestation_indices: &Vec<usize>,
                    bitfield: &Bitfield)
    -> Option<Vec<PublicKey>>
{
    // cats
    None
}

/// Generates the message used to validate the signature provided with an AttestationRecord.
///
/// Ensures that the signer of the message has a view of the chain that is compatible with ours.
fn generate_signed_message(slot: u64,
                           parent_hashes: &[Hash256],
                           shard_id: u16,
                           shard_block_hash: &Hash256,
                           justified_slot: u64)
    -> Vec<u8>
{
    /*
     * Note: it's a little risky here to use SSZ, because the encoding is not necessarily SSZ
     * (for example, SSZ might change whilst this doesn't).
     *
     * I have suggested switching this to ssz here:
     * https://github.com/ethereum/eth2.0-specs/issues/5
     *
     * If this doesn't happen, it would be safer to not use SSZ at all.
     */
    let mut ssz_stream = SszStream::new();
    ssz_stream.append(&slot);
    for h in parent_hashes {
        ssz_stream.append_encoded_raw(&h.to_vec())
    }
    ssz_stream.append(&shard_id);
    ssz_stream.append(shard_block_hash);
    ssz_stream.append(&justified_slot);
    let bytes = ssz_stream.drain();
    canonical_hash(&bytes)
}

impl From<ParentHashesError> for AttestationValidationError {
    fn from(e: ParentHashesError) -> Self {
        match e {
            ParentHashesError::BadCurrentHashes =>
                AttestationValidationError::BadCurrentHashes,
            ParentHashesError::BadObliqueHashes =>
                AttestationValidationError::BadObliqueHashes,
            ParentHashesError::SlotTooLow =>
                AttestationValidationError::SlotTooLow,
            ParentHashesError::SlotTooHigh =>
                AttestationValidationError::SlotTooHigh,
            ParentHashesError::IntWrapping =>
                AttestationValidationError::IntWrapping
        }
    }
}
