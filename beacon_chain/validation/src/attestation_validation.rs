use std::collections::HashSet;
use std::sync::Arc;
use super::types::{
    AttestationRecord,
    AttesterMap,
};
use super::attestation_parent_hashes::{
    attestation_parent_hashes,
    ParentHashesError,
};
use super::db::{
    ClientDB,
    DBError
};
use super::db::stores::{
    BeaconBlockStore,
    BeaconBlockAtSlotError,
    ValidatorStore,
};
use super::types::{
    Hash256,
};
use super::message_generation::generate_signed_message;
use super::signature_verification::{
    verify_aggregate_signature_for_indices,
    SignatureVerificationError,
};

#[derive(Debug,PartialEq)]
pub enum AttestationValidationError {
    ParentSlotTooHigh,
    BlockSlotTooHigh,
    BlockSlotTooLow,
    JustifiedSlotIncorrect,
    InvalidJustifiedBlockHash,
    TooManyObliqueHashes,
    BadCurrentHashes,
    BadObliqueHashes,
    BadAttesterMap,
    IntWrapping,
    PublicKeyCorrupt,
    NoPublicKeyForValidator,
    BadBitfieldLength,
    InvalidBitfield,
    InvalidBitfieldEndBits,
    NoSignatures,
    NonZeroTrailingBits,
    BadAggregateSignature,
    DBError(String),
}

/// The context against which some attestation should be validated.
pub struct AttestationValidationContext<T>
    where T: ClientDB + Sized
{
    /// The slot as determined by the system time.
    pub block_slot: u64,
    /// The slot of the parent of the block that contained this attestation.
    pub parent_block_slot: u64,
    /// The cycle_length as determined by the chain configuration.
    pub cycle_length: u8,
    /// The last justified slot as per the client's view of the canonical chain.
    pub last_justified_slot: u64,
    /// A vec of the hashes of the blocks preceeding the present slot.
    pub parent_hashes: Arc<Vec<Hash256>>,
    /// The store containing block information.
    pub block_store: Arc<BeaconBlockStore<T>>,
    /// The store containing validator information.
    pub validator_store: Arc<ValidatorStore<T>>,
    /// A map of (slot, shard_id) to the attestation set of validation indices.
    pub attester_map: Arc<AttesterMap>,
}

impl<T> AttestationValidationContext<T>
    where T: ClientDB
{
    /// Validate a (fully deserialized) AttestationRecord against this context.
    ///
    /// The function will return a HashSet of validator indices (canonical validator indices not
    /// attestation indices) if the validation passed successfully, or an error otherwise.
    ///
    /// The attestation's aggregate signature will be verified, therefore the function must able to
    /// access all required validation public keys via the `validator_store`.
    pub fn validate_attestation(&self, a: &AttestationRecord)
        -> Result<HashSet<usize>, AttestationValidationError>
    {
        /*
         * The attesation slot must be less than or equal to the parent of the slot of the block
         * that contained the attestation.
         */
        if a.slot > self.parent_block_slot {
            return Err(AttestationValidationError::ParentSlotTooHigh);
        }

        /*
         * The slot of this attestation must not be more than cycle_length + 1 distance
         * from the block that contained it.
         */
        if a.slot < self.block_slot
            .saturating_sub(u64::from(self.cycle_length).saturating_add(1)) {
            return Err(AttestationValidationError::BlockSlotTooLow);
        }

        /*
         * The attestation justified slot must not be higher than the last_justified_slot of the
         * context.
         */
        if a.justified_slot > self.last_justified_slot {
            return Err(AttestationValidationError::JustifiedSlotIncorrect);
        }

        /*
         * There is no need to include more oblique parents hashes than there are blocks
         * in a cycle.
         */
        if a.oblique_parent_hashes.len() > usize::from(self.cycle_length) {
            return Err(AttestationValidationError::TooManyObliqueHashes);
        }

        /*
         * Retrieve the set of attestation indices for this slot and shard id.
         *
         * This is an array mapping the order that validators will appear in the bitfield to the
         * canonincal index of a validator.
         */
        let attestation_indices = self.attester_map.get(&(a.slot, a.shard_id))
            .ok_or(AttestationValidationError::BadAttesterMap)?;

        /*
         * The bitfield must be no longer than the minimum required to represent each validator in the
         * attestation indices for this slot and shard id.
         */
        if a.attester_bitfield.num_bytes() !=
            bytes_for_bits(attestation_indices.len())
        {
            return Err(AttestationValidationError::BadBitfieldLength);
       }

        /*
         * If there are excess bits in the bitfield because the number of a validators in not a
         * multiple of 8, reject this attestation record.
         *
         * Allow extra set bits would permit mutliple different byte layouts (and therefore hashes) to
         * refer to the same AttesationRecord.
         */
        if a.attester_bitfield.len() > attestation_indices.len() {
            return Err(AttestationValidationError::InvalidBitfieldEndBits)
        }

        /*
         * Generate the parent hashes for this attestation
         */
        let parent_hashes = attestation_parent_hashes(
            self.cycle_length,
            self.block_slot,
            a.slot,
            &self.parent_hashes,
            &a.oblique_parent_hashes)?;

        /*
         * The specified justified block hash supplied in the attestation must be in the chain at
         * the given slot number.
         *
         * First, we find the latest parent hash from the parent_hashes array. Then, using the
         * block store (database) we iterate back through the blocks until we find (or fail to
         * find) the justified block hash referenced in the attestation record.
         */
        let latest_parent_hash = parent_hashes.last()
            .ok_or(AttestationValidationError::BadCurrentHashes)?;
        match self.block_store.block_at_slot(&latest_parent_hash, a.justified_slot)? {
            Some((ref hash, _)) if *hash == a.justified_block_hash.to_vec() => (),
            _ => return Err(AttestationValidationError::InvalidJustifiedBlockHash)
        };

        /*
         * Generate the message that this attestation aggregate signature must sign across.
         */
        let signed_message = {
            generate_signed_message(
                a.slot,
                &parent_hashes,
                a.shard_id,
                &a.shard_block_hash,
                a.justified_slot)
        };

        let voted_hashset =
            verify_aggregate_signature_for_indices(
                &signed_message,
                &a.aggregate_sig,
                &attestation_indices,
                &a.attester_bitfield,
                &self.validator_store)?;

        /*
         * If the hashset of voters is None, the signature verification failed.
         */
        match voted_hashset {
            None => Err(AttestationValidationError::BadAggregateSignature),
            Some(hashset) => Ok(hashset),
        }
    }
}

fn bytes_for_bits(bits: usize) -> usize {
    (bits.saturating_sub(1) / 8) + 1
}

impl From<ParentHashesError> for AttestationValidationError {
    fn from(e: ParentHashesError) -> Self {
        match e {
            ParentHashesError::BadCurrentHashes
                => AttestationValidationError::BadCurrentHashes,
            ParentHashesError::BadObliqueHashes
                => AttestationValidationError::BadObliqueHashes,
            ParentHashesError::SlotTooLow
                => AttestationValidationError::BlockSlotTooLow,
            ParentHashesError::SlotTooHigh
                => AttestationValidationError::BlockSlotTooHigh,
            ParentHashesError::IntWrapping
                => AttestationValidationError::IntWrapping
        }
    }
}

impl From<BeaconBlockAtSlotError> for AttestationValidationError {
    fn from(e: BeaconBlockAtSlotError) -> Self {
        match e {
            BeaconBlockAtSlotError::DBError(s) => AttestationValidationError::DBError(s),
            _ => AttestationValidationError::InvalidJustifiedBlockHash

        }
    }
}

impl From<DBError> for AttestationValidationError {
    fn from(e: DBError) -> Self {
        AttestationValidationError::DBError(e.message)
    }
}

impl From<SignatureVerificationError> for AttestationValidationError {
    fn from(e: SignatureVerificationError) -> Self {
        match e {
            SignatureVerificationError::BadValidatorIndex
                => AttestationValidationError::BadAttesterMap,
            SignatureVerificationError::PublicKeyCorrupt
                => AttestationValidationError::PublicKeyCorrupt,
            SignatureVerificationError::NoPublicKeyForValidator
                => AttestationValidationError::NoPublicKeyForValidator,
            SignatureVerificationError::DBError(s)
                => AttestationValidationError::DBError(s),
        }
    }
}
