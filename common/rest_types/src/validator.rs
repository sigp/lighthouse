use bls::{PublicKey, PublicKeyBytes, Signature};
use eth2_hashing::hash;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::{CommitteeIndex, Epoch, Slot};

/// A Validator duty with the validator public key represented a `PublicKeyBytes`.
pub type ValidatorDutyBytes = ValidatorDutyBase<PublicKeyBytes>;
/// A validator duty with the pubkey represented as a `PublicKey`.
pub type ValidatorDuty = ValidatorDutyBase<PublicKey>;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorDutyBase<T> {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: T,
    /// The validator's index in `state.validators`
    pub validator_index: Option<u64>,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The position of the validator in the committee.
    pub attestation_committee_position: Option<usize>,
    /// The committee count at `attestation_slot`.
    pub committee_count_at_slot: Option<u64>,
    /// The slots in which a validator must propose a block (can be empty).
    pub block_proposal_slots: Vec<Slot>,
    /// This provides the modulo: `max(1, len(committee) // TARGET_AGGREGATORS_PER_COMMITTEE)`
    /// which allows the validator client to determine if this duty requires the validator to be
    /// aggregate attestations.
    pub aggregator_modulo: Option<u64>,
}

impl<T> ValidatorDutyBase<T> {
    /// Given a `slot_signature` determines if the validator of this duty is an aggregator.
    // Note that we assume the signature is for the associated pubkey to avoid the signature
    // verification
    pub fn is_aggregator(&self, slot_signature: &Signature) -> bool {
        if let Some(modulo) = self.aggregator_modulo {
            let signature_hash = hash(&slot_signature.as_bytes());
            let signature_hash_int = u64::from_le_bytes(
                signature_hash[0..8]
                    .try_into()
                    .expect("first 8 bytes of signature should always convert to fixed array"),
            );
            signature_hash_int % modulo == 0
        } else {
            false
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ValidatorDutiesRequest {
    pub epoch: Epoch,
    pub pubkeys: Vec<PublicKeyBytes>,
}

/// A validator subscription, created when a validator subscribes to a slot to perform optional aggregation
/// duties.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ValidatorSubscription {
    /// The validators index.
    pub validator_index: u64,
    /// The index of the committee within `slot` of which the validator is a member. Used by the
    /// beacon node to quickly evaluate the associated `SubnetId`.
    pub attestation_committee_index: CommitteeIndex,
    /// The slot in which to subscribe.
    pub slot: Slot,
    /// Committee count at slot to subscribe.
    pub committee_count_at_slot: u64,
    /// If true, the validator is an aggregator and the beacon node should aggregate attestations
    /// for this slot.
    pub is_aggregator: bool,
}
