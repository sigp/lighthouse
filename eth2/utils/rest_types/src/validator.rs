use bls::{PublicKey, PublicKeyBytes, Signature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
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
    pub validator_index: Option<usize>,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The position of the validator in the committee.
    pub attestation_committee_position: Option<usize>,
    /// The slots in which a validator must propose a block (can be empty).
    pub block_proposal_slots: Vec<Slot>,
    /// Indicates if this duty requires the validator to aggregate attestations. This is false if
    /// there is no `attestation_slot`.
    pub is_aggregator: bool,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ValidatorDutiesRequest {
    pub epoch: Epoch,
    pub pubkeys: Vec<PublicKeyBytes>,
}

/// The container sent when a validator subscribes to a slot to perform optional aggregation
/// duties.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ValidatorSubscriptions {
    pub pubkeys: Vec<PublicKeyBytes>,
    pub slots: Vec<Slot>,
    pub slot_signatures: Vec<Signature>,
}

impl ValidatorSubscriptions {
    pub fn new() -> Self {
        ValidatorSubscriptions {
            pubkeys: Vec::new(),
            slots: Vec::new(),
            slot_signatures: Vec::new(),
        }
    }
}
