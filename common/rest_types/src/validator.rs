use bls::{PublicKey, PublicKeyBytes};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::{CommitteeIndex, Epoch, Slot};

/// A Validator duty with the validator public key represented a `PublicKeyBytes`.
pub type ValidatorDutyBytes = ValidatorDutyBase<PublicKeyBytes>;
/// A validator duty with the pubkey represented as a `PublicKey`.
pub type ValidatorDuty = ValidatorDutyBase<PublicKey>;

// NOTE: if you add or remove fields, please adjust `eq_ignoring_proposal_slots`
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorDutyBase<T> {
    /// The validator's BLS public key, uniquely identifying them.
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
    ///
    /// Should be set to `None` when duties are not yet known (before the current epoch).
    pub block_proposal_slots: Option<Vec<Slot>>,
    /// This provides the modulo: `max(1, len(committee) // TARGET_AGGREGATORS_PER_COMMITTEE)`
    /// which allows the validator client to determine if this duty requires the validator to be
    /// aggregate attestations.
    pub aggregator_modulo: Option<u64>,
}

impl<T> ValidatorDutyBase<T> {
    /// Return `true` if these validator duties are equal, ignoring their `block_proposal_slots`.
    pub fn eq_ignoring_proposal_slots(&self, other: &Self) -> bool
    where
        T: PartialEq,
    {
        self.validator_pubkey == other.validator_pubkey
            && self.validator_index == other.validator_index
            && self.attestation_slot == other.attestation_slot
            && self.attestation_committee_index == other.attestation_committee_index
            && self.attestation_committee_position == other.attestation_committee_position
            && self.committee_count_at_slot == other.committee_count_at_slot
            && self.aggregator_modulo == other.aggregator_modulo
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

#[cfg(test)]
mod test {
    use super::*;
    use bls::SecretKey;

    #[test]
    fn eq_ignoring_proposal_slots() {
        let validator_pubkey = SecretKey::deserialize(&[1; 32]).unwrap().public_key();

        let duty1 = ValidatorDuty {
            validator_pubkey,
            validator_index: Some(10),
            attestation_slot: Some(Slot::new(50)),
            attestation_committee_index: Some(2),
            attestation_committee_position: Some(6),
            committee_count_at_slot: Some(4),
            block_proposal_slots: None,
            aggregator_modulo: Some(99),
        };
        let duty2 = ValidatorDuty {
            block_proposal_slots: Some(vec![Slot::new(42), Slot::new(45)]),
            ..duty1.clone()
        };
        assert_ne!(duty1, duty2);
        assert!(duty1.eq_ignoring_proposal_slots(&duty2));
        assert!(duty2.eq_ignoring_proposal_slots(&duty1));
    }
}
