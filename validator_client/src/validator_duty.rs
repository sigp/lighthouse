use eth2::{
    types::{BeaconCommitteeSubscription, StateId, ValidatorId},
    BeaconNodeHttpClient,
};
use serde::{Deserialize, Serialize};
use types::{CommitteeIndex, Epoch, PublicKey, PublicKeyBytes, Slot};

/// This struct is being used as a shim since we deprecated the `rest_api` in favour of `http_api`.
///
/// Tracking issue: https://github.com/sigp/lighthouse/issues/1643
// NOTE: if you add or remove fields, please adjust `eq_ignoring_proposal_slots`
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them.
    pub validator_pubkey: PublicKey,
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
    /// The number of validators in the committee.
    pub committee_length: Option<u64>,
    /// The slots in which a validator must propose a block (can be empty).
    ///
    /// Should be set to `None` when duties are not yet known (before the current epoch).
    pub block_proposal_slots: Option<Vec<Slot>>,
}

impl ValidatorDuty {
    /// Instantiate `Self` as if there are no known dutes for `validator_pubkey`.
    fn no_duties(validator_pubkey: PublicKey) -> Self {
        ValidatorDuty {
            validator_pubkey,
            validator_index: None,
            attestation_slot: None,
            attestation_committee_index: None,
            attestation_committee_position: None,
            committee_count_at_slot: None,
            committee_length: None,
            block_proposal_slots: None,
        }
    }

    /// Instantiate `Self` by performing requests on the `beacon_node`.
    ///
    /// Will only request proposer duties if `current_epoch == request_epoch`.
    pub async fn download(
        beacon_node: &BeaconNodeHttpClient,
        current_epoch: Epoch,
        request_epoch: Epoch,
        pubkey: PublicKey,
    ) -> Result<ValidatorDuty, String> {
        let pubkey_bytes = PublicKeyBytes::from(&pubkey);

        let validator_index = if let Some(index) = beacon_node
            .get_beacon_states_validator_id(
                StateId::Head,
                &ValidatorId::PublicKey(pubkey_bytes.clone()),
            )
            .await
            .map_err(|e| format!("Failed to get validator index: {}", e))?
            .map(|body| body.data.index)
        {
            index
        } else {
            return Ok(Self::no_duties(pubkey));
        };

        if let Some(attester) = beacon_node
            .get_validator_duties_attester(request_epoch, Some(&[validator_index]))
            .await
            .map_err(|e| format!("Failed to get attester duties: {}", e))?
            .data
            .first()
        {
            let block_proposal_slots = if current_epoch == request_epoch {
                beacon_node
                    .get_validator_duties_proposer(current_epoch)
                    .await
                    .map_err(|e| format!("Failed to get proposer indices: {}", e))?
                    .data
                    .into_iter()
                    .filter(|data| data.pubkey == pubkey_bytes)
                    .map(|data| data.slot)
                    .collect()
            } else {
                vec![]
            };

            Ok(ValidatorDuty {
                validator_pubkey: pubkey,
                validator_index: Some(attester.validator_index),
                attestation_slot: Some(attester.slot),
                attestation_committee_index: Some(attester.committee_index),
                attestation_committee_position: Some(attester.validator_committee_index as usize),
                committee_count_at_slot: Some(attester.committees_at_slot),
                committee_length: Some(attester.committee_length),
                block_proposal_slots: Some(block_proposal_slots),
            })
        } else {
            Ok(Self::no_duties(pubkey))
        }
    }

    /// Return `true` if these validator duties are equal, ignoring their `block_proposal_slots`.
    pub fn eq_ignoring_proposal_slots(&self, other: &Self) -> bool {
        self.validator_pubkey == other.validator_pubkey
            && self.validator_index == other.validator_index
            && self.attestation_slot == other.attestation_slot
            && self.attestation_committee_index == other.attestation_committee_index
            && self.attestation_committee_position == other.attestation_committee_position
            && self.committee_count_at_slot == other.committee_count_at_slot
            && self.committee_length == other.committee_length
    }

    /// Generate a subscription for `self`, if `self` has appropriate attestation duties.
    pub fn subscription(&self, is_aggregator: bool) -> Option<BeaconCommitteeSubscription> {
        Some(BeaconCommitteeSubscription {
            validator_index: self.validator_index?,
            committee_index: self.attestation_committee_index?,
            committees_at_slot: self.committee_count_at_slot?,
            slot: self.attestation_slot?,
            is_aggregator,
        })
    }
}
