use eth2::{
    types::{BeaconCommitteeSubscription, StateId, ValidatorId},
    BeaconNodeHttpClient,
};
use serde::{Deserialize, Serialize};
use slog::{error, Logger};
use std::collections::HashMap;
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
    fn no_duties(validator_pubkey: PublicKey, validator_index: Option<u64>) -> Self {
        ValidatorDuty {
            validator_pubkey,
            validator_index,
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
        mut pubkeys: Vec<(PublicKey, Option<u64>)>,
        log: &Logger,
    ) -> Result<Vec<ValidatorDuty>, String> {
        for (pubkey, index_opt) in &mut pubkeys {
            if index_opt.is_none() {
                *index_opt = beacon_node
                    .get_beacon_states_validator_id(
                        StateId::Head,
                        &ValidatorId::PublicKey(PublicKeyBytes::from(&*pubkey)),
                    )
                    .await
                    .map_err(|e| {
                        error!(
                            log,
                            "Failed to obtain validator index";
                            "pubkey" => ?pubkey,
                            "error" => ?e
                        )
                    })
                    // Supress the error since we've already logged an error and we don't want to
                    // stop the rest of the code.
                    .ok()
                    .and_then(|body_opt| body_opt.map(|body| body.data.index));
            }
        }

        // Query for all block proposer duties in the current epoch and map the response by index.
        let proposal_slots_by_index: HashMap<u64, Vec<Slot>> = if current_epoch == request_epoch {
            beacon_node
                .get_validator_duties_proposer(current_epoch)
                .await
                .map(|resp| resp.data)
                // Exit early if there's an error.
                .map_err(|e| format!("Failed to get proposer indices: {:?}", e))?
                .into_iter()
                .fold(
                    HashMap::with_capacity(pubkeys.len()),
                    |mut map, proposer_data| {
                        map.entry(proposer_data.validator_index)
                            .or_insert_with(Vec::new)
                            .push(proposer_data.slot);
                        map
                    },
                )
        } else {
            HashMap::new()
        };

        let query_indices = pubkeys
            .iter()
            .filter_map(|(_, index_opt)| *index_opt)
            .collect::<Vec<_>>();
        let attester_data_map = beacon_node
            .post_validator_duties_attester(request_epoch, query_indices.as_slice())
            .await
            .map(|resp| resp.data)
            // Exit early if there's an error.
            .map_err(|e| format!("Failed to get attester duties: {:?}", e))?
            .into_iter()
            .fold(
                HashMap::with_capacity(pubkeys.len()),
                |mut map, attester_data| {
                    map.insert(attester_data.validator_index, attester_data);
                    map
                },
            );

        let duties = pubkeys
            .into_iter()
            .map(|(pubkey, index_opt)| {
                if let Some(index) = index_opt {
                    if let Some(attester_data) = attester_data_map.get(&index) {
                        match attester_data.pubkey.decompress() {
                            Ok(pubkey) => ValidatorDuty {
                                validator_pubkey: pubkey,
                                validator_index: Some(attester_data.validator_index),
                                attestation_slot: Some(attester_data.slot),
                                attestation_committee_index: Some(attester_data.committee_index),
                                attestation_committee_position: Some(
                                    attester_data.validator_committee_index as usize,
                                ),
                                committee_count_at_slot: Some(attester_data.committees_at_slot),
                                committee_length: Some(attester_data.committee_length),
                                block_proposal_slots: proposal_slots_by_index
                                    .get(&attester_data.validator_index)
                                    .cloned(),
                            },
                            Err(e) => {
                                error!(
                                    log,
                                    "Could not deserialize validator public key";
                                    "error" => format!("{:?}", e),
                                    "validator_index" => attester_data.validator_index
                                );
                                Self::no_duties(pubkey, Some(index))
                            }
                        }
                    } else {
                        Self::no_duties(pubkey, Some(index))
                    }
                } else {
                    Self::no_duties(pubkey, None)
                }
            })
            .collect();

        Ok(duties)
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
