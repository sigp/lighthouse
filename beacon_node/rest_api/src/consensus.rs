use crate::helpers::*;
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::{Future, Stream};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use state_processing::per_epoch_processing::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use std::sync::Arc;
use types::{Epoch, EthSpec, PublicKeyBytes};

/// The results of validators voting during an epoch.
///
/// Provides information about the current and previous epochs.
#[derive(Serialize, Deserialize, Encode, Decode)]
pub struct VoteCount {
    /// The total effective balance of all active validators during the _current_ epoch.
    pub current_epoch_active_gwei: u64,
    /// The total effective balance of all active validators during the _previous_ epoch.
    pub previous_epoch_active_gwei: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch.
    pub current_epoch_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _current_ epoch.
    pub current_epoch_target_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch.
    pub previous_epoch_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _previous_ epoch.
    pub previous_epoch_target_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the time of attestation.
    pub previous_epoch_head_attesting_gwei: u64,
}

impl Into<VoteCount> for TotalBalances {
    fn into(self) -> VoteCount {
        VoteCount {
            current_epoch_active_gwei: self.current_epoch(),
            previous_epoch_active_gwei: self.previous_epoch(),
            current_epoch_attesting_gwei: self.current_epoch_attesters(),
            current_epoch_target_attesting_gwei: self.current_epoch_target_attesters(),
            previous_epoch_attesting_gwei: self.previous_epoch_attesters(),
            previous_epoch_target_attesting_gwei: self.previous_epoch_target_attesters(),
            previous_epoch_head_attesting_gwei: self.previous_epoch_head_attesters(),
        }
    }
}

/// HTTP handler return a `VoteCount` for some given `Epoch`.
pub fn get_vote_count<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;
    // This is the last slot of the given epoch (one prior to the first slot of the next epoch).
    let target_slot = (epoch + 1).start_slot(T::EthSpec::slots_per_epoch()) - 1;

    let (_root, state) = state_at_slot(&beacon_chain, target_slot)?;
    let spec = &beacon_chain.spec;

    let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
    validator_statuses.process_attestations(&state, spec)?;

    let report: VoteCount = validator_statuses.total_balances.into();

    ResponseBuilder::new(&req)?.body(&report)
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct IndividualVotesRequest {
    pub epoch: Epoch,
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct IndividualVote {
    /// True if the validator has been slashed, ever.
    pub is_slashed: bool,
    /// True if the validator can withdraw in the current epoch.
    pub is_withdrawable_in_current_epoch: bool,
    /// True if the validator was active in the state's _current_ epoch.
    pub is_active_in_current_epoch: bool,
    /// True if the validator was active in the state's _previous_ epoch.
    pub is_active_in_previous_epoch: bool,
    /// The validator's effective balance in the _current_ epoch.
    pub current_epoch_effective_balance_gwei: u64,
    /// True if the validator had an attestation included in the _current_ epoch.
    pub is_current_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _current_
    /// epoch matches the block root known to the state.
    pub is_current_epoch_target_attester: bool,
    /// True if the validator had an attestation included in the _previous_ epoch.
    pub is_previous_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _previous_
    /// epoch matches the block root known to the state.
    pub is_previous_epoch_target_attester: bool,
    /// True if the validator's beacon block root attestation in the _previous_ epoch at the
    /// attestation's slot (`attestation_data.slot`) matches the block root known to the state.
    pub is_previous_epoch_head_attester: bool,
}

impl Into<IndividualVote> for ValidatorStatus {
    fn into(self) -> IndividualVote {
        IndividualVote {
            is_slashed: self.is_slashed,
            is_withdrawable_in_current_epoch: self.is_withdrawable_in_current_epoch,
            is_active_in_current_epoch: self.is_active_in_current_epoch,
            is_active_in_previous_epoch: self.is_active_in_previous_epoch,
            current_epoch_effective_balance_gwei: self.current_epoch_effective_balance,
            is_current_epoch_attester: self.is_current_epoch_attester,
            is_current_epoch_target_attester: self.is_current_epoch_target_attester,
            is_previous_epoch_attester: self.is_previous_epoch_attester,
            is_previous_epoch_target_attester: self.is_previous_epoch_target_attester,
            is_previous_epoch_head_attester: self.is_previous_epoch_head_attester,
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct IndividualVotesResponse {
    /// The epoch which is considered the "current" epoch.
    pub epoch: Epoch,
    /// The validators public key.
    pub pubkey: PublicKeyBytes,
    /// The index of the validator in state.validators.
    pub validator_index: Option<usize>,
    /// Voting statistics for the validator, if they voted in the given epoch.
    pub vote: Option<IndividualVote>,
}

pub fn post_individual_votes<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);

    let future = req
        .into_body()
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<IndividualVotesRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorDutiesRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(move |body| {
            let epoch = body.epoch;

            // This is the last slot of the given epoch (one prior to the first slot of the next epoch).
            let target_slot = (epoch + 1).start_slot(T::EthSpec::slots_per_epoch()) - 1;

            let (_root, mut state) = state_at_slot(&beacon_chain, target_slot)?;
            let spec = &beacon_chain.spec;

            let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
            validator_statuses.process_attestations(&state, spec)?;

            state.update_pubkey_cache().map_err(|e| {
                ApiError::ServerError(format!("Unable to build pubkey cache: {:?}", e))
            })?;

            body.pubkeys
                .into_iter()
                .map(|pubkey| {
                    let validator_index_opt = state.get_validator_index(&pubkey).map_err(|e| {
                        ApiError::ServerError(format!("Unable to read pubkey cache: {:?}", e))
                    })?;

                    if let Some(validator_index) = validator_index_opt {
                        let vote = validator_statuses
                            .statuses
                            .get(validator_index)
                            .cloned()
                            .map(Into::into);

                        Ok(IndividualVotesResponse {
                            epoch,
                            pubkey,
                            validator_index: Some(validator_index),
                            vote,
                        })
                    } else {
                        Ok(IndividualVotesResponse {
                            epoch,
                            pubkey,
                            validator_index: None,
                            vote: None,
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .and_then(|votes| response_builder?.body_no_ssz(&votes));

    Box::new(future)
}
