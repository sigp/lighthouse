use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use state_processing::per_epoch_processing::ValidatorStatus;
use types::{Epoch, PublicKeyBytes};

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
