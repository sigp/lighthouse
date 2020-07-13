use crate::DutiesService;
use remote_beacon_node::RemoteBeaconNode;
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use types::{ChainSpec, Epoch, EthSpec, PublicKey, Validator};

/// The number of epochs between when a validator is eligible for activation and when they
/// *usually* enter the activation queue.
const EPOCHS_BEFORE_FINALITY: u64 = 3;

pub enum ValidatorState {
    Unknown,
    WaitingForEligibility,
    WaitingForFinality(Epoch),
    WaitingInQueue,
    StandbyForActive(Epoch),
    Active,
    ActiveAwaitingExit(Epoch),
    Exited(Epoch),
    Withdrawable,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorStateDisplay {
    state: String,
    next_state: Option<String>,
    estimated_next_state_time: Option<u64>,
    description: String,
}

impl ValidatorStateDisplay {
    fn new(
        state: ValidatorState,
        genesis_time: u64,
        slots_per_epoch: u64,
        spec: &ChainSpec,
    ) -> Self {
        let time = |epoch: Epoch| -> u64 {
            let slot = epoch
                .as_u64()
                .saturating_mul(slots_per_epoch)
                .saturating_sub(spec.genesis_slot.as_u64());
            genesis_time.saturating_add(slot.saturating_mul(spec.milliseconds_per_slot / 1_000))
        };

        match state {
            ValidatorState::Unknown => Self {
                state: "unknown".into(),
                next_state: Some("waiting_for_eligibility".into()),
                estimated_next_state_time: None,
                description: "The beacon chain is unaware of the validator".into(),
            },
            ValidatorState::WaitingForEligibility => Self {
                state: "waiting_for_eligibility".into(),
                next_state: Some("waiting_for_finality".into()),
                estimated_next_state_time: None,
                description: "The beacon chain is waiting to confirm the validator balance".into(),
            },
            ValidatorState::WaitingForFinality(epoch) => Self {
                state: "waiting_for_finality".into(),
                next_state: Some("waiting_in_queue".into()),
                estimated_next_state_time: Some(time(epoch)),
                description: "The beacon chain is waiting to finalized the validator balance"
                    .into(),
            },
            ValidatorState::WaitingInQueue => Self {
                state: "waiting_in_queue".into(),
                next_state: Some("standby_for_active".into()),
                estimated_next_state_time: None,
                description: "The validator is queued for activation".into(),
            },
            ValidatorState::StandbyForActive(epoch) => Self {
                state: "standby_for_active".into(),
                next_state: Some("active".into()),
                estimated_next_state_time: Some(time(epoch)),
                description: "The validator will be activated shortly".into(),
            },
            ValidatorState::Active => Self {
                state: "active".into(),
                next_state: Some("active_awaiting_exit".into()),
                estimated_next_state_time: None,
                description: "The validator is required to perform duties".into(),
            },
            ValidatorState::ActiveAwaitingExit(epoch) => Self {
                state: "active_awaiting_exit".into(),
                next_state: Some("exited".into()),
                estimated_next_state_time: Some(time(epoch)),
                description: "The validator is active but scheduled for exit".into(),
            },
            ValidatorState::Exited(epoch) => Self {
                state: "exited".into(),
                next_state: Some("withdrawable".into()),
                estimated_next_state_time: Some(time(epoch)),
                description: "The validator is no longer required to perform duties and is waiting
                    to become withdrawable"
                    .into(),
            },
            ValidatorState::Withdrawable => Self {
                state: "withdrawable".into(),
                next_state: None,
                estimated_next_state_time: None,
                description: "The validator is no longer required to perform duties and is eligible
                    for withdraw"
                    .into(),
            },
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorInfo {
    status: ValidatorStateDisplay,
    validator_index: Option<usize>,
    balance: Option<u64>,
    validator: Option<Validator>,
}

pub async fn get_validator_info<T: SlotClock + 'static, E: EthSpec>(
    validators: Vec<PublicKey>,
    beacon_node: RemoteBeaconNode<E>,
    duties_service: &DutiesService<T, E>,
    spec: &ChainSpec,
) -> Result<Vec<ValidatorInfo>, String> {
    let head = beacon_node
        .http
        .beacon()
        .get_head()
        .await
        .map_err(|e| format!("Failed to get head info from beacon node: {:?}", e))?;

    let finalized_epoch = head.finalized_slot.epoch(E::slots_per_epoch());
    let genesis_time = duties_service.slot_clock.genesis_duration().as_secs();

    let validators = beacon_node
        .http
        .beacon()
        .get_validators(validators, Some(head.state_root))
        .await
        .map_err(|e| format!("Failed to get validator info from beacon node: {:?}", e))?;

    Ok(validators
        .iter()
        .map(|v| {
            let status = if let Some(validator) = v.validator.as_ref() {
                if validator.is_withdrawable_at(v.epoch) {
                    ValidatorState::Withdrawable
                } else if validator.is_exited_at(v.epoch) {
                    ValidatorState::Exited(validator.withdrawable_epoch)
                } else if validator.is_active_at(v.epoch) {
                    if validator.exit_epoch < spec.far_future_epoch {
                        ValidatorState::ActiveAwaitingExit(validator.exit_epoch)
                    } else {
                        ValidatorState::Active
                    }
                } else {
                    if validator.activation_epoch < spec.far_future_epoch {
                        ValidatorState::StandbyForActive(validator.activation_epoch)
                    } else if validator.activation_eligibility_epoch < spec.far_future_epoch {
                        if finalized_epoch < validator.activation_eligibility_epoch {
                            ValidatorState::WaitingForFinality(
                                validator.activation_eligibility_epoch + EPOCHS_BEFORE_FINALITY,
                            )
                        } else {
                            ValidatorState::WaitingInQueue
                        }
                    } else {
                        ValidatorState::WaitingForEligibility
                    }
                }
            } else {
                ValidatorState::Unknown
            };

            ValidatorInfo {
                status: ValidatorStateDisplay::new(
                    status,
                    genesis_time,
                    E::slots_per_epoch(),
                    &spec,
                ),
                validator_index: v.validator_index.clone(),
                balance: v.balance.clone(),
                validator: v.validator.clone(),
            }
        })
        .collect())
}
