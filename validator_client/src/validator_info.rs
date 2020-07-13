use remote_beacon_node::RemoteBeaconNode;
use types::{ChainSpec, Epoch, EthSpec, PublicKey, Slot, Validator};

pub struct SlotSpan {
    a: Slot,
    b: Slot,
}

impl SlotSpan {
    pub fn from_slot_and_epoch<T: EthSpec>(a: Slot, b: Epoch) -> Self {
        Self {
            a,
            b: b.start_slot(T::slots_per_epoch()),
        }
    }

    pub fn from_epochs<T: EthSpec>(a: Epoch, b: Epoch) -> Self {
        Self {
            a: a.start_slot(T::slots_per_epoch()),
            b: b.start_slot(T::slots_per_epoch()),
        }
    }

    pub fn secs(&self, seconds_per_slot: u64) -> u64 {
        // Taking advantage of saturating arithmetic on slots.
        let distance = self.b - self.a;
        distance.as_u64() * seconds_per_slot
    }
}

pub enum ValidatorState {
    Unknown,
    WaitingForEligibility,
    WaitingForFinality(SlotSpan),
    WaitingInQueue,
    StandbyForActive(SlotSpan),
    Active,
    ActiveAwaitingExit(SlotSpan),
    Exited(SlotSpan),
    Withdrawable,
}

pub struct ValidatorStateDisplay {
    state: &'static str,
    estimated_seconds_till_transition: Option<u64>,
    description: &'static str,
}

impl ValidatorStateDisplay {
    fn new(state: ValidatorState, seconds_per_slot: u64) -> Self {
        match state {
            ValidatorState::Unknown => Self {
                state: "unknown",
                estimated_seconds_till_transition: None,
                description: "The beacon chain is unaware of the validator",
            },
            ValidatorState::WaitingForEligibility => Self {
                state: "waiting_for_eligibility",
                estimated_seconds_till_transition: None,
                description: "The beacon chain is waiting to confirm the validator balance",
            },
            ValidatorState::WaitingForFinality(span) => Self {
                state: "waiting_for_finality",
                estimated_seconds_till_transition: Some(span.secs(seconds_per_slot)),
                description: "The beacon chain is waiting to finalized the validator balance",
            },
            ValidatorState::WaitingInQueue => Self {
                state: "waiting_in_queue",
                estimated_seconds_till_transition: None,
                description: "The validator is queued for activation",
            },
            ValidatorState::StandbyForActive(span) => Self {
                state: "standby_for_active",
                estimated_seconds_till_transition: Some(span.secs(seconds_per_slot)),
                description: "The validator will be activated shortly",
            },
            ValidatorState::Active => Self {
                state: "active",
                estimated_seconds_till_transition: None,
                description: "The validator is required to perform duties",
            },
            ValidatorState::ActiveAwaitingExit(span) => Self {
                state: "active_awaiting_exit",
                estimated_seconds_till_transition: Some(span.secs(seconds_per_slot)),
                description: "The validator is active but scheduled for exit",
            },
            ValidatorState::Exited(span) => Self {
                state: "exited",
                estimated_seconds_till_transition: Some(span.secs(seconds_per_slot)),
                description: "The validator is no longer required to perform duties and is waiting
                    to become withdrawable",
            },
            ValidatorState::Withdrawable => Self {
                state: "withdrawable",
                estimated_seconds_till_transition: None,
                description: "The validator is no longer required to perform duties and is eligible
                    for withdraw",
            },
        }
    }
}

pub struct ValidatorInfo {
    status: ValidatorStateDisplay,
    validator_index: Option<usize>,
    balance: Option<u64>,
    validator: Option<Validator>,
}

pub async fn validator_info<T: EthSpec>(
    beacon_node: RemoteBeaconNode<T>,
    validators: &[PublicKey],
    genesis_time: u64,
    spec: &ChainSpec,
) -> Result<Vec<ValidatorInfo>, String> {
    let head = beacon_node
        .http
        .beacon()
        .get_head()
        .await
        .map_err(|e| format!("Failed to get head info from beacon node: {:?}", e))?;

    let finalized_epoch = head.finalized_slot.epoch(T::slots_per_epoch());

    let validators = beacon_node
        .http
        .beacon()
        .get_validators(validators.to_vec(), Some(head.state_root))
        .await
        .map_err(|e| format!("Failed to get validator info from beacon node: {:?}", e))?;

    Ok(validators
        .iter()
        .map(|v| {
            let status = if let Some(validator) = v.validator.as_ref() {
                if validator.is_withdrawable_at(v.epoch) {
                    ValidatorState::Withdrawable
                } else if validator.is_exited_at(v.epoch) {
                    ValidatorState::Exited(SlotSpan::from_slot_and_epoch::<T>(
                        head.slot,
                        validator.withdrawable_epoch,
                    ))
                } else if validator.is_active_at(v.epoch) {
                    if validator.exit_epoch < spec.far_future_epoch {
                        ValidatorState::ActiveAwaitingExit(SlotSpan::from_slot_and_epoch::<T>(
                            head.slot,
                            validator.exit_epoch,
                        ))
                    } else {
                        ValidatorState::Active
                    }
                } else {
                    if validator.activation_epoch < spec.far_future_epoch {
                        ValidatorState::StandbyForActive(SlotSpan::from_slot_and_epoch::<T>(
                            head.slot,
                            validator.activation_epoch,
                        ))
                    } else if validator.activation_eligibility_epoch < spec.far_future_epoch {
                        if finalized_epoch < validator.activation_eligibility_epoch {
                            ValidatorState::WaitingForFinality(SlotSpan::from_epochs::<T>(
                                finalized_epoch,
                                validator.activation_eligibility_epoch,
                            ))
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
                status: ValidatorStateDisplay::new(status, spec.milliseconds_per_slot / 1_000),
                validator_index: v.validator_index.clone(),
                balance: v.balance.clone(),
                validator: v.validator.clone(),
            }
        })
        .collect())
}
