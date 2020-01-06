use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{future, Future, IntoFuture, Stream};
use parking_lot::RwLock;
use remote_beacon_node::RemoteBeaconNode;
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, CommitteeIndex, Epoch, EthSpec, PublicKey, Slot};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

/// Remove any duties where the `duties_epoch < current_epoch - PRUNE_DEPTH`.
const PRUNE_DEPTH: u64 = 4;

type BaseHashMap = HashMap<PublicKey, HashMap<Epoch, ValidatorDuty>>;

/// Stores the duties for some validator for an epoch.
#[derive(PartialEq, Debug, Clone)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: PublicKey,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The position of the validator in the committee.
    pub attestation_committee_position: Option<usize>,
    /// The slots in which a validator must propose a block (can be empty).
    pub block_proposal_slots: Vec<Slot>,
}

impl TryInto<ValidatorDuty> for remote_beacon_node::ValidatorDuty {
    type Error = String;

    fn try_into(self) -> Result<ValidatorDuty, Self::Error> {
        Ok(ValidatorDuty {
            validator_pubkey: (&self.validator_pubkey)
                .try_into()
                .map_err(|e| format!("Invalid pubkey bytes from server: {:?}", e))?,
            attestation_slot: self.attestation_slot,
            attestation_committee_index: self.attestation_committee_index,
            attestation_committee_position: self.attestation_committee_position,
            block_proposal_slots: self.block_proposal_slots,
        })
    }
}

/// The outcome of inserting some `ValidatorDuty` into the `DutiesStore`.
enum InsertOutcome {
    /// These are the first duties received for this validator.
    NewValidator,
    /// The duties for this given epoch were previously unknown and have been stored.
    NewEpoch,
    /// The duties were identical to some already in the store.
    Identical,
    /// There were duties for this validator and epoch in the store that were different to the ones
    /// provided. The existing duties were replaced.
    Replaced,
    /// The given duties were invalid.
    Invalid,
}

#[derive(Default)]
pub struct DutiesStore {
    store: RwLock<BaseHashMap>,
}

impl DutiesStore {
    /// Returns the total number of validators that should propose in the given epoch.
    fn proposer_count(&self, epoch: Epoch) -> usize {
        self.store
            .read()
            .iter()
            .filter(|(_validator_pubkey, validator_map)| {
                validator_map
                    .get(&epoch)
                    .map(|duties| !duties.block_proposal_slots.is_empty())
                    .unwrap_or_else(|| false)
            })
            .count()
    }

    /// Returns the total number of validators that should attest in the given epoch.
    fn attester_count(&self, epoch: Epoch) -> usize {
        self.store
            .read()
            .iter()
            .filter(|(_validator_pubkey, validator_map)| {
                validator_map
                    .get(&epoch)
                    .map(|duties| duties.attestation_slot.is_some())
                    .unwrap_or_else(|| false)
            })
            .count()
    }

    fn block_producers(&self, slot: Slot, slots_per_epoch: u64) -> Vec<PublicKey> {
        self.store
            .read()
            .iter()
            // As long as a `HashMap` iterator does not return duplicate keys, neither will this
            // function.
            .filter_map(|(_validator_pubkey, validator_map)| {
                let epoch = slot.epoch(slots_per_epoch);

                validator_map.get(&epoch).and_then(|duties| {
                    if duties.block_proposal_slots.contains(&slot) {
                        Some(duties.validator_pubkey.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    fn attesters(&self, slot: Slot, slots_per_epoch: u64) -> Vec<ValidatorDuty> {
        self.store
            .read()
            .iter()
            // As long as a `HashMap` iterator does not return duplicate keys, neither will this
            // function.
            .filter_map(|(_validator_pubkey, validator_map)| {
                let epoch = slot.epoch(slots_per_epoch);

                validator_map.get(&epoch).and_then(|duties| {
                    if duties.attestation_slot == Some(slot) {
                        Some(duties)
                    } else {
                        None
                    }
                })
            })
            .cloned()
            .collect()
    }

    fn insert(&self, epoch: Epoch, duties: ValidatorDuty, slots_per_epoch: u64) -> InsertOutcome {
        let mut store = self.store.write();

        if !duties_match_epoch(&duties, epoch, slots_per_epoch) {
            return InsertOutcome::Invalid;
        }

        if let Some(validator_map) = store.get_mut(&duties.validator_pubkey) {
            if let Some(known_duties) = validator_map.get_mut(&epoch) {
                if *known_duties == duties {
                    InsertOutcome::Identical
                } else {
                    *known_duties = duties;
                    InsertOutcome::Replaced
                }
            } else {
                validator_map.insert(epoch, duties);

                InsertOutcome::NewEpoch
            }
        } else {
            let validator_pubkey = duties.validator_pubkey.clone();

            let mut validator_map = HashMap::new();
            validator_map.insert(epoch, duties);

            store.insert(validator_pubkey, validator_map);

            InsertOutcome::NewValidator
        }
    }

    fn prune(&self, prior_to: Epoch) {
        self.store
            .write()
            .retain(|_validator_pubkey, validator_map| {
                validator_map.retain(|epoch, _duties| *epoch >= prior_to);
                !validator_map.is_empty()
            });
    }
}

pub struct DutiesServiceBuilder<T, E: EthSpec> {
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<T>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
    }

    pub fn validator_store(mut self, store: ValidatorStore<T, E>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_node(mut self, beacon_node: RemoteBeaconNode<E>) -> Self {
        self.beacon_node = Some(beacon_node);
        self
    }

    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.context = Some(context);
        self
    }

    pub fn build(self) -> Result<DutiesService<T, E>, String> {
        Ok(DutiesService {
            inner: Arc::new(Inner {
                store: Arc::new(DutiesStore::default()),
                validator_store: self
                    .validator_store
                    .ok_or_else(|| "Cannot build DutiesService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build DutiesService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build DutiesService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build DutiesService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    store: Arc<DutiesStore>,
    validator_store: ValidatorStore<T, E>,
    pub(crate) slot_clock: T,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

/// Maintains a store of the duties for all voting validators in the `validator_store`.
///
/// Polls the beacon node at the start of each epoch, collecting duties for the current and next
/// epoch.
pub struct DutiesService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for DutiesService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for DutiesService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesService<T, E> {
    /// Returns the total number of validators known to the duties service.
    pub fn total_validator_count(&self) -> usize {
        self.validator_store.num_voting_validators()
    }

    /// Returns the total number of validators that should propose in the given epoch.
    pub fn proposer_count(&self, epoch: Epoch) -> usize {
        self.store.proposer_count(epoch)
    }

    /// Returns the total number of validators that should attest in the given epoch.
    pub fn attester_count(&self, epoch: Epoch) -> usize {
        self.store.attester_count(epoch)
    }

    /// Returns the pubkeys of the validators which are assigned to propose in the given slot.
    ///
    /// In normal cases, there should be 0 or 1 validators returned. In extreme cases (i.e., deep forking)
    ///
    /// It is possible that multiple validators have an identical proposal slot, however that is
    /// likely the result of heavy forking (lol) or inconsistent beacon node connections.
    pub fn block_producers(&self, slot: Slot) -> Vec<PublicKey> {
        self.store.block_producers(slot, E::slots_per_epoch())
    }

    /// Returns all `ValidatorDuty` for the given `slot`.
    pub fn attesters(&self, slot: Slot) -> Vec<ValidatorDuty> {
        self.store.attesters(slot, E::slots_per_epoch())
    }

    /// Start the service that periodically polls the beacon node for validator duties.
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<Signal, String> {
        let log = self.context.log.clone();

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        let interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            Interval::new(
                Instant::now() + duration_to_next_slot + TIME_DELAY_FROM_SLOT,
                slot_duration,
            )
        };

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();
        let log_1 = log.clone();
        let log_2 = log.clone();

        // Run an immediate update before starting the updater service.
        self.context.executor.spawn(service.clone().do_update());

        self.context.executor.spawn(
            exit_fut
                .until(
                    interval
                        .map_err(move |e| {
                            crit! {
                                log_1,
                                "Timer thread failed";
                                "error" => format!("{}", e)
                            }
                        })
                        .for_each(move |_| service.clone().do_update().then(|_| Ok(()))),
                )
                .map(move |_| info!(log_2, "Shutdown complete")),
        );

        Ok(exit_signal)
    }

    /// Attempt to download the duties of all managed validators for this epoch and the next.
    fn do_update(&self) -> impl Future<Item = (), Error = ()> {
        let service_1 = self.clone();
        let service_2 = self.clone();
        let service_3 = self.clone();
        let service_4 = self.clone();
        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        self.slot_clock
            .now()
            .ok_or_else(move || {
                error!(log_1, "Duties manager failed to read slot clock");
            })
            .into_future()
            .map(move |slot| {
                let epoch = slot.epoch(E::slots_per_epoch());

                if slot % E::slots_per_epoch() == 0 {
                    let prune_below = epoch - PRUNE_DEPTH;

                    trace!(
                        log_2,
                        "Pruning duties cache";
                        "pruning_below" => prune_below.as_u64(),
                        "current_epoch" => epoch.as_u64(),
                    );

                    service_1.store.prune(prune_below);
                }

                epoch
            })
            .and_then(move |epoch| {
                let log = service_2.context.log.clone();

                service_2
                    .beacon_node
                    .http
                    .beacon()
                    .get_head()
                    .map(move |head| (epoch, head.slot.epoch(E::slots_per_epoch())))
                    .map_err(move |e| {
                        error!(
                                log,
                                "Failed to contact beacon node";
                                "error" => format!("{:?}", e)
                        )
                    })
            })
            .and_then(move |(current_epoch, beacon_head_epoch)| {
                let log = service_3.context.log.clone();

                let future: Box<dyn Future<Item = (), Error = ()> + Send> =
                    if beacon_head_epoch + 1 < current_epoch {
                        error!(
                            log,
                            "Beacon node is not synced";
                            "node_head_epoch" => format!("{}", beacon_head_epoch),
                            "current_epoch" => format!("{}", current_epoch),
                        );

                        Box::new(future::ok(()))
                    } else {
                        Box::new(service_3.update_epoch(current_epoch).then(move |result| {
                            if let Err(e) = result {
                                error!(
                                    log,
                                    "Failed to get current epoch duties";
                                    "http_error" => format!("{:?}", e)
                                );
                            }

                            let log = service_4.context.log.clone();
                            service_4.update_epoch(current_epoch + 1).map_err(move |e| {
                                error!(
                                    log,
                                    "Failed to get next epoch duties";
                                    "http_error" => format!("{:?}", e)
                                );
                            })
                        }))
                    };

                future
            })
            .map(|_| ())
    }

    /// Attempt to download the duties of all managed validators for the given `epoch`.
    fn update_epoch(self, epoch: Epoch) -> impl Future<Item = (), Error = String> {
        let service_1 = self.clone();
        let service_2 = self.clone();

        let pubkeys = service_1.validator_store.voting_pubkeys();
        service_1
            .beacon_node
            .http
            .validator()
            .get_duties(epoch, pubkeys.as_slice())
            .map(move |all_duties| (epoch, all_duties))
            .map_err(move |e| format!("Failed to get duties for epoch {}: {:?}", epoch, e))
            .and_then(move |(epoch, all_duties)| {
                let log = service_2.context.log.clone();

                let mut new_validator = 0;
                let mut new_epoch = 0;
                let mut identical = 0;
                let mut replaced = 0;
                let mut invalid = 0;

                all_duties.into_iter().try_for_each::<_, Result<_, String>>(|remote_duties| {
                    let duties: ValidatorDuty = remote_duties.try_into()?;

                    match service_2
                        .store
                        .insert(epoch, duties.clone(), E::slots_per_epoch())
                    {
                        InsertOutcome::NewValidator => {
                            debug!(
                                log,
                                "First duty assignment for validator";
                                "proposal_slots" => format!("{:?}", &duties.block_proposal_slots),
                                "attestation_slot" => format!("{:?}", &duties.attestation_slot),
                                "validator" => format!("{:?}", &duties.validator_pubkey)
                            );
                            new_validator += 1
                        }
                        InsertOutcome::NewEpoch => new_epoch += 1,
                        InsertOutcome::Identical => identical += 1,
                        InsertOutcome::Replaced => replaced += 1,
                        InsertOutcome::Invalid => invalid += 1,
                    };

                    Ok(())
                })?;

                if invalid > 0 {
                    error!(
                        log,
                        "Received invalid duties from beacon node";
                        "bad_duty_count" => invalid,
                        "info" => "Duties are from wrong epoch."
                    )
                }

                trace!(
                    log,
                    "Performed duties update";
                    "identical" => identical,
                    "new_epoch" => new_epoch,
                    "new_validator" => new_validator,
                    "replaced" => replaced,
                    "epoch" => format!("{}", epoch)
                );

                if replaced > 0 {
                    warn!(
                        log,
                        "Duties changed during routine update";
                        "info" => "Chain re-org likely occurred."
                    )
                }

                Ok(())
            })
    }
}

/// Returns `true` if the slots in the `duties` are from the given `epoch`
fn duties_match_epoch(duties: &ValidatorDuty, epoch: Epoch, slots_per_epoch: u64) -> bool {
    duties
        .attestation_slot
        .map_or(true, |slot| slot.epoch(slots_per_epoch) == epoch)
        && duties
            .block_proposal_slots
            .iter()
            .all(|slot| slot.epoch(slots_per_epoch) == epoch)
}
