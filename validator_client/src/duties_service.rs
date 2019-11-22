use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, IntoFuture, Stream};
use parking_lot::RwLock;
use remote_beacon_node::{RemoteBeaconNode, ValidatorDuty};
use slog::{error, info, trace, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, Epoch, EthSpec, PublicKey, Slot};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

type BaseHashMap = HashMap<PublicKey, HashMap<Epoch, ValidatorDuty>>;

enum InsertOutcome {
    New,
    Identical,
    Replaced,
}

#[derive(Default)]
pub struct DutiesStore {
    store: RwLock<BaseHashMap>,
}

impl DutiesStore {
    fn block_producers(&self, slot: Slot, slots_per_epoch: u64) -> Vec<PublicKey> {
        self.store
            .read()
            .iter()
            // As long as a `HashMap` iterator does not return duplicate keys, neither will this
            // function.
            .filter_map(|(_validator_pubkey, validator_map)| {
                let epoch = slot.epoch(slots_per_epoch);

                validator_map.get(&epoch).and_then(|duties| {
                    if duties.block_proposal_slot == Some(slot) {
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

    fn insert(&self, epoch: Epoch, duties: ValidatorDuty) -> InsertOutcome {
        let mut store = self.store.write();

        if store.contains_key(&duties.validator_pubkey) {
            let validator_map = store.get_mut(&duties.validator_pubkey).expect(
                "Store is exclusively locked and this path is guarded to ensure the key exists.",
            );

            // TODO: validate that the slots in the duties are all in the given epoch.

            if validator_map.contains_key(&epoch) {
                let known_duties = validator_map.get_mut(&epoch).expect(
                    "Validator map is exclusively mutable and this path is guarded to ensure the key exists.",
                );

                if *known_duties == duties {
                    InsertOutcome::Identical
                } else {
                    *known_duties = duties;
                    InsertOutcome::Replaced
                }
            } else {
                validator_map.insert(epoch, duties);

                InsertOutcome::New
            }
        } else {
            let validator_pubkey = duties.validator_pubkey.clone();

            let mut validator_map = HashMap::new();
            validator_map.insert(epoch, duties);

            store.insert(validator_pubkey, validator_map);

            InsertOutcome::New
        }
    }

    // TODO: call this.
    fn prune(&self, prior_to: Epoch) {
        self.store
            .write()
            .retain(|_validator_pubkey, validator_map| {
                validator_map.retain(|epoch, _duties| *epoch >= prior_to);
                !validator_map.is_empty()
            });
    }
}

#[derive(Clone)]
pub struct DutiesServiceBuilder<T: Clone, E: EthSpec> {
    store: Option<Arc<DutiesStore>>,
    validator_store: Option<ValidatorStore<E>>,
    slot_clock: Option<Arc<T>>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

// TODO: clean trait bounds.
impl<T: SlotClock + Clone + 'static, E: EthSpec> DutiesServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            store: None,
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
    }

    pub fn validator_store(mut self, store: ValidatorStore<E>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(Arc::new(slot_clock));
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
        })
    }
}

#[derive(Clone)]
pub struct DutiesService<T: Clone, E: EthSpec> {
    store: Arc<DutiesStore>,
    validator_store: ValidatorStore<E>,
    slot_clock: Arc<T>,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

impl<T: SlotClock + Clone + 'static, E: EthSpec> DutiesService<T, E> {
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

        info!(
            log,
            "Waiting for next slot";
            "seconds_to_wait" => duration_to_next_slot.as_secs()
        );

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();

        // Run an immediate update before starting the updater service.
        self.context.executor.spawn(service.clone().do_update());

        self.context.executor.spawn(
            interval
                .map_err(move |e| {
                    error! {
                        log,
                        "Timer thread failed";
                        "error" => format!("{}", e)
                    }
                })
                .and_then(move |_| if exit_fut.is_live() { Ok(()) } else { Err(()) })
                .for_each(move |_| service.clone().do_update())
                // Prevent any errors from escaping and stopping the interval.
                .then(|_| Ok(())),
        );

        Ok(exit_signal)
    }

    fn do_update(self) -> impl Future<Item = (), Error = ()> {
        let slots_per_epoch = E::slots_per_epoch();
        let service_1 = self.clone();
        let service_2 = self.clone();
        let log = self.context.log.clone();

        self.slot_clock
            .now()
            .ok_or_else(move || {
                error!(log, "Duties manager failed to read slot clock");
            })
            .into_future()
            .map(move |slot| slot.epoch(slots_per_epoch))
            .and_then(move |epoch| {
                let log = service_1.context.log.clone();
                service_1.update_epoch(epoch).then(move |result| {
                    if let Err(e) = result {
                        error!(
                            log,
                            "Failed to get current epoch duties";
                            "http_error" => format!("{:?}", e)
                        );
                    }

                    let log = service_2.context.log.clone();
                    service_2.update_epoch(epoch + 1).map_err(move |e| {
                        error!(
                            log,
                            "Failed to get next epoch duties";
                            "http_error" => format!("{:?}", e)
                        );
                    })
                })
            })
            .map(|_| ())
    }

    fn update_epoch(self, epoch: Epoch) -> impl Future<Item = (), Error = String> {
        let service_1 = self.clone();
        let service_2 = self.clone();

        let pubkeys = service_1.validator_store.voting_pubkeys();
        service_1
            .beacon_node
            .http
            .validator()
            .get_duties_bulk(epoch, pubkeys.as_slice())
            .map(move |all_duties| (epoch, all_duties))
            .map_err(move |e| format!("Failed to get duties for epoch {}: {:?}", epoch, e))
            .map(move |(epoch, all_duties)| {
                let mut new = 0;
                let mut identical = 0;
                let mut replaced = 0;

                all_duties.into_iter().for_each(|duties| {
                    match service_2.store.insert(epoch, duties) {
                        InsertOutcome::New => new += 1,
                        InsertOutcome::Identical => identical += 1,
                        InsertOutcome::Replaced => replaced += 1,
                    };
                });

                trace!(
                    service_2.context.log,
                    "Performed duties update";
                    "replaced_duties" => replaced,
                    "identical_duties" => identical,
                    "new_duties" => new,
                    "epoch" => format!("{}", epoch)
                );

                if replaced > 0 {
                    warn!(
                        service_2.context.log,
                        "Duties changed during routine update";
                        "info" => "Chain re-org likely occurred."
                    )
                }
            })
    }
}
