use crate::duties_service::DutiesService;
use beacon_node_fallback::{ApiTopic, BeaconNodeFallback};
use futures::future::join_all;
use logging::crit;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};
use types::{
    inclusion_list, ChainSpec, EthSpec, InclusionList, InclusionListDuty, Slot, VariableList,
};
use validator_store::{Error as ValidatorStoreError, ValidatorStore};

/// Builds an `AttestationService`.
#[derive(Default)]
pub struct InclusionListServiceBuilder<S: ValidatorStore, T: SlotClock + 'static> {
    duties_service: Option<Arc<DutiesService<S, T>>>,
    validator_store: Option<Arc<S>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: Option<TaskExecutor>,
    chain_spec: Option<Arc<ChainSpec>>,
    disable: bool,
}

impl<S: ValidatorStore, T: SlotClock + 'static> InclusionListServiceBuilder<S, T> {
    pub fn new() -> Self {
        Self {
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            executor: None,
            chain_spec: None,
            disable: true,
        }
    }

    pub fn duties_service(mut self, service: Arc<DutiesService<S, T>>) -> Self {
        self.duties_service = Some(service);
        self
    }

    pub fn validator_store(mut self, store: Arc<S>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn executor(mut self, executor: TaskExecutor) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn chain_spec(mut self, chain_spec: Arc<ChainSpec>) -> Self {
        self.chain_spec = Some(chain_spec);
        self
    }

    pub fn disable(mut self, disable: bool) -> Self {
        self.disable = disable;
        self
    }

    pub fn build(self) -> Result<InclusionListService<S, T>, String> {
        Ok(InclusionListService {
            inner: Arc::new(Inner {
                duties_service: self
                    .duties_service
                    .ok_or("Cannot build AttestationService without duties_service")?,
                validator_store: self
                    .validator_store
                    .ok_or("Cannot build AttestationService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build AttestationService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build AttestationService without beacon_nodes")?,
                executor: self
                    .executor
                    .ok_or("Cannot build AttestationService without executor")?,
                chain_spec: self
                    .chain_spec
                    .ok_or("Cannot build AttestationService without chain_spec")?,
                disable: self.disable,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    // TODO(focil)
    #[allow(dead_code)]
    chain_spec: Arc<ChainSpec>,
    #[allow(dead_code)]
    disable: bool,
}

/// Attempts to produce inclusion lists for all known validators 3/4 of the way through each slot.
pub struct InclusionListService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for InclusionListService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for InclusionListService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> InclusionListService<S, T> {
    /// Starts the service which periodically produces inclusion lists.
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let slot_duration = Duration::from_secs(spec.seconds_per_slot);

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            next_update_millis = ?duration_to_next_slot.as_millis(),
            "Inclusion list production service started",
        );

        let executor = self.executor.clone();
        let chain_spec = spec.clone();
        let interval_fut = async move {
            loop {
                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    // 3/4 of the way into the slot
                    sleep(duration_to_next_slot + (slot_duration * 3 / 4)).await;
                    if let Err(e) = self.spawn_inclusion_list_task(slot_duration, &chain_spec) {
                        crit!(
                            error = ?e,
                            "Failed to spawn inclusion list task"
                        )
                    } else {
                        trace!("Spawned inclusion list task")
                    }
                } else {
                    error!("Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                    continue;
                }
            }
        };

        executor.spawn(interval_fut, "inclusion_list_service");
        Ok(())
    }

    /// Spawn a task that downloads, signs and uploads the inclusion lists to the beacon node.
    // TODO(focil) I don't think we need `slot_duration` here, unless we need to make some calculation
    // related to the freeze deadline.
    fn spawn_inclusion_list_task(
        &self,
        _slot_duration: Duration,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        info!("Spawning inclusion list task");

        let current_slot: Slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;

        if !spec.is_focil_enabled_for_epoch(current_slot.epoch(S::E::slots_per_epoch())) {
            debug!("FOCIL not enabled");
            return Ok(());
        }

        // TODO(focil) unused variable
        let _duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        let inclusion_list_duties = self.duties_service.inclusion_list_duties(current_slot);

        error!(?current_slot, "PRODUCING INCLUSION LIST");

        let executor = self.executor.clone();

        // TODO(focil) remove this clone
        let this = self.clone();
        let interval_fut = async move {
            if let Err(e) = this
                .produce_and_publish_inclusion_lists(current_slot, inclusion_list_duties)
                .await
            {
                error!(error = e, "Failed to produce and publish inclusion list")
            };
        };

        executor.spawn(interval_fut, "inclusion_list_service");

        Ok(())
    }

    /// Downloads inclusion list objects, signs them, and returns them to the validator.
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot`. Critical errors will be logged if this is not the case.
    ///
    /// Only one `InclusionList` is downloaded from the BN. It is then cloned and signed by each
    /// validator and the list of individually-signed `SignedInclusionList` objects is returned to
    /// the BN.
    async fn produce_and_publish_inclusion_lists(
        self,
        slot: Slot,
        validator_duties: Vec<InclusionListDuty>,
    ) -> Result<(), String> {
        let validator_store = self.validator_store.clone();

        if validator_duties.is_empty() {
            return Ok(());
        }

        // TODO(focil)
        #[allow(unused_variables)]
        let current_epoch = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?
            .epoch(S::E::slots_per_epoch());

        let inclusion_list_transactions = self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                // TODO(focil) add timer metric
                beacon_node
                    .get_validator_inclusion_list::<S::E>(slot)
                    .await
                    .map_err(|e| format!("Failed to produce inclusion list: {:?}", e))
                    .map(|result| result.ok_or("Inclusion list unavailable".to_string()))?
                    .map(|result| result.data)
            })
            .await
            .map_err(|e| {
                crit!(
                    error = format!("{}", e),
                    ?slot,
                    "Error during inclusion list routine"
                );
                format!("{}", e)
            })?;

        let mut trimmed_il = vec![];
        let mut total_bytes = 0;

        for transaction in inclusion_list_transactions.into_iter() {
            total_bytes += transaction.len();
            if total_bytes <= 8192 {
                trimmed_il.push(transaction);
            }
        }

        // Create futures to produce signed `InclusionList` objects.
        let signing_futures = validator_duties.iter().map(|duty| {
            let inclusion_list = InclusionList {
                slot,
                transactions: trimmed_il.clone().into(),
                inclusion_list_committee_root: duty.committee_root,
                validator_index: duty.validator_index,
            };
            let inclusion_list = inclusion_list.clone();
            let validator_store = Arc::clone(&validator_store);
            async move {
                // Ensure that the inclusion list matches the duties.
                //
                // TODO: do we need to check any other fields here?
                if inclusion_list.slot != duty.slot {
                    crit!(
                        validator = ?duty.pubkey,
                        duty_slot = ?duty.slot,
                        inclusion_list_slot = ?inclusion_list.slot,
                        "Inconsistent validator duties during signing"
                    );
                    return None;
                }

                match validator_store
                    .sign_inclusion_list(duty.pubkey, inclusion_list)
                    .await
                {
                    Ok(il) => Some((il, duty.validator_index)),
                    Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                        // A pubkey can be missing when a validator was recently
                        // removed via the API.
                        warn!(
                            info = "a validator may have recently been removed from this VC",
                            ?pubkey,
                            validator = ?duty.pubkey,
                            ?slot,
                            "Missing pubkey for inclusion list",
                        );
                        None
                    }
                    Err(e) => {
                        crit!(
                            error = ?e,
                            validator = ?duty.pubkey,
                            ?slot,
                            "Failed to sign inclusion list",
                        );
                        None
                    }
                }
            }
        });

        // Execute all the futures in parallel, collecting any successful results.
        let (ref inclusion_lists, ref validator_indices): (Vec<_>, Vec<_>) =
            join_all(signing_futures)
                .await
                .into_iter()
                .flatten()
                .unzip();

        if inclusion_lists.is_empty() {
            warn!("No inclusion lists were published");
            return Ok(());
        }

        // Post the inclusion lists to the BN.
        match self
            .beacon_nodes
            .request(ApiTopic::InclusionLists, |beacon_node| async move {
                // TODO: add timer metric
                beacon_node
                    .post_beacon_pool_inclusion_lists(inclusion_lists)
                    .await
            })
            .await
        {
            Ok(()) => info!(
                il_count = inclusion_lists.len(),
                ?validator_indices,
                ?slot,
                "Successfully published inclusion lists",
            ),
            Err(e) => error!(
                error = %e,
                ?slot,
                "Unable to publish inclusion lists"
            ),
        }

        Ok(())
    }
}
