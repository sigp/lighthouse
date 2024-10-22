use crate::attestation_data_service::AttestationDataService;
use crate::beacon_node_fallback::{ApiTopic, BeaconNodeFallback};
use crate::{
    duties_service::{DutiesService, DutyAndProof},
    http_metrics::metrics,
    validator_store::{Error as ValidatorStoreError, ValidatorStore},
};
use environment::RuntimeContext;
use futures::future::join_all;
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use tree_hash::TreeHash;
use types::{Attestation, AttestationData, ChainSpec, CommitteeIndex, EthSpec, ForkName, Slot};

/// Builds an `AttestationService`.
pub struct AttestationServiceBuilder<T: SlotClock + 'static, E: EthSpec> {
    duties_service: Option<Arc<DutiesService<T, E>>>,
    validator_store: Option<Arc<ValidatorStore<T, E>>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            context: None,
        }
    }

    pub fn duties_service(mut self, service: Arc<DutiesService<T, E>>) -> Self {
        self.duties_service = Some(service);
        self
    }

    pub fn validator_store(mut self, store: Arc<ValidatorStore<T, E>>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.context = Some(context);
        self
    }

    pub fn build(self) -> Result<AttestationService<T, E>, String> {
        Ok(AttestationService {
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
                context: self
                    .context
                    .ok_or("Cannot build AttestationService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    duties_service: Arc<DutiesService<T, E>>,
    validator_store: Arc<ValidatorStore<T, E>>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
}

/// Attempts to produce attestations for all known validators 1/3rd of the way through each slot.
///
/// If any validators are on the same committee, a single attestation will be downloaded and
/// returned to the beacon node. This attestation will have a signature from each of the
/// validators.
pub struct AttestationService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for AttestationService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for AttestationService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationService<T, E> {
    /// Starts the service which periodically produces attestations.
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();

        let slot_duration = Duration::from_secs(spec.seconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            log,
            "Attestation production service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
        );

        let executor = self.context.executor.clone();

        let interval_fut = async move {
            loop {
                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot + slot_duration / 3).await;
                    let log = self.context.log();

                    if let Err(e) = self.spawn_attestation_tasks(slot_duration) {
                        crit!(
                            log,
                            "Failed to spawn attestation tasks";
                            "error" => e
                        )
                    } else {
                        trace!(
                            log,
                            "Spawned attestation tasks";
                        )
                    }
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                    continue;
                }
            }
        };

        executor.spawn(interval_fut, "attestation_service");
        Ok(())
    }

    /// For each each required attestation, spawn a new task that downloads, signs and uploads the
    /// attestation to the beacon node.
    fn spawn_attestation_tasks(&self, slot_duration: Duration) -> Result<(), String> {
        let slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;

        let fork_name = self.context.eth2_config.spec.fork_name_at_slot::<E>(slot);

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        // If a validator needs to publish an aggregate attestation, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_sub(slot_duration / 3)
                .unwrap_or_else(|| Duration::from_secs(0));

        let duties_by_committee_index: HashMap<CommitteeIndex, Vec<DutyAndProof>> = self
            .duties_service
            .attesters(slot)
            .into_iter()
            .fold(HashMap::new(), |mut map, duty_and_proof| {
                map.entry(duty_and_proof.duty.committee_index)
                    .or_default()
                    .push(duty_and_proof);
                map
            });

        // Signs unaggregated attestations and broadcasts them to the network.
        // Downloads aggregated attestations, signs them, and broadcasts to the network.
        self.spawn_attestation_sign_and_broadcast_task(duties_by_committee_index, slot, fork_name);

        // Schedule pruning of the slashing protection database once all unaggregated
        // attestations have (hopefully) been signed, i.e. at the same time as aggregate
        // production.
        self.spawn_slashing_protection_pruning_task(slot, aggregate_production_instant);

        Ok(())
    }

    /// Spawn a blocking task to run the attestation signing and broadcasting process
    /// for both unaggregated and aggregated attestations.
    fn spawn_attestation_sign_and_broadcast_task(
        &self,
        duties_by_committee_index: HashMap<u64, Vec<DutyAndProof>>,
        slot: Slot,
        fork_name: ForkName,
    ) {
        let inner_self = self.clone();

        let _attestations_timer = metrics::start_timer_vec(
            &metrics::ATTESTATION_SERVICE_TIMES,
            &[metrics::ATTESTATIONS],
        );

        self.inner.context.executor.spawn(
            async move {
                let log = inner_self.context.log().clone();

                let mut attestation_data_service =
                    AttestationDataService::new(inner_self.beacon_nodes.clone());

                inner_self
                    .produce_attestation_data(
                        &mut attestation_data_service,
                        &duties_by_committee_index,
                        &slot,
                        &fork_name,
                    )
                    .await;

                let mut handles = vec![];

                // Sign an `Attestation` for all required validators.
                duties_by_committee_index
                    .iter()
                    .for_each(|(committee_index, validator_duties)| {
                        validator_duties.iter().for_each(|validator_duty| {
                            // Get the previously downloaded attestation data for this committee index.
                            if let Some(attestation_data) = attestation_data_service
                                .get_data_by_committee_index(committee_index, &fork_name)
                            {
                                let this = inner_self.clone();
                                let duty = validator_duty.clone();
                                // Have the validator sign the attestation.
                                let handle =
                                    inner_self.inner.context.executor.spawn_blocking_handle(
                                        move || this.sign_attestation(attestation_data, duty),
                                        "Sign attestation",
                                    );

                                if let Some(handle) = handle {
                                    handles.push(handle);
                                }
                            } else {
                                crit!(
                                    log,
                                    "Failed to fetch attestation data";
                                    "committee_index" => format!("{:?}",&committee_index),
                                    "slot" => format!("{}", &slot),
                                )
                            }
                        })
                    });

                let mut signed_attestations = vec![];

                let results = join_all(handles).await;

                for result in results.into_iter().flatten() {
                    if let Ok(Some(result)) = result.await {
                        signed_attestations.push(result);
                    }
                }

                let slashing_checks_enabled = match inner_self
                    .validator_store
                    .attestation_slashing_checks_enabled(&signed_attestations)
                {
                    Ok(slashing_checks_enabled) => slashing_checks_enabled,
                    Err(e) => {
                        crit!(
                            log,
                            "An error occurred when checking if slashing checks are enabled";
                            "error" => format!("{:?}", e)
                        );
                        return;
                    }
                };

                // Check that the signed attestations are not slash-able (if slash-ability checks are enabled).
                let safe_attestations = if slashing_checks_enabled {
                    let _timer = metrics::start_timer_vec(
                        &metrics::ATTESTATION_SERVICE_TIMES,
                        &[metrics::ATTESTATION_SLASHABILITY_CHECK],
                    );
                    match inner_self
                        .validator_store
                        .check_and_insert_attestations(signed_attestations)
                    {
                        Ok(attestations) => attestations,
                        Err(e) => {
                            crit!(
                                log,
                                "An error occurred when checking for slashable attestations";
                                "error" => format!("{:?}", e)
                            );
                            return;
                        }
                    }
                } else {
                    signed_attestations
                };

                match inner_self
                    .publish_attestations(
                        &safe_attestations.iter().map(|(a, _)| a).collect::<Vec<_>>(),
                        fork_name,
                    )
                    .await
                {
                    Ok(_) => (),
                    Err(e) => {
                        crit!(
                            log,
                            "Failed to broadcast signed attestations";
                            "slot" => format!("{}", slot),
                            "error" => format!("{:?}", e),
                        );
                    }
                };

                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::AGGREGATES],
                );
                // Create and publish `SignedAggregateAndProof` for all aggregating validators.
                for (committee_index, validator_duties) in duties_by_committee_index.iter() {
                    // TODO(attn-slash) we could make this multi threaded
                    if let Some(attestation_data) = attestation_data_service
                        .get_data_by_committee_index(committee_index, &fork_name)
                    {
                        match inner_self
                            .produce_and_publish_aggregates(
                                &attestation_data,
                                *committee_index,
                                validator_duties,
                            )
                            .await
                        {
                            Ok(_) => (),
                            Err(e) => {
                                crit!(
                                    log,
                                    "Failed to produce and publish attestation aggregates";
                                    "slot" => format!("{}", slot),
                                    "error" => format!("{:?}", e),
                                );
                            }
                        };
                    } else {
                        crit!(
                            log,
                            "Failed to fetch attestation data";
                            "committee_index" => format!("{:?}",&committee_index),
                            "slot" => format!("{}", &slot),
                        )
                    }
                }
            },
            "Download and sign attestations",
        );
    }

    /// Performs the first step of the attesting process: downloading `AttestationData` objects.
    /// Pre Electra: Only one `AttestationData` is downloaded from the BN for each committee index.
    /// Post Electra: Only one `AttestationData` is downloaded from the BN for each slot.
    pub async fn produce_attestation_data(
        &self,
        attestation_data_service: &mut AttestationDataService<T, E>,
        duties_by_committee_index: &HashMap<u64, Vec<DutyAndProof>>,
        slot: &Slot,
        fork_name: &ForkName,
    ) {
        let log = self.context.log().clone();

        for (committee_index, _) in duties_by_committee_index.iter() {
            match attestation_data_service
                .download_data(committee_index, slot, fork_name)
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    crit!(
                        log,
                        "Failed to download attestation data";
                        "slot" => format!("{}", slot),
                        "committee_index" => format!("{}", committee_index),
                        "error" => format!("{:?}", e)
                    );
                }
            };
        }
    }

    /// Performs the second step of the attesting process: signing the downloaded
    /// `Attestation` objects.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#attesting
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    async fn sign_attestation(
        self,
        attestation_data: AttestationData,
        validator_duty: DutyAndProof,
    ) -> Result<Option<(Attestation<E>, DutyAndProof)>, String> {
        let log = self.context.log();
        let _timer = metrics::start_timer_vec(
            &metrics::ATTESTATION_SERVICE_TIMES,
            &[metrics::ATTESTATION_SIGN],
        );

        let current_epoch = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?
            .epoch(E::slots_per_epoch());

        if !validator_duty
            .duty
            .match_attestation_data::<E>(&attestation_data, &self.context.eth2_config.spec)
        {
            crit!(
                log,
                "Inconsistent validator duties during signing";
                "validator" => ?validator_duty.duty.pubkey,
                "duty_slot" => validator_duty.duty.slot,
                "attestation_slot" => attestation_data.slot,
                "duty_index" => validator_duty.duty.committee_index,
                "attestation_index" => attestation_data.index,
            );
        }

        let mut attestation = match Attestation::<E>::empty_for_signing(
            validator_duty.duty.committee_index,
            validator_duty.duty.committee_length as usize,
            attestation_data.slot,
            attestation_data.beacon_block_root,
            attestation_data.source,
            attestation_data.target,
            &self.context.eth2_config.spec,
        ) {
            Ok(attestation) => attestation,
            Err(err) => {
                crit!(
                    log,
                    "Invalid validator duties during signing";
                    "validator" => ?validator_duty.duty.pubkey,
                    "duty" => ?validator_duty.duty,
                    "err" => ?err,
                );
                return Ok(None);
            }
        };

        let signed_attestation = match self
            .validator_store
            .sign_attestation(
                validator_duty.duty.pubkey,
                validator_duty.duty.validator_committee_index as usize,
                &mut attestation,
                current_epoch,
            )
            .await
        {
            Ok(()) => Some((attestation, validator_duty)),
            Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                // A pubkey can be missing when a validator was recently
                // removed via the API.
                warn!(
                    log,
                    "Missing pubkey for attestation";
                    "info" => "a validator may have recently been removed from this VC",
                    "pubkey" => ?pubkey,
                    "validator" => ?validator_duty.duty.pubkey,
                    "committee_index" => validator_duty.duty.committee_index,
                    "slot" => validator_duty.duty.slot.as_u64(),
                );
                None
            }
            Err(e) => {
                crit!(
                    log,
                    "Failed to sign attestation";
                    "error" => ?e,
                    "validator" => ?validator_duty.duty.pubkey,
                    "slot" => validator_duty.duty.slot.as_u64(),
                );
                None
            }
        };

        Ok(signed_attestation)
    }

    /// Performs the third step of the attesting process: broadcasting the signed attestations
    /// to the network.
    ///
    /// ## Detail
    ///
    /// If slash-ability checks are enabled the broadcasted attestations only include
    /// attestations that were deemed "safe".
    pub async fn publish_attestations(
        &self,
        attestations: &[&Attestation<E>],
        fork_name: ForkName,
    ) -> Result<(), String> {
        self.beacon_nodes
            .request(ApiTopic::Attestations, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::ATTESTATIONS_HTTP_POST],
                );

                if fork_name.electra_enabled() {
                    beacon_node
                        .post_beacon_pool_attestations_v2(attestations, fork_name)
                        .await
                } else {
                    beacon_node
                        .post_beacon_pool_attestations_v1(attestations)
                        .await
                }
            })
            .await
            .map_err(|_| "Failed to broadcast")?;

        Ok(())
    }

    /// Performs the fourth step of the attesting process: downloading an aggregated `Attestation`,
    /// converting it into a `SignedAggregateAndProof` and returning it to the BN.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#broadcast-aggregate
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    ///
    /// Only one aggregated `Attestation` is downloaded from the BN. It is then cloned and signed
    /// by each validator and the list of individually-signed `SignedAggregateAndProof` objects is
    /// returned to the BN.
    async fn produce_and_publish_aggregates(
        &self,
        attestation_data: &AttestationData,
        committee_index: CommitteeIndex,
        validator_duties: &[DutyAndProof],
    ) -> Result<(), String> {
        let log = self.context.log();

        if !validator_duties
            .iter()
            .any(|duty_and_proof| duty_and_proof.selection_proof.is_some())
        {
            // Exit early if no validator is aggregator
            return Ok(());
        }

        let fork_name = self
            .context
            .eth2_config
            .spec
            .fork_name_at_slot::<E>(attestation_data.slot);

        let aggregated_attestation = &self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::AGGREGATES_HTTP_GET],
                );
                if fork_name.electra_enabled() {
                    beacon_node
                        .get_validator_aggregate_attestation_v2(
                            attestation_data.slot,
                            attestation_data.tree_hash_root(),
                            committee_index,
                        )
                        .await
                        .map_err(|e| {
                            format!("Failed to produce an aggregate attestation: {:?}", e)
                        })?
                        .ok_or_else(|| format!("No aggregate available for {:?}", attestation_data))
                        .map(|result| result.data)
                } else {
                    beacon_node
                        .get_validator_aggregate_attestation_v1(
                            attestation_data.slot,
                            attestation_data.tree_hash_root(),
                        )
                        .await
                        .map_err(|e| {
                            format!("Failed to produce an aggregate attestation: {:?}", e)
                        })?
                        .ok_or_else(|| format!("No aggregate available for {:?}", attestation_data))
                        .map(|result| result.data)
                }
            })
            .await
            .map_err(|e| e.to_string())?;

        // Create futures to produce the signed aggregated attestations.
        let signing_futures = validator_duties.iter().map(|duty_and_proof| async move {
            let duty = &duty_and_proof.duty;
            let selection_proof = duty_and_proof.selection_proof.as_ref()?;

            if !duty.match_attestation_data::<E>(attestation_data, &self.context.eth2_config.spec) {
                crit!(log, "Inconsistent validator duties during signing");
                return None;
            }

            match self
                .validator_store
                .produce_signed_aggregate_and_proof(
                    duty.pubkey,
                    duty.validator_index,
                    aggregated_attestation.clone(),
                    selection_proof.clone(),
                )
                .await
            {
                Ok(aggregate) => Some(aggregate),
                Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                    // A pubkey can be missing when a validator was recently
                    // removed via the API.
                    debug!(
                        log,
                        "Missing pubkey for aggregate";
                        "pubkey" => ?pubkey,
                    );
                    None
                }
                Err(e) => {
                    crit!(
                        log,
                        "Failed to sign aggregate";
                        "error" => ?e,
                        "pubkey" => ?duty.pubkey,
                    );
                    None
                }
            }
        });

        // Execute all the futures in parallel, collecting any successful results.
        let signed_aggregate_and_proofs = join_all(signing_futures)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        if !signed_aggregate_and_proofs.is_empty() {
            let signed_aggregate_and_proofs_slice = signed_aggregate_and_proofs.as_slice();
            match self
                .beacon_nodes
                .first_success(|beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::ATTESTATION_SERVICE_TIMES,
                        &[metrics::AGGREGATES_HTTP_POST],
                    );
                    if fork_name.electra_enabled() {
                        beacon_node
                            .post_validator_aggregate_and_proof_v2(
                                signed_aggregate_and_proofs_slice,
                                fork_name,
                            )
                            .await
                    } else {
                        beacon_node
                            .post_validator_aggregate_and_proof_v1(
                                signed_aggregate_and_proofs_slice,
                            )
                            .await
                    }
                })
                .await
            {
                Ok(()) => {
                    for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                        let attestation = signed_aggregate_and_proof.message().aggregate();
                        info!(
                            log,
                            "Successfully published attestation";
                            "aggregator" => signed_aggregate_and_proof.message().aggregator_index(),
                            "signatures" => attestation.num_set_aggregation_bits(),
                            "head_block" => format!("{:?}", attestation.data().beacon_block_root),
                            "committee_index" => attestation.committee_index(),
                            "slot" => attestation.data().slot.as_u64(),
                            "type" => "aggregated",
                        );
                    }
                }
                Err(e) => {
                    for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                        let attestation = &signed_aggregate_and_proof.message().aggregate();
                        crit!(
                            log,
                            "Failed to publish attestation";
                            "error" => %e,
                            "aggregator" => signed_aggregate_and_proof.message().aggregator_index(),
                            "committee_index" => attestation.committee_index(),
                            "slot" => attestation.data().slot.as_u64(),
                            "type" => "aggregated",
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Spawn a blocking task to run the slashing protection pruning process.
    ///
    /// Start the task at `pruning_instant` to avoid interference with other tasks.
    fn spawn_slashing_protection_pruning_task(&self, slot: Slot, pruning_instant: Instant) {
        let attestation_service = self.clone();
        let executor = self.inner.context.executor.clone();
        let current_epoch = slot.epoch(E::slots_per_epoch());

        // Wait for `pruning_instant` in a regular task, and then switch to a blocking one.
        self.inner.context.executor.spawn(
            async move {
                sleep_until(pruning_instant).await;

                executor.spawn_blocking(
                    move || {
                        attestation_service
                            .validator_store
                            .prune_slashing_protection_db(current_epoch, false)
                    },
                    "slashing_protection_pruning",
                )
            },
            "slashing_protection_pre_pruning",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;
    use parking_lot::RwLock;

    /// This test is to ensure that a `tokio_timer::Sleep` with an instant in the past will still
    /// trigger.
    #[tokio::test]
    async fn delay_triggers_when_in_the_past() {
        let in_the_past = Instant::now() - Duration::from_secs(2);
        let state_1 = Arc::new(RwLock::new(in_the_past));
        let state_2 = state_1.clone();

        sleep_until(in_the_past)
            .map(move |()| *state_1.write() = Instant::now())
            .await;

        assert!(
            *state_2.read() > in_the_past,
            "state should have been updated"
        );
    }
}
