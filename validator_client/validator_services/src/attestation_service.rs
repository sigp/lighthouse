use crate::duties_service::{DutiesService, DutyAndProof};
use beacon_node_fallback::{ApiTopic, BeaconNodeFallback, beacon_head_monitor::HeadEvent};
use futures::StreamExt;
use logging::crit;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep, sleep_until};
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};
use tree_hash::TreeHash;
use types::{AttestationData, ChainSpec, CommitteeIndex, EthSpec, Hash256, Slot};
use validator_store::{AggregateToSign, AttestationToSign, ValidatorStore};

/// Builds an `AttestationService`.
#[derive(Default)]
pub struct AttestationServiceBuilder<S: ValidatorStore, T: SlotClock + 'static> {
    duties_service: Option<Arc<DutiesService<S, T>>>,
    validator_store: Option<Arc<S>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: Option<TaskExecutor>,
    chain_spec: Option<Arc<ChainSpec>>,
    head_monitor_rx: Option<Mutex<mpsc::Receiver<HeadEvent>>>,
    disable: bool,
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> AttestationServiceBuilder<S, T> {
    pub fn new() -> Self {
        Self {
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            executor: None,
            chain_spec: None,
            head_monitor_rx: None,
            disable: false,
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

    pub fn head_monitor_rx(
        mut self,
        head_monitor_rx: Option<Mutex<mpsc::Receiver<HeadEvent>>>,
    ) -> Self {
        self.head_monitor_rx = head_monitor_rx;
        self
    }
    pub fn build(self) -> Result<AttestationService<S, T>, String> {
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
                executor: self
                    .executor
                    .ok_or("Cannot build AttestationService without executor")?,
                chain_spec: self
                    .chain_spec
                    .ok_or("Cannot build AttestationService without chain_spec")?,
                head_monitor_rx: self.head_monitor_rx,
                disable: self.disable,
                latest_attested_slot: Mutex::new(Slot::default()),
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
    chain_spec: Arc<ChainSpec>,
    head_monitor_rx: Option<Mutex<mpsc::Receiver<HeadEvent>>>,
    disable: bool,
    latest_attested_slot: Mutex<Slot>,
}

/// Attempts to produce attestations for all known validators at the fork-aware attestation
/// deadline or when a head event is received from the BNs.
///
/// If any validators are on the same committee, a single attestation will be downloaded and
/// returned to the beacon node. This attestation will have a signature from each of the
/// validators.
pub struct AttestationService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for AttestationService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for AttestationService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

fn attestation_deadline<E: EthSpec>(
    slot_clock: &impl SlotClock,
    chain_spec: &ChainSpec,
    now: Duration,
) -> (Slot, Option<Duration>) {
    let attestation_slot = slot_clock
        .slot_of(now)
        .map_or_else(|| slot_clock.genesis_slot(), |slot| slot + 1);
    let duration_to_attestation_deadline = slot_clock
        .start_of(attestation_slot)
        .and_then(|slot_start| {
            slot_start.checked_add(chain_spec.get_attestation_due::<E>(attestation_slot))
        })
        .and_then(|deadline| deadline.checked_sub(now));
    (attestation_slot, duration_to_attestation_deadline)
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> AttestationService<S, T> {
    /// Starts the service which periodically produces attestations.
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        if self.disable {
            info!("Attestation service disabled");
            return Ok(());
        }

        let slot_duration = spec.get_slot_duration();
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            next_update_millis = duration_to_next_slot.as_millis(),
            "Attestation production service started"
        );

        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                let Some(now) = self.slot_clock.now_duration() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };
                let (attestation_slot, duration_to_attestation_deadline) =
                    attestation_deadline::<S::E>(&self.slot_clock, &self.chain_spec, now);
                let Some(duration_to_attestation_deadline) = duration_to_attestation_deadline
                else {
                    error!(%attestation_slot, "Failed to determine attestation deadline");
                    sleep(slot_duration).await;
                    continue;
                };

                let beacon_node_data = if self.head_monitor_rx.is_some() {
                    tokio::select! {
                        _ = sleep(duration_to_attestation_deadline) => None,
                        event = self.poll_for_head_events() =>
                            event.map(|event| (event.beacon_node_index, event.beacon_block_root)),
                    }
                } else {
                    sleep(duration_to_attestation_deadline).await;
                    None
                };

                let Some(current_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock after trigger");
                    continue;
                };

                let mut last_slot = self.latest_attested_slot.lock().await;

                if current_slot <= *last_slot {
                    debug!(%current_slot, "Attestation already initiated for the slot");
                    continue;
                }

                match self.spawn_attestation_tasks(beacon_node_data).await {
                    Ok(_) => {
                        *last_slot = current_slot;
                    }
                    Err(e) => {
                        crit!(error = e, "Failed to spawn attestation tasks");
                    }
                }
            }
        };

        executor.spawn(interval_fut, "attestation_service");
        Ok(())
    }

    async fn poll_for_head_events(&self) -> Option<HeadEvent> {
        let Some(receiver) = &self.head_monitor_rx else {
            return None;
        };
        let mut receiver = receiver.lock().await;
        loop {
            match receiver.recv().await {
                Some(head_event) => {
                    // Only return head events for the current slot - this ensures the
                    // block for this slot has been produced before triggering attestation
                    let current_slot = self.slot_clock.now()?;
                    if head_event.slot == current_slot {
                        return Some(head_event);
                    }
                    // Head event is for a previous slot, keep waiting
                }
                None => {
                    warn!("Head monitor channel closed unexpectedly");
                    return None;
                }
            }
        }
    }

    /// Spawn only one new task for attestation post-Electra
    /// For each required aggregates, spawn a new task that downloads, signs and uploads the
    /// aggregates to the beacon node.
    async fn spawn_attestation_tasks(
        &self,
        beacon_node_data: Option<(usize, Hash256)>,
    ) -> Result<(), String> {
        let slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;

        // Create and publish an `Attestation` for all validators only once
        // as the committee_index is not included in AttestationData post-Electra
        let attestation_duties: Vec<_> = self.duties_service.attesters(slot).into_iter().collect();

        // Return early if there is no attestation duties
        if attestation_duties.is_empty() {
            return Ok(());
        }

        debug!(
            %slot,
            from_head_monitor = beacon_node_data.is_some(),
            "Starting attestation production"
        );

        let attestation_service = self.clone();

        let mut attestation_data_from_head_event = None;

        if let Some((beacon_node_index, expected_block_root)) = beacon_node_data {
            match attestation_service
                .beacon_nodes
                .run_on_candidate_index(beacon_node_index, |beacon_node| async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::ATTESTATIONS_HTTP_GET],
                    );
                    let data = beacon_node
                        .get_validator_attestation_data(slot, 0)
                        .await
                        .map_err(|e| format!("Failed to produce attestation data: {:?}", e))?
                        .data;

                    if data.beacon_block_root != expected_block_root {
                        return Err(format!(
                            "Attestation block root mismatch: expected {:?}, got {:?}",
                            expected_block_root, data.beacon_block_root
                        ));
                    }
                    Ok(data)
                })
                .await
            {
                Ok(data) => attestation_data_from_head_event = Some(data),
                Err(error) => {
                    warn!(?error, "Failed to attest based on head event");
                }
            }
        }

        // If the beacon node that sent us the head failed to attest, wait until the attestation
        // deadline then try all BNs.
        let attestation_data = if let Some(attestation_data) = attestation_data_from_head_event {
            attestation_data
        } else {
            let duration_to_deadline = self
                .slot_clock
                .duration_to_slot(slot + 1)
                .and_then(|duration_to_next_slot| {
                    duration_to_next_slot
                        .checked_add(self.chain_spec.get_attestation_due::<S::E>(slot))
                })
                .map(|next_slot_deadline| {
                    next_slot_deadline.saturating_sub(self.chain_spec.get_slot_duration())
                })
                .unwrap_or(Duration::from_secs(0));
            sleep(duration_to_deadline).await;

            attestation_service
                .beacon_nodes
                .first_success(|beacon_node| async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::ATTESTATIONS_HTTP_GET],
                    );
                    let data = beacon_node
                        .get_validator_attestation_data(slot, 0)
                        .await
                        .map_err(|e| format!("Failed to produce attestation data: {:?}", e))?
                        .data;
                    Ok::<AttestationData, String>(data)
                })
                .await
                .map_err(|e| e.to_string())?
        };

        // Sign and publish attestations.
        let publication_handle = self
            .inner
            .executor
            .spawn_handle(
                async move {
                    attestation_service
                        .sign_and_publish_attestations(
                            slot,
                            &attestation_duties,
                            attestation_data.clone(),
                        )
                        .await
                        .map_err(|e| {
                            crit!(
                                error = e,
                                slot = slot.as_u64(),
                                "Error during attestation routine"
                            );
                            e
                        })?;
                    Ok::<AttestationData, String>(attestation_data)
                },
                "unaggregated attestation publication",
            )
            .ok_or("Failed to spawn attestation data task")?;

        // If a validator needs to publish an aggregate attestation, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_slot(slot + 1)
            .ok_or("Unable to determine duration to next slot")?;
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_add(self.chain_spec.get_aggregate_attestation_due())
                .and_then(|offset| offset.checked_sub(self.chain_spec.get_slot_duration()))
                .unwrap_or_else(|| Duration::from_secs(0));

        let aggregate_duties_by_committee_index: HashMap<CommitteeIndex, Vec<DutyAndProof>> = self
            .duties_service
            .attesters(slot)
            .into_iter()
            .fold(HashMap::new(), |mut map, duty_and_proof| {
                map.entry(duty_and_proof.duty.committee_index)
                    .or_default()
                    .push(duty_and_proof);
                map
            });

        // Spawn a task that awaits the attestation data handle and then spawns aggregate tasks
        let attestation_service_clone = self.clone();
        let executor = self.inner.executor.clone();
        self.inner.executor.spawn(
            async move {
                // Log an error if the handle fails and return, skipping aggregates
                let attestation_data = match publication_handle.await {
                    Ok(Some(Ok(data))) => data,
                    Ok(Some(Err(err))) => {
                        error!(?err, "Attestation production failed");
                        return;
                    }
                    Ok(None) | Err(_) => {
                        info!("Aborting attestation production due to shutdown");
                        return;
                    }
                };

                // For each committee index for this slot:
                // Create and publish `SignedAggregateAndProof` for all aggregating validators.
                aggregate_duties_by_committee_index.into_iter().for_each(
                    |(committee_index, validator_duties)| {
                        let attestation_service = attestation_service_clone.clone();
                        let attestation_data = attestation_data.clone();
                        executor.spawn_ignoring_error(
                            attestation_service.handle_aggregates(
                                slot,
                                committee_index,
                                validator_duties,
                                aggregate_production_instant,
                                attestation_data,
                            ),
                            "aggregate publish",
                        );
                    },
                )
            },
            "attestation and aggregate publish",
        );

        // Schedule pruning of the slashing protection database once all unaggregated
        // attestations have (hopefully) been signed, i.e. at the same time as aggregate
        // production.
        self.spawn_slashing_protection_pruning_task(slot, aggregate_production_instant);

        Ok(())
    }

    #[instrument(
        name = "lh_handle_aggregates",
        skip_all,
        fields(%slot, %committee_index)
    )]
    async fn handle_aggregates(
        self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<DutyAndProof>,
        aggregate_production_instant: Instant,
        attestation_data: AttestationData,
    ) -> Result<(), ()> {
        // There's not need to produce `SignedAggregateAndProof` if we do not have
        // any validators for the given `slot` and `committee_index`.
        if validator_duties.is_empty() {
            return Ok(());
        }

        // Wait until the `aggregation_production_instant` (2/3rds
        // of the way though the slot). As verified in the
        // `delay_triggers_when_in_the_past` test, this code will still run
        // even if the instant has already elapsed.
        sleep_until(aggregate_production_instant).await;

        // Start the metrics timer *after* we've done the delay.
        let _aggregates_timer = validator_metrics::start_timer_vec(
            &validator_metrics::ATTESTATION_SERVICE_TIMES,
            &[validator_metrics::AGGREGATES],
        );

        // Download, sign and publish a `SignedAggregateAndProof` for each
        // validator that is elected to aggregate for this `slot` and
        // `committee_index`.
        self.produce_and_publish_aggregates(&attestation_data, committee_index, &validator_duties)
            .await
            .map_err(move |e| {
                crit!(
                    error = format!("{:?}", e),
                    committee_index,
                    slot = slot.as_u64(),
                    "Error during aggregate attestation routine"
                );
            })?;

        Ok(())
    }

    /// Performs the main steps of the attesting process: signing and publishing to the BN.
    ///
    /// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#attesting
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot`. Critical errors will be logged if this is not the case.
    #[instrument(name = "lh_sign_and_publish_attestations", skip_all, fields(%slot, %attestation_data.beacon_block_root))]
    async fn sign_and_publish_attestations(
        &self,
        slot: Slot,
        validator_duties: &[DutyAndProof],
        attestation_data: AttestationData,
    ) -> Result<(), String> {
        let _attestations_timer = validator_metrics::start_timer_vec(
            &validator_metrics::ATTESTATION_SERVICE_TIMES,
            &[validator_metrics::ATTESTATIONS],
        );

        let current_epoch = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?
            .epoch(S::E::slots_per_epoch());

        // Make sure the target epoch is not higher than the current epoch to avoid potential attacks.
        if attestation_data.target.epoch > current_epoch {
            return Err(format!(
                "Attestation target epoch {} is higher than current epoch {}",
                attestation_data.target.epoch, current_epoch
            ));
        }

        // Create attestations for each validator duty.
        let mut attestations_to_sign = Vec::with_capacity(validator_duties.len());

        for duty_and_proof in validator_duties {
            let duty = &duty_and_proof.duty;

            // Ensure that the attestation matches the duties.
            if !duty.match_attestation_data::<S::E>(&attestation_data, &self.chain_spec) {
                crit!(
                    validator = ?duty.pubkey,
                    duty_slot = %duty.slot,
                    attestation_slot = %attestation_data.slot,
                    duty_index = duty.committee_index,
                    attestation_index = attestation_data.index,
                    "Inconsistent validator duties during signing"
                );
                continue;
            }

            attestations_to_sign.push(AttestationToSign {
                attester_index: duty.validator_index,
                pubkey: duty.pubkey,
                committee_index: duty.committee_index,
                data: attestation_data.clone(),
            });
        }

        if attestations_to_sign.is_empty() {
            warn!("No valid attestations to sign");
            return Ok(());
        }

        let attestation_stream = self.validator_store.sign_attestations(attestations_to_sign);
        tokio::pin!(attestation_stream);

        let fork_name = self
            .chain_spec
            .fork_name_at_slot::<S::E>(attestation_data.slot);

        // Publish each batch as it arrives from the stream.
        let mut received_non_empty_batch = false;
        while let Some(result) = attestation_stream.next().await {
            match result {
                Ok(batch) if !batch.is_empty() => {
                    received_non_empty_batch = true;

                    let single_attestations = &batch;
                    let validator_indices = single_attestations
                        .iter()
                        .map(|att| att.attester_index)
                        .collect::<Vec<_>>();
                    let published_count = single_attestations.len();

                    // Post the attestations to the BN.
                    match self
                        .beacon_nodes
                        .request(ApiTopic::Attestations, |beacon_node| async move {
                            let _timer = validator_metrics::start_timer_vec(
                                &validator_metrics::ATTESTATION_SERVICE_TIMES,
                                &[validator_metrics::ATTESTATIONS_HTTP_POST],
                            );

                            beacon_node
                                .post_beacon_pool_attestations_v2::<S::E>(
                                    single_attestations.clone(),
                                    fork_name,
                                )
                                .await
                        })
                        .instrument(info_span!("publish_attestations", count = published_count))
                        .await
                    {
                        Ok(()) => info!(
                            count = published_count,
                            validator_indices = ?validator_indices,
                            head_block = ?attestation_data.beacon_block_root,
                            committee_index = attestation_data.index,
                            slot = attestation_data.slot.as_u64(),
                            "type" = "unaggregated",
                            "Successfully published attestations"
                        ),
                        Err(e) => error!(
                            error = %e,
                            committee_index = attestation_data.index,
                            slot = slot.as_u64(),
                            "type" = "unaggregated",
                            "Unable to publish attestations"
                        ),
                    }
                }
                Err(e) => {
                    crit!(error = ?e, "Failed to sign attestations");
                }
                _ => {}
            }
        }

        if !received_non_empty_batch {
            warn!("No attestations were published");
        }

        Ok(())
    }

    /// Performs the second step of the attesting process: downloading an aggregated `Attestation`,
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
    #[instrument(skip_all, fields(slot = %attestation_data.slot, %committee_index))]
    async fn produce_and_publish_aggregates(
        &self,
        attestation_data: &AttestationData,
        committee_index: CommitteeIndex,
        validator_duties: &[DutyAndProof],
    ) -> Result<(), String> {
        if !validator_duties
            .iter()
            .any(|duty_and_proof| duty_and_proof.selection_proof.is_some())
        {
            // Exit early if no validator is aggregator
            return Ok(());
        }

        let fork_name = self
            .chain_spec
            .fork_name_at_slot::<S::E>(attestation_data.slot);

        let aggregated_attestation = &self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                let _timer = validator_metrics::start_timer_vec(
                    &validator_metrics::ATTESTATION_SERVICE_TIMES,
                    &[validator_metrics::AGGREGATES_HTTP_GET],
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
                        .map(|result| result.into_data())
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
            .instrument(info_span!("fetch_aggregate_attestation"))
            .await
            .map_err(|e| e.to_string())?;

        // Build the batch of aggregates to sign.
        let aggregates_to_sign: Vec<_> = validator_duties
            .iter()
            .filter_map(|duty_and_proof| {
                let duty = &duty_and_proof.duty;
                let selection_proof = duty_and_proof.selection_proof.as_ref()?;

                if !duty.match_attestation_data::<S::E>(attestation_data, &self.chain_spec) {
                    crit!("Inconsistent validator duties during signing");
                    return None;
                }

                Some(AggregateToSign {
                    pubkey: duty.pubkey,
                    aggregator_index: duty.validator_index,
                    aggregate: aggregated_attestation.clone(),
                    selection_proof: selection_proof.clone(),
                })
            })
            .collect();

        // Sign aggregates. Returns a stream of batches.
        let aggregate_stream = self
            .validator_store
            .sign_aggregate_and_proofs(aggregates_to_sign);
        tokio::pin!(aggregate_stream);

        // Publish each batch as it arrives from the stream.
        while let Some(result) = aggregate_stream.next().await {
            match result {
                Ok(batch) if !batch.is_empty() => {
                    let signed_aggregate_and_proofs = batch.as_slice();
                    match self
                        .beacon_nodes
                        .first_success(|beacon_node| async move {
                            let _timer = validator_metrics::start_timer_vec(
                                &validator_metrics::ATTESTATION_SERVICE_TIMES,
                                &[validator_metrics::AGGREGATES_HTTP_POST],
                            );
                            if fork_name.electra_enabled() {
                                beacon_node
                                    .post_validator_aggregate_and_proof_v2(
                                        signed_aggregate_and_proofs,
                                        fork_name,
                                    )
                                    .await
                            } else {
                                beacon_node
                                    .post_validator_aggregate_and_proof_v1(
                                        signed_aggregate_and_proofs,
                                    )
                                    .await
                            }
                        })
                        .instrument(info_span!(
                            "publish_aggregates",
                            count = signed_aggregate_and_proofs.len()
                        ))
                        .await
                    {
                        Ok(()) => {
                            for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                                let attestation = signed_aggregate_and_proof.message().aggregate();
                                info!(
                                    aggregator =
                                        signed_aggregate_and_proof.message().aggregator_index(),
                                    signatures = attestation.num_set_aggregation_bits(),
                                    head_block =
                                        format!("{:?}", attestation.data().beacon_block_root),
                                    committee_index = attestation.committee_index(),
                                    slot = attestation.data().slot.as_u64(),
                                    "type" = "aggregated",
                                    "Successfully published attestation"
                                );
                            }
                        }
                        Err(e) => {
                            for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                                let attestation = &signed_aggregate_and_proof.message().aggregate();
                                crit!(
                                    error = %e,
                                    aggregator = signed_aggregate_and_proof
                                        .message()
                                        .aggregator_index(),
                                    committee_index = attestation.committee_index(),
                                    slot = attestation.data().slot.as_u64(),
                                    "type" = "aggregated",
                                    "Failed to publish attestation"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    crit!(error = ?e, "Failed to sign aggregates");
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Spawn a blocking task to run the slashing protection pruning process.
    ///
    /// Start the task at `pruning_instant` to avoid interference with other tasks.
    fn spawn_slashing_protection_pruning_task(&self, slot: Slot, pruning_instant: Instant) {
        let attestation_service = self.clone();
        let executor = self.inner.executor.clone();
        let current_epoch = slot.epoch(S::E::slots_per_epoch());

        // Wait for `pruning_instant` in a regular task, and then switch to a blocking one.
        self.inner.executor.spawn(
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
    use slot_clock::ManualSlotClock;
    use types::{Epoch, MainnetEthSpec};

    #[test]
    fn duration_to_attestation_deadline_is_fork_aware() {
        type E = MainnetEthSpec;

        let mut spec = E::default_spec();
        let gloas_fork_epoch = Epoch::new(1);
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);

        let slot_duration = spec.get_slot_duration();
        let genesis_time = slot_duration;
        let slot_clock = ManualSlotClock::new(Slot::new(0), genesis_time, slot_duration);
        let first_gloas_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());
        let last_pre_gloas_slot = first_gloas_slot - 1;

        let test_cases = [
            (
                "pre-genesis",
                genesis_time - Duration::from_secs(1),
                slot_clock.genesis_slot(),
                Duration::from_millis(4999),
            ),
            (
                "pre-Gloas",
                slot_clock.start_of(last_pre_gloas_slot - 1).unwrap(),
                last_pre_gloas_slot,
                Duration::from_millis(15999),
            ),
            (
                "post-Gloas",
                slot_clock.start_of(last_pre_gloas_slot).unwrap(),
                first_gloas_slot,
                Duration::from_millis(15000),
            ),
        ];

        for (case, now, expected_slot, expected_duration) in test_cases {
            assert_eq!(
                attestation_deadline::<E>(&slot_clock, &spec, now),
                (expected_slot, Some(expected_duration)),
                "{case}"
            );
        }
    }

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
