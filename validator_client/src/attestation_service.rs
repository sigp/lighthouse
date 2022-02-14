use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{
    duties_service::{DutiesService, DutyAndProof},
    http_metrics::metrics,
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use futures::future::join_all;
use slog::{crit, error, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use tree_hash::TreeHash;
use types::{
    AggregateSignature, Attestation, AttestationData, BitList, ChainSpec, CommitteeIndex, EthSpec,
    Slot,
};

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
                    .or_insert_with(Vec::new)
                    .push(duty_and_proof);
                map
            });

        // For each committee index for this slot:
        //
        // - Create and publish an `Attestation` for all required validators.
        // - Create and publish `SignedAggregateAndProof` for all aggregating validators.
        duties_by_committee_index
            .into_iter()
            .for_each(|(committee_index, validator_duties)| {
                // Spawn a separate task for each attestation.
                self.inner.context.executor.spawn_ignoring_error(
                    self.clone().publish_attestations_and_aggregates(
                        slot,
                        committee_index,
                        validator_duties,
                        aggregate_production_instant,
                    ),
                    "attestation publish",
                );
            });

        // Schedule pruning of the slashing protection database once all unaggregated
        // attestations have (hopefully) been signed, i.e. at the same time as aggregate
        // production.
        self.spawn_slashing_protection_pruning_task(slot, aggregate_production_instant);

        Ok(())
    }

    /// Performs the first step of the attesting process: downloading `Attestation` objects,
    /// signing them and returning them to the validator.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#attesting
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    async fn publish_attestations_and_aggregates(
        self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<DutyAndProof>,
        aggregate_production_instant: Instant,
    ) -> Result<(), ()> {
        let log = self.context.log();
        let attestations_timer = metrics::start_timer_vec(
            &metrics::ATTESTATION_SERVICE_TIMES,
            &[metrics::ATTESTATIONS],
        );

        // There's not need to produce `Attestation` or `SignedAggregateAndProof` if we do not have
        // any validators for the given `slot` and `committee_index`.
        if validator_duties.is_empty() {
            return Ok(());
        }

        // Step 1.
        //
        // Download, sign and publish an `Attestation` for each validator.
        let attestation_opt = self
            .produce_and_publish_attestations(slot, committee_index, &validator_duties)
            .await
            .map_err(move |e| {
                crit!(
                    log,
                    "Error during attestation routine";
                    "error" => format!("{:?}", e),
                    "committee_index" => committee_index,
                    "slot" => slot.as_u64(),
                )
            })?;

        drop(attestations_timer);

        // Step 2.
        //
        // If an attestation was produced, make an aggregate.
        if let Some(attestation_data) = attestation_opt {
            // First, wait until the `aggregation_production_instant` (2/3rds
            // of the way though the slot). As verified in the
            // `delay_triggers_when_in_the_past` test, this code will still run
            // even if the instant has already elapsed.
            sleep_until(aggregate_production_instant).await;

            // Start the metrics timer *after* we've done the delay.
            let _aggregates_timer = metrics::start_timer_vec(
                &metrics::ATTESTATION_SERVICE_TIMES,
                &[metrics::AGGREGATES],
            );

            // Then download, sign and publish a `SignedAggregateAndProof` for each
            // validator that is elected to aggregate for this `slot` and
            // `committee_index`.
            self.produce_and_publish_aggregates(&attestation_data, &validator_duties)
                .await
                .map_err(move |e| {
                    crit!(
                        log,
                        "Error during attestation routine";
                        "error" => format!("{:?}", e),
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                    )
                })?;
        }

        Ok(())
    }

    /// Performs the first step of the attesting process: downloading `Attestation` objects,
    /// signing them and returning them to the validator.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#attesting
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    ///
    /// Only one `Attestation` is downloaded from the BN. It is then cloned and signed by each
    /// validator and the list of individually-signed `Attestation` objects is returned to the BN.
    async fn produce_and_publish_attestations(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: &[DutyAndProof],
    ) -> Result<Option<AttestationData>, String> {
        let log = self.context.log();

        if validator_duties.is_empty() {
            return Ok(None);
        }

        let current_epoch = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?
            .epoch(E::slots_per_epoch());

        let attestation_data = self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::ATTESTATIONS_HTTP_GET],
                );
                beacon_node
                    .get_validator_attestation_data(slot, committee_index)
                    .await
                    .map_err(|e| format!("Failed to produce attestation data: {:?}", e))
                    .map(|result| result.data)
            })
            .await
            .map_err(|e| e.to_string())?;

        // Create futures to produce signed `Attestation` objects.
        let attestation_data_ref = &attestation_data;
        let signing_futures = validator_duties.iter().map(|duty_and_proof| async move {
            let duty = &duty_and_proof.duty;
            let attestation_data = attestation_data_ref;

            // Ensure that the attestation matches the duties.
            #[allow(clippy::suspicious_operation_groupings)]
            if duty.slot != attestation_data.slot || duty.committee_index != attestation_data.index
            {
                crit!(
                    log,
                    "Inconsistent validator duties during signing";
                    "validator" => ?duty.pubkey,
                    "duty_slot" => duty.slot,
                    "attestation_slot" => attestation_data.slot,
                    "duty_index" => duty.committee_index,
                    "attestation_index" => attestation_data.index,
                );
                return None;
            }

            let mut attestation = Attestation {
                aggregation_bits: BitList::with_capacity(duty.committee_length as usize).unwrap(),
                data: attestation_data.clone(),
                signature: AggregateSignature::infinity(),
            };

            match self
                .validator_store
                .sign_attestation(
                    duty.pubkey,
                    duty.validator_committee_index as usize,
                    &mut attestation,
                    current_epoch,
                )
                .await
            {
                Ok(()) => Some(attestation),
                Err(e) => {
                    crit!(
                        log,
                        "Failed to sign attestation";
                        "error" => ?e,
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                    );
                    None
                }
            }
        });

        // Execute all the futures in parallel, collecting any successful results.
        let attestations = &join_all(signing_futures)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<Attestation<E>>>();

        // Post the attestations to the BN.
        match self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::ATTESTATIONS_HTTP_POST],
                );
                beacon_node
                    .post_beacon_pool_attestations(attestations)
                    .await
            })
            .await
        {
            Ok(()) => info!(
                log,
                "Successfully published attestations";
                "count" => attestations.len(),
                "head_block" => ?attestation_data.beacon_block_root,
                "committee_index" => attestation_data.index,
                "slot" => attestation_data.slot.as_u64(),
                "type" => "unaggregated",
            ),
            Err(e) => error!(
                log,
                "Unable to publish attestations";
                "error" => %e,
                "committee_index" => attestation_data.index,
                "slot" => slot.as_u64(),
                "type" => "unaggregated",
            ),
        }

        Ok(Some(attestation_data))
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
    async fn produce_and_publish_aggregates(
        &self,
        attestation_data: &AttestationData,
        validator_duties: &[DutyAndProof],
    ) -> Result<(), String> {
        let log = self.context.log();

        let aggregated_attestation = &self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::ATTESTATION_SERVICE_TIMES,
                    &[metrics::AGGREGATES_HTTP_GET],
                );
                beacon_node
                    .get_validator_aggregate_attestation(
                        attestation_data.slot,
                        attestation_data.tree_hash_root(),
                    )
                    .await
                    .map_err(|e| format!("Failed to produce an aggregate attestation: {:?}", e))?
                    .ok_or_else(|| format!("No aggregate available for {:?}", attestation_data))
                    .map(|result| result.data)
            })
            .await
            .map_err(|e| e.to_string())?;

        // Create futures to produce the signed aggregated attestations.
        let signing_futures = validator_duties.iter().map(|duty_and_proof| async move {
            let duty = &duty_and_proof.duty;
            let selection_proof = duty_and_proof.selection_proof.as_ref()?;

            let slot = attestation_data.slot;
            let committee_index = attestation_data.index;

            if duty.slot != slot || duty.committee_index != committee_index {
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
                Err(e) => {
                    crit!(
                        log,
                        "Failed to sign attestation";
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
                .first_success(RequireSynced::No, |beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::ATTESTATION_SERVICE_TIMES,
                        &[metrics::AGGREGATES_HTTP_POST],
                    );
                    beacon_node
                        .post_validator_aggregate_and_proof(signed_aggregate_and_proofs_slice)
                        .await
                })
                .await
            {
                Ok(()) => {
                    for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                        let attestation = &signed_aggregate_and_proof.message.aggregate;
                        info!(
                            log,
                            "Successfully published attestations";
                            "aggregator" => signed_aggregate_and_proof.message.aggregator_index,
                            "signatures" => attestation.aggregation_bits.num_set_bits(),
                            "head_block" => format!("{:?}", attestation.data.beacon_block_root),
                            "committee_index" => attestation.data.index,
                            "slot" => attestation.data.slot.as_u64(),
                            "type" => "aggregated",
                        );
                    }
                }
                Err(e) => {
                    for signed_aggregate_and_proof in signed_aggregate_and_proofs {
                        let attestation = &signed_aggregate_and_proof.message.aggregate;
                        crit!(
                            log,
                            "Failed to publish attestation";
                            "error" => %e,
                            "committee_index" => attestation.data.index,
                            "slot" => attestation.data.slot.as_u64(),
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
