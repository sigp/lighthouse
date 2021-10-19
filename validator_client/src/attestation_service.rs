use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::Config;
use crate::{
    duties_service::{DutiesService, DutyAndProof},
    http_metrics::metrics,
    validator_store::ValidatorStore,
    ProductionValidatorClient,
};
use bls::Hash256;
use environment::RuntimeContext;
use slog::{crit, error, info, trace, warn, Logger};
use futures::future::join_all;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::broadcast;
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

#[derive(Clone)]
pub enum SignMessageEvent {
    Head { root: Hash256, slot: Slot },
    Time(Slot),
}

impl SignMessageEvent {
    pub fn slot(&self) -> Slot {
        match self {
            SignMessageEvent::Head { root: _, slot } => *slot,
            SignMessageEvent::Time(slot) => *slot,
        }
    }
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationService<T, E> {
    /// Starts the service which periodically produces attestations.
    pub fn start_update_service(
        self,
        spec: &ChainSpec,
        mut rx_opt: Option<broadcast::Receiver<Hash256>>,
    ) -> Result<(), String> {
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
                //TODO: issue here is that we are looping 15ish seconds each time, so skipping duties
                // should start at 1/3 through next slot (or 1/3 through this slot?) and then sleep every 12 seconds
                if let (Some(duration_to_next_slot), Some(current_slot)) = (
                    self.slot_clock.duration_to_next_slot(),
                    self.slot_clock.now(),
                ) {
                    info!(log,"duration_to_next_slot: {:?}",duration_to_next_slot);
                    info!(log,"current_slot: {:?}",current_slot);
                    info!(log,"sleep_time: {:?}", (duration_to_next_slot + slot_duration / 3));
                    let log = self.context.log();
                    let attestation_slot = current_slot + 1;

                    let event: SignMessageEvent = if let Some(ref mut rx) = rx_opt {
                        tokio::select! {
                            Ok(root) = {
                                sleep(duration_to_next_slot).await;
                                rx.recv()
                            } => {
                                info!(log, "Head event received"; "head_root" => ?root);
                                SignMessageEvent::Head{root, slot: attestation_slot}
                            },
                            _ = sleep(duration_to_next_slot + slot_duration / 3) => {
                                info!(log, "Head event not received");
                                SignMessageEvent::Time(attestation_slot)
                            },
                        }
                    } else {
                        sleep(duration_to_next_slot + slot_duration / 3).await;
                        SignMessageEvent::Time(attestation_slot)
                    };

                    if let Err(e) = self.spawn_attestation_tasks(slot_duration, event, log) {
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
    fn spawn_attestation_tasks(
        &self,
        slot_duration: Duration,
        event: SignMessageEvent,
        log: &Logger,
    ) -> Result<(), String> {
        let slot = self.slot_clock.now().ok_or("Unable to determine current slot")?;

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_slot(slot + 1)
            .ok_or("Unable to determine duration to next slot")?;

        // If a validator needs to publish an aggregate attestation, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_sub(slot_duration / 3)
                .unwrap_or_else(|| Duration::from_secs(0));

        info!(log, "Attesters: {}", self.duties_service.attesters(slot).len());
        info!(log, "slot: {}", slot);
        info!(log, "aggregate_production_instant: {:?}", aggregate_production_instant);

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

        info!(log, "Here1");
        info!(log, "duties_by_committee_index: {:?}", duties_by_committee_index.len());


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
                        committee_index,
                        validator_duties,
                        aggregate_production_instant,
                        event.clone(),
                    ),
                    "attestation publish",
                );
            });

        info!(log, "Here2");


        // Schedule pruning of the slashing protection database once all unaggregated
        // attestations have (hopefully) been signed, i.e. at the same time as aggregate
        // production.
        self.spawn_slashing_protection_pruning_task(slot, aggregate_production_instant);
        info!(log, "Here3");

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
        committee_index: CommitteeIndex,
        validator_duties: Vec<DutyAndProof>,
        aggregate_production_instant: Instant,
        event: SignMessageEvent,
    ) -> Result<(), ()> {
        let slot = event.slot();
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
            .produce_and_publish_attestations(committee_index, &validator_duties, event)
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
        committee_index: CommitteeIndex,
        validator_duties: &[DutyAndProof],
        event: SignMessageEvent,
    ) -> Result<Option<AttestationData>, String> {
        let log = self.context.log();
        let slot = event.slot();

        if validator_duties.is_empty() {
            return Ok(None);
        }

        let current_epoch = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?
            .epoch(E::slots_per_epoch());

        let mut attestation_data = self
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

        match event {
            SignMessageEvent::Head {
                root,
                slot: attestation_slot,
            } => {
                info!(log, "Attestation production triggered by event"; "root" => ?root, "attestation_data_root" => ?attestation_data.beacon_block_root);
                if root != attestation_data.beacon_block_root {
                    let duration_until_att_production = self
                        .slot_clock
                        .duration_until_start_of(attestation_slot)
                        .ok_or("Unable to read slot clock")?
                        + self.slot_clock.unagg_attestation_production_delay();

                    warn!(log, "Head from event stream does not match current connected beacon node's head. Retrying at one-third through the slot"; "event_root" => ?root, "head_root" => ?attestation_data.beacon_block_root, "ms_until_att_production" => ?duration_until_att_production.as_millis());

                    sleep(duration_until_att_production).await;
                    attestation_data = self
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
                        .map_err(|e| e.to_string())?
                }
            }
            SignMessageEvent::Time(_) => {}
        }

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
    use crate::{duties_service, ProductionValidatorClient};
    use bls::{Hash256, PublicKeyBytes};
    use env_logger;
    use environment::EnvironmentBuilder;
    use eth2::types::{GenericResponse, GenesisData, SyncingData, VersionData, ValidatorData, Validator, ValidatorStatus};
    use futures::future::FutureExt;
    use httpmock::prelude::*;
    use httpmock::Mock;
    use parking_lot::RwLock;
    use sensitive_url::SensitiveUrl;
    use serde::Serialize;
    use slot_clock::SystemTimeSlotClock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::Builder as TempBuilder;
    use tokio::runtime::Runtime;
    use types::{Checkpoint, ConfigAndPreset, Domain, Epoch, MainnetEthSpec, SignedRoot};
    use validator_dir::insecure_keys::build_deterministic_validator_dirs;
    use mock_beacon::MockBeacon;
    use task_executor::ShutdownReason;

    // /// This test is to ensure that a `tokio_timer::Sleep` with an instant in the past will still
    // /// trigger.
    // #[tokio::test]
    // async fn delay_triggers_when_in_the_past() {
    //     let in_the_past = Instant::now() - Duration::from_secs(2);
    //     let state_1 = Arc::new(RwLock::new(in_the_past));
    //     let state_2 = state_1.clone();
    //
    //     sleep_until(in_the_past)
    //         .map(move |()| *state_1.write() = Instant::now())
    //         .await;
    //
    //     assert!(
    //         *state_2.read() > in_the_past,
    //         "state should have been updated"
    //     );
    // }

    // Builds a runtime to be used in the testing configuration.
    fn build_runtime() -> Arc<Runtime> {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Should be able to build a testing runtime"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validator_enabling() {
        let validators_per_node = 20;
        // Generate the directories and keystores required for the validator clients.
        let indices = (0..validators_per_node).collect::<Vec<_>>();

        let datadir = TempBuilder::new()
            .prefix("lighthouse-validator-client")
            .tempdir()
            .map_err(|e| format!("Unable to create VC data dir: {:?}", e))
            .unwrap();

        let secrets_dir = TempBuilder::new()
            .prefix("lighthouse-validator-client-secrets")
            .tempdir()
            .map_err(|e| format!("Unable to create VC secrets dir: {:?}", e))
            .unwrap();

        build_deterministic_validator_dirs(
            datadir.path().into(),
            secrets_dir.path().into(),
            indices.as_slice(),
        )
        .map_err(|e| format!("Unable to build validator directories: {:?}", e))
        .unwrap();

        let mut env = EnvironmentBuilder::mainnet()
            .async_logger("debug", None)
            .unwrap()
            .multi_threaded_tokio_runtime()
            .unwrap()
            .build()
            .unwrap();
        let mut context = env.core_context();
        // context.eth2_config.spec.seconds_per_slot = 3;
        context.eth2_config.spec.min_genesis_time = 0;
        context.eth2_config.spec.min_genesis_active_validator_count = 20;

        let log = context.log();

        info!(log, "Secrets dir"; "secrets_dir" => ?secrets_dir);
        info!(log, "Datadir"; "datadir" => ?datadir);
        let mock_server = MockServer::start();
        let spec = context.eth2_config.spec.clone();

        let mut mock_beacon : MockBeacon<MainnetEthSpec> = MockBeacon::default(&mock_server, &spec);

        let mut config = Config {
            init_slashing_protection: true,
            disable_auto_discover: false,
            validator_dir: datadir.into_path(),
            secrets_dir: secrets_dir.into_path(),
            beacon_nodes: vec![mock_beacon.url()],
            ..Config::default()
        };
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let spec = context.eth2_config.spec.clone();

        async move {
            //TODO: add timeout to VC initialization
            let mut shutdown_sender = context.executor.shutdown_sender();
            let exit = context.executor.exit();
            let validator = ProductionValidatorClient::new(context, config).await.unwrap();
            let slot_clock = validator.duties_service.slot_clock.clone();

            //TODO: check if indices are ordered and start at 0
            let index_pubkey = validator.validator_store.initialized_validators().read().iter_voting_pubkeys().cloned().enumerate().collect::<Vec<_>>();
            let mock_beacon = mock_beacon.slot_clock(slot_clock).validators_exist(index_pubkey.as_slice());

            let duration_to_next_slot = validator.duties_service.slot_clock.duration_to_next_slot().unwrap();
            sleep(duration_to_next_slot).await;

            // loop update BN response per slot
            duties_service::start_update_service(validator.duties_service.clone(), tx);
            let (_,mut rx) = broadcast::channel(10);
            validator.attestation_service.start_update_service(&spec, Some(rx));

            sleep(Duration::from_secs(2 * spec.seconds_per_slot)).await;
            shutdown_sender.try_send(ShutdownReason::Success("Ending test"));
            exit.await;
        }.await;

    }
}
