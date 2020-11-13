use crate::{
    duties_service::{DutiesService, DutyAndProof},
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use futures::StreamExt;
use slog::{crit, error, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{delay_until, interval_at, Duration, Instant};
use tree_hash::TreeHash;
use types::{
    AggregateSignature, Attestation, AttestationData, BitList, ChainSpec, CommitteeIndex, EthSpec,
    Slot,
};

/// Builds an `AttestationService`.
pub struct AttestationServiceBuilder<T, E: EthSpec> {
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<T>,
    beacon_node: Option<BeaconNodeHttpClient>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
    }

    pub fn duties_service(mut self, service: DutiesService<T, E>) -> Self {
        self.duties_service = Some(service);
        self
    }

    pub fn validator_store(mut self, store: ValidatorStore<T, E>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_node(mut self, beacon_node: BeaconNodeHttpClient) -> Self {
        self.beacon_node = Some(beacon_node);
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
                    .ok_or_else(|| "Cannot build AttestationService without duties_service")?,
                validator_store: self
                    .validator_store
                    .ok_or_else(|| "Cannot build AttestationService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build AttestationService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build AttestationService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build AttestationService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    duties_service: DutiesService<T, E>,
    validator_store: ValidatorStore<T, E>,
    slot_clock: T,
    beacon_node: BeaconNodeHttpClient,
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

        let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        info!(
            log,
            "Attestation production service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
        );

        let mut interval = {
            // Note: `interval_at` panics if `slot_duration` is 0
            interval_at(
                Instant::now() + duration_to_next_slot + slot_duration / 3,
                slot_duration,
            )
        };

        let executor = self.context.executor.clone();

        let interval_fut = async move {
            while interval.next().await.is_some() {
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
            }
        };

        executor.spawn(interval_fut, "attestation_service");
        Ok(())
    }

    /// For each each required attestation, spawn a new task that downloads, signs and uploads the
    /// attestation to the beacon node.
    fn spawn_attestation_tasks(&self, slot_duration: Duration) -> Result<(), String> {
        let slot = self
            .slot_clock
            .now()
            .ok_or_else(|| "Failed to read slot clock".to_string())?;
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

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
                if let Some(committee_index) = duty_and_proof.duty.attestation_committee_index {
                    let validator_duties = map.entry(committee_index).or_insert_with(Vec::new);

                    validator_duties.push(duty_and_proof);
                }

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
                self.inner.context.executor.runtime_handle().spawn(
                    self.clone().publish_attestations_and_aggregates(
                        slot,
                        committee_index,
                        validator_duties,
                        aggregate_production_instant,
                    ),
                );
            });

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

        // Step 2.
        //
        // If an attestation was produced, make an aggregate.
        if let Some(attestation_data) = attestation_opt {
            // First, wait until the `aggregation_production_instant` (2/3rds
            // of the way though the slot). As verified in the
            // `delay_triggers_when_in_the_past` test, this code will still run
            // even if the instant has already elapsed.
            delay_until(aggregate_production_instant).await;

            // Then download, sign and publish a `SignedAggregateAndProof` for each
            // validator that is elected to aggregate for this `slot` and
            // `committee_index`.
            self.produce_and_publish_aggregates(attestation_data, &validator_duties)
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
            .ok_or_else(|| "Unable to determine current slot from clock".to_string())?
            .epoch(E::slots_per_epoch());

        let attestation_data = self
            .beacon_node
            .get_validator_attestation_data(slot, committee_index)
            .await
            .map_err(|e| format!("Failed to produce attestation data: {:?}", e))?
            .data;

        for duty in validator_duties {
            // Ensure that all required fields are present in the validator duty.
            let (
                duty_slot,
                duty_committee_index,
                validator_committee_position,
                _,
                _,
                committee_length,
            ) = if let Some(tuple) = duty.attestation_duties() {
                tuple
            } else {
                crit!(
                    log,
                    "Missing validator duties when signing";
                    "duties" => format!("{:?}", duty)
                );
                continue;
            };

            // Ensure that the attestation matches the duties.
            if duty_slot != attestation_data.slot || duty_committee_index != attestation_data.index
            {
                crit!(
                    log,
                    "Inconsistent validator duties during signing";
                    "validator" => format!("{:?}", duty.validator_pubkey()),
                    "duty_slot" => duty_slot,
                    "attestation_slot" => attestation_data.slot,
                    "duty_index" => duty_committee_index,
                    "attestation_index" => attestation_data.index,
                );
                continue;
            }

            let mut attestation = Attestation {
                aggregation_bits: BitList::with_capacity(committee_length as usize).unwrap(),
                data: attestation_data.clone(),
                signature: AggregateSignature::infinity(),
            };

            self.validator_store
                .sign_attestation(
                    duty.validator_pubkey(),
                    validator_committee_position,
                    &mut attestation,
                    current_epoch,
                )
                .ok_or_else(|| "Failed to sign attestation".to_string())?;

            match self
                .beacon_node
                .post_beacon_pool_attestations(&attestation)
                .await
            {
                Ok(()) => info!(
                    log,
                    "Successfully published attestation";
                    "head_block" => format!("{:?}", attestation.data.beacon_block_root),
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                    "type" => "unaggregated",
                ),
                Err(e) => error!(
                    log,
                    "Unable to publish attestation";
                    "error" => e.to_string(),
                    "committee_index" => attestation.data.index,
                    "slot" => slot.as_u64(),
                    "type" => "unaggregated",
                ),
            }
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
        attestation_data: AttestationData,
        validator_duties: &[DutyAndProof],
    ) -> Result<(), String> {
        let log = self.context.log();

        let aggregated_attestation = self
            .beacon_node
            .get_validator_aggregate_attestation(
                attestation_data.slot,
                attestation_data.tree_hash_root(),
            )
            .await
            .map_err(|e| format!("Failed to produce an aggregate attestation: {:?}", e))?
            .ok_or_else(|| format!("No aggregate available for {:?}", attestation_data))?
            .data;

        let mut signed_aggregate_and_proofs = Vec::new();

        for duty_and_proof in validator_duties {
            let selection_proof = if let Some(proof) = duty_and_proof.selection_proof.as_ref() {
                proof
            } else {
                // Do not produce a signed aggregate for validators that are not
                // subscribed aggregators.
                continue;
            };
            let (duty_slot, duty_committee_index, _, validator_index, _, _) =
                if let Some(tuple) = duty_and_proof.attestation_duties() {
                    tuple
                } else {
                    crit!(log, "Missing duties when signing aggregate");
                    continue;
                };

            let pubkey = &duty_and_proof.duty.validator_pubkey;
            let slot = attestation_data.slot;
            let committee_index = attestation_data.index;

            if duty_slot != slot || duty_committee_index != committee_index {
                crit!(log, "Inconsistent validator duties during signing");
                continue;
            }

            if let Some(aggregate) = self.validator_store.produce_signed_aggregate_and_proof(
                pubkey,
                validator_index,
                aggregated_attestation.clone(),
                selection_proof.clone(),
            ) {
                signed_aggregate_and_proofs.push(aggregate);
            } else {
                crit!(log, "Failed to sign attestation");
                continue;
            };
        }

        if !signed_aggregate_and_proofs.is_empty() {
            match self
                .beacon_node
                .post_validator_aggregate_and_proof(signed_aggregate_and_proofs.as_slice())
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
                            "error" => e.to_string(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;
    use parking_lot::RwLock;

    /// This test is to ensure that a `tokio_timer::Delay` with an instant in the past will still
    /// trigger.
    #[tokio::test]
    async fn delay_triggers_when_in_the_past() {
        let in_the_past = Instant::now() - Duration::from_secs(2);
        let state_1 = Arc::new(RwLock::new(in_the_past));
        let state_2 = state_1.clone();

        delay_until(in_the_past)
            .map(move |()| *state_1.write() = Instant::now())
            .await;

        assert!(
            *state_2.read() > in_the_past,
            "state should have been updated"
        );
    }
}
