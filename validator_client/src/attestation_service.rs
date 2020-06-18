use crate::{
    duties_service::{DutiesService, DutyAndProof},
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use futures::StreamExt;
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use slog::{crit, debug, error, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{delay_until, interval_at, Duration, Instant};
use types::{Attestation, ChainSpec, CommitteeIndex, EthSpec, Slot, SubnetId};

/// Builds an `AttestationService`.
pub struct AttestationServiceBuilder<T, E: EthSpec> {
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<T>,
    beacon_node: Option<RemoteBeaconNode<E>>,
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

    pub fn beacon_node(mut self, beacon_node: RemoteBeaconNode<E>) -> Self {
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
    beacon_node: RemoteBeaconNode<E>,
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
                    let validator_duties = map.entry(committee_index).or_insert_with(|| vec![]);

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
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#attesting
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
        if let Some(attestation) = attestation_opt {
            // First, wait until the `aggregation_production_instant` (2/3rds
            // of the way though the slot). As verified in the
            // `delay_triggers_when_in_the_past` test, this code will still run
            // even if the instant has already elapsed.
            delay_until(aggregate_production_instant).await;

            // Then download, sign and publish a `SignedAggregateAndProof` for each
            // validator that is elected to aggregate for this `slot` and
            // `committee_index`.
            self.produce_and_publish_aggregates(attestation, &validator_duties)
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
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#attesting
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
    ) -> Result<Option<Attestation<E>>, String> {
        let log = self.context.log();

        if validator_duties.is_empty() {
            return Ok(None);
        }

        let current_epoch = self
            .slot_clock
            .now()
            .ok_or_else(|| "Unable to determine current slot from clock".to_string())?
            .epoch(E::slots_per_epoch());

        let attestation = self
            .beacon_node
            .http
            .validator()
            .produce_attestation(slot, committee_index)
            .await
            .map_err(|e| format!("Failed to produce attestation: {:?}", e))?;

        // For each validator in `validator_duties`, clone the `attestation` and add
        // their signature.
        //
        // If any validator is unable to sign, they are simply skipped.
        let signed_attestations = validator_duties
            .iter()
            .filter_map(|duty| {
                // Ensure that all required fields are present in the validator duty.
                let (
                    duty_slot,
                    duty_committee_index,
                    validator_committee_position,
                    _,
                    committee_count_at_slot,
                ) = if let Some(tuple) = duty.attestation_duties() {
                    tuple
                } else {
                    crit!(
                        log,
                        "Missing validator duties when signing";
                        "duties" => format!("{:?}", duty)
                    );
                    return None;
                };

                // Ensure that the attestation matches the duties.
                if duty_slot != attestation.data.slot
                    || duty_committee_index != attestation.data.index
                {
                    crit!(
                        log,
                        "Inconsistent validator duties during signing";
                        "validator" => format!("{:?}", duty.validator_pubkey()),
                        "duty_slot" => duty_slot,
                        "attestation_slot" => attestation.data.slot,
                        "duty_index" => duty_committee_index,
                        "attestation_index" => attestation.data.index,
                    );
                    return None;
                }

                let mut attestation = attestation.clone();
                let subnet_id = SubnetId::compute_subnet_for_attestation_data::<E>(
                    &attestation.data,
                    committee_count_at_slot,
                    &self.context.eth2_config().spec,
                )
                .map_err(|e| {
                    error!(
                        log,
                        "Failed to compute subnet id to publish attestation: {:?}", e
                    )
                })
                .ok()?;
                self.validator_store
                    .sign_attestation(
                        duty.validator_pubkey(),
                        validator_committee_position,
                        &mut attestation,
                        current_epoch,
                    )
                    .map(|_| (attestation, subnet_id))
            })
            .collect::<Vec<_>>();

        // If there are any signed attestations, publish them to the BN. Otherwise,
        // just return early.
        if let Some(attestation) = signed_attestations.first().cloned() {
            let num_attestations = signed_attestations.len();
            let beacon_block_root = attestation.0.data.beacon_block_root;

            self.beacon_node
                .http
                .validator()
                .publish_attestations(signed_attestations)
                .await
                .map_err(|e| format!("Failed to publish attestation: {:?}", e))
                .map(move |publish_status| match publish_status {
                    PublishStatus::Valid => info!(
                        log,
                        "Successfully published attestations";
                        "count" => num_attestations,
                        "head_block" => format!("{:?}", beacon_block_root),
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                        "type" => "unaggregated",
                    ),
                    PublishStatus::Invalid(msg) => crit!(
                        log,
                        "Published attestation was invalid";
                        "message" => msg,
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                        "type" => "unaggregated",
                    ),
                    PublishStatus::Unknown => {
                        crit!(log, "Unknown condition when publishing unagg. attestation")
                    }
                })
                .map(|()| Some(attestation.0))
        } else {
            debug!(
                log,
                "No attestations to publish";
                "committee_index" => committee_index,
                "slot" => slot.as_u64(),
            );

            Ok(None)
        }
    }

    /// Performs the second step of the attesting process: downloading an aggregated `Attestation`,
    /// converting it into a `SignedAggregateAndProof` and returning it to the BN.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#broadcast-aggregate
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
        attestation: Attestation<E>,
        validator_duties: &[DutyAndProof],
    ) -> Result<(), String> {
        let log = self.context.log();

        let aggregated_attestation = self
            .beacon_node
            .http
            .validator()
            .produce_aggregate_attestation(&attestation.data)
            .await
            .map_err(|e| format!("Failed to produce an aggregate attestation: {:?}", e))?;

        // For each validator, clone the `aggregated_attestation` and convert it into
        // a `SignedAggregateAndProof`
        let signed_aggregate_and_proofs = validator_duties
            .iter()
            .filter_map(|duty_and_proof| {
                // Do not produce a signed aggregator for validators that are not
                // subscribed aggregators.
                let selection_proof = duty_and_proof.selection_proof.as_ref()?.clone();

                let (duty_slot, duty_committee_index, _, validator_index, _) =
                    duty_and_proof.attestation_duties().or_else(|| {
                        crit!(log, "Missing duties when signing aggregate");
                        None
                    })?;

                let pubkey = &duty_and_proof.duty.validator_pubkey;
                let slot = attestation.data.slot;
                let committee_index = attestation.data.index;

                if duty_slot != slot || duty_committee_index != committee_index {
                    crit!(log, "Inconsistent validator duties during signing");
                    return None;
                }

                if let Some(signed_aggregate_and_proof) =
                    self.validator_store.produce_signed_aggregate_and_proof(
                        pubkey,
                        validator_index,
                        aggregated_attestation.clone(),
                        selection_proof,
                    )
                {
                    Some(signed_aggregate_and_proof)
                } else {
                    crit!(log, "Failed to sign attestation");
                    None
                }
            })
            .collect::<Vec<_>>();

        // If there any signed aggregates and proofs were produced, publish them to the
        // BN.
        if let Some(first) = signed_aggregate_and_proofs.first().cloned() {
            let attestation = first.message.aggregate;

            let publish_status = self
                .beacon_node
                .http
                .validator()
                .publish_aggregate_and_proof(signed_aggregate_and_proofs)
                .await
                .map_err(|e| format!("Failed to publish aggregate and proofs: {:?}", e))?;
            match publish_status {
                PublishStatus::Valid => info!(
                    log,
                    "Successfully published attestations";
                    "signatures" => attestation.aggregation_bits.num_set_bits(),
                    "head_block" => format!("{:?}", attestation.data.beacon_block_root),
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                    "type" => "aggregated",
                ),
                PublishStatus::Invalid(msg) => crit!(
                    log,
                    "Published attestation was invalid";
                    "message" => msg,
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                    "type" => "aggregated",
                ),
                PublishStatus::Unknown => {
                    crit!(log, "Unknown condition when publishing agg. attestation")
                }
            };
            Ok(())
        } else {
            debug!(
                log,
                "No signed aggregates to publish";
                "committee_index" => attestation.data.index,
                "slot" => attestation.data.slot.as_u64(),
            );
            Ok(())
        }
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
