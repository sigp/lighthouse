use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{duties_service::DutiesService, validator_store::ValidatorStore};
use environment::RuntimeContext;
use eth2::types::BlockId;
use futures::future::join_all;
use futures::future::FutureExt;
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use types::{
    ChainSpec, EthSpec, Hash256, PublicKeyBytes, Slot, SyncCommitteeSubscription,
    SyncContributionData, SyncDuty, SyncSelectionProof, SyncSubnetId,
};

pub const SUBSCRIPTION_LOOKAHEAD_EPOCHS: u64 = 4;

pub struct SyncCommitteeService<T: SlotClock + 'static, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> Clone for SyncCommitteeService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: SlotClock + 'static, E: EthSpec> Deref for SyncCommitteeService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

pub struct Inner<T: SlotClock + 'static, E: EthSpec> {
    duties_service: Arc<DutiesService<T, E>>,
    validator_store: Arc<ValidatorStore<T, E>>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
    /// Boolean to track whether the service has posted subscriptions to the BN at least once.
    ///
    /// This acts as a latch that fires once upon start-up, and then never again.
    first_subscription_done: AtomicBool,
}

impl<T: SlotClock + 'static, E: EthSpec> SyncCommitteeService<T, E> {
    pub fn new(
        duties_service: Arc<DutiesService<T, E>>,
        validator_store: Arc<ValidatorStore<T, E>>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
        context: RuntimeContext<E>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                context,
                first_subscription_done: AtomicBool::new(false),
            }),
        }
    }

    /// Check if the Altair fork has been activated and therefore sync duties should be performed.
    ///
    /// Slot clock errors are mapped to `false`.
    fn altair_fork_activated(&self) -> bool {
        self.duties_service
            .spec
            .altair_fork_epoch
            .and_then(|fork_epoch| {
                let current_epoch = self.slot_clock.now()?.epoch(E::slots_per_epoch());
                Some(current_epoch >= fork_epoch)
            })
            .unwrap_or(false)
    }

    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();
        let slot_duration = Duration::from_secs(spec.seconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            log,
            "Sync committee service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
        );

        let executor = self.context.executor.clone();

        let interval_fut = async move {
            loop {
                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    // Wait for contribution broadcast interval 1/3 of the way through the slot.
                    let log = self.context.log();
                    sleep(duration_to_next_slot + slot_duration / 3).await;

                    // Do nothing if the Altair fork has not yet occurred.
                    if !self.altair_fork_activated() {
                        continue;
                    }

                    if let Err(e) = self.spawn_contribution_tasks(slot_duration).await {
                        crit!(
                            log,
                            "Failed to spawn sync contribution tasks";
                            "error" => e
                        )
                    } else {
                        trace!(
                            log,
                            "Spawned sync contribution tasks";
                        )
                    }

                    // Do subscriptions for future slots/epochs.
                    self.spawn_subscription_tasks();
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                }
            }
        };

        executor.spawn(interval_fut, "sync_committee_service");
        Ok(())
    }

    async fn spawn_contribution_tasks(&self, slot_duration: Duration) -> Result<(), String> {
        let log = self.context.log().clone();
        let slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        // If a validator needs to publish a sync aggregate, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_sub(slot_duration / 3)
                .unwrap_or_else(|| Duration::from_secs(0));

        let slot_duties = self
            .duties_service
            .sync_duties
            .get_duties_for_slot::<E>(slot, &self.duties_service.spec)
            .ok_or_else(|| format!("Error fetching duties for slot {}", slot))?;

        if slot_duties.duties.is_empty() {
            debug!(
                log,
                "No local validators in current sync committee";
                "slot" => slot,
            );
            return Ok(());
        }

        // Fetch block root for `SyncCommitteeContribution`.
        let block_root = self
            .beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node.get_beacon_blocks_root(BlockId::Head).await
            })
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("No block root found for slot {}", slot))?
            .data
            .root;

        // Spawn one task to publish all of the sync committee signatures.
        let validator_duties = slot_duties.duties;
        let service = self.clone();
        self.inner.context.executor.spawn(
            async move {
                service
                    .publish_sync_committee_signatures(slot, block_root, validator_duties)
                    .map(|_| ())
                    .await
            },
            "sync_committee_signature_publish",
        );

        let aggregators = slot_duties.aggregators;
        let service = self.clone();
        self.inner.context.executor.spawn(
            async move {
                service
                    .publish_sync_committee_aggregates(
                        slot,
                        block_root,
                        aggregators,
                        aggregate_production_instant,
                    )
                    .map(|_| ())
                    .await
            },
            "sync_committee_aggregate_publish",
        );

        Ok(())
    }

    /// Publish sync committee signatures.
    async fn publish_sync_committee_signatures(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        validator_duties: Vec<SyncDuty>,
    ) -> Result<(), ()> {
        let log = self.context.log();

        // Create futures to produce sync committee signatures.
        let signature_futures = validator_duties.iter().map(|duty| async move {
            match self
                .validator_store
                .produce_sync_committee_signature(
                    slot,
                    beacon_block_root,
                    duty.validator_index,
                    &duty.pubkey,
                )
                .await
            {
                Ok(signature) => Some(signature),
                Err(e) => {
                    crit!(
                        log,
                        "Failed to sign sync committee signature";
                        "validator_index" => duty.validator_index,
                        "slot" => slot,
                        "error" => ?e,
                    );
                    None
                }
            }
        });

        // Execute all the futures in parallel, collecting any successful results.
        let committee_signatures = &join_all(signature_futures)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        self.beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .post_beacon_pool_sync_committee_signatures(committee_signatures)
                    .await
            })
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to publish sync committee messages";
                    "slot" => slot,
                    "error" => %e,
                );
            })?;

        info!(
            log,
            "Successfully published sync committee messages";
            "count" => committee_signatures.len(),
            "head_block" => ?beacon_block_root,
            "slot" => slot,
        );

        Ok(())
    }

    async fn publish_sync_committee_aggregates(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        aggregators: HashMap<SyncSubnetId, Vec<(u64, PublicKeyBytes, SyncSelectionProof)>>,
        aggregate_instant: Instant,
    ) {
        for (subnet_id, subnet_aggregators) in aggregators {
            let service = self.clone();
            self.inner.context.executor.spawn(
                async move {
                    service
                        .publish_sync_committee_aggregate_for_subnet(
                            slot,
                            beacon_block_root,
                            subnet_id,
                            subnet_aggregators,
                            aggregate_instant,
                        )
                        .map(|_| ())
                        .await
                },
                "sync_committee_aggregate_publish_subnet",
            );
        }
    }

    async fn publish_sync_committee_aggregate_for_subnet(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        subnet_id: SyncSubnetId,
        subnet_aggregators: Vec<(u64, PublicKeyBytes, SyncSelectionProof)>,
        aggregate_instant: Instant,
    ) -> Result<(), ()> {
        sleep_until(aggregate_instant).await;

        let log = self.context.log();

        let contribution = &self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let sync_contribution_data = SyncContributionData {
                    slot,
                    beacon_block_root,
                    subcommittee_index: subnet_id.into(),
                };

                beacon_node
                    .get_validator_sync_committee_contribution::<E>(&sync_contribution_data)
                    .await
            })
            .await
            .map_err(|e| {
                crit!(
                    log,
                    "Failed to produce sync contribution";
                    "slot" => slot,
                    "beacon_block_root" => ?beacon_block_root,
                    "error" => %e,
                )
            })?
            .ok_or_else(|| {
                crit!(
                    log,
                    "No aggregate contribution found";
                    "slot" => slot,
                    "beacon_block_root" => ?beacon_block_root,
                );
            })?
            .data;

        // Create futures to produce signed contributions.
        let signature_futures = subnet_aggregators.into_iter().map(
            |(aggregator_index, aggregator_pk, selection_proof)| async move {
                match self
                    .validator_store
                    .produce_signed_contribution_and_proof(
                        aggregator_index,
                        aggregator_pk,
                        contribution.clone(),
                        selection_proof,
                    )
                    .await
                {
                    Ok(signed_contribution) => Some(signed_contribution),
                    Err(e) => {
                        crit!(
                            log,
                            "Unable to sign sync committee contribution";
                            "slot" => slot,
                            "error" => ?e,
                        );
                        None
                    }
                }
            },
        );

        // Execute all the futures in parallel, collecting any successful results.
        let signed_contributions = &join_all(signature_futures)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // Publish to the beacon node.
        self.beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .post_validator_contribution_and_proofs(signed_contributions)
                    .await
            })
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to publish signed contributions and proofs";
                    "slot" => slot,
                    "error" => %e,
                );
            })?;

        info!(
            log,
            "Successfully published sync contributions";
            "subnet" => %subnet_id,
            "beacon_block_root" => %beacon_block_root,
            "num_signers" => contribution.aggregation_bits.num_set_bits(),
            "slot" => slot,
        );

        Ok(())
    }

    fn spawn_subscription_tasks(&self) {
        let service = self.clone();
        let log = self.context.log().clone();
        self.inner.context.executor.spawn(
            async move {
                service.publish_subscriptions().await.unwrap_or_else(|e| {
                    error!(
                        log,
                        "Error publishing subscriptions";
                        "error" => ?e,
                    )
                });
            },
            "sync_committee_subscription_publish",
        );
    }

    async fn publish_subscriptions(self) -> Result<(), String> {
        let log = self.context.log().clone();
        let spec = &self.duties_service.spec;
        let slot = self.slot_clock.now().ok_or("Failed to read slot clock")?;

        let mut duty_slots = vec![];
        let mut all_succeeded = true;

        // At the start of every epoch during the current period, re-post the subscriptions
        // to the beacon node. This covers the case where the BN has forgotten the subscriptions
        // due to a restart, or where the VC has switched to a fallback BN.
        let current_period = sync_period_of_slot::<E>(slot, spec)?;

        if !self.first_subscription_done.load(Ordering::Relaxed)
            || slot.as_u64() % E::slots_per_epoch() == 0
        {
            duty_slots.push((slot, current_period));
        }

        // Near the end of the current period, push subscriptions for the next period to the
        // beacon node. We aggressively push every slot in the lead-up, as this is the main way
        // that we want to ensure that the BN is subscribed (well in advance).
        let lookahead_slot = slot + SUBSCRIPTION_LOOKAHEAD_EPOCHS * E::slots_per_epoch();

        let lookahead_period = sync_period_of_slot::<E>(lookahead_slot, spec)?;

        if lookahead_period > current_period {
            duty_slots.push((lookahead_slot, lookahead_period));
        }

        if duty_slots.is_empty() {
            return Ok(());
        }

        // Collect subscriptions.
        let mut subscriptions = vec![];

        for (duty_slot, sync_committee_period) in duty_slots {
            debug!(
                log,
                "Fetching subscription duties";
                "duty_slot" => duty_slot,
                "current_slot" => slot,
            );
            match self
                .duties_service
                .sync_duties
                .get_duties_for_slot::<E>(duty_slot, spec)
            {
                Some(duties) => subscriptions.extend(subscriptions_from_sync_duties(
                    duties.duties,
                    sync_committee_period,
                    spec,
                )),
                None => {
                    warn!(
                        log,
                        "Missing duties for subscription";
                        "slot" => duty_slot,
                    );
                    all_succeeded = false;
                }
            }
        }

        // Post subscriptions to BN.
        debug!(
            log,
            "Posting sync subscriptions to BN";
            "count" => subscriptions.len(),
        );
        let subscriptions_slice = &subscriptions;

        for subscription in subscriptions_slice {
            debug!(
                log,
                "Subscription";
                "validator_index" => subscription.validator_index,
                "validator_sync_committee_indices" => ?subscription.sync_committee_indices,
                "until_epoch" => subscription.until_epoch,
            );
        }

        if let Err(e) = self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .post_validator_sync_committee_subscriptions(subscriptions_slice)
                    .await
            })
            .await
        {
            error!(
                log,
                "Unable to post sync committee subscriptions";
                "slot" => slot,
                "error" => %e,
            );
            all_succeeded = false;
        }

        // Disable first-subscription latch once all duties have succeeded once.
        if all_succeeded {
            self.first_subscription_done.store(true, Ordering::Relaxed);
        }

        Ok(())
    }
}

fn sync_period_of_slot<E: EthSpec>(slot: Slot, spec: &ChainSpec) -> Result<u64, String> {
    slot.epoch(E::slots_per_epoch())
        .sync_committee_period(spec)
        .map_err(|e| format!("Error computing sync period: {:?}", e))
}

fn subscriptions_from_sync_duties(
    duties: Vec<SyncDuty>,
    sync_committee_period: u64,
    spec: &ChainSpec,
) -> impl Iterator<Item = SyncCommitteeSubscription> {
    let until_epoch = spec.epochs_per_sync_committee_period * (sync_committee_period + 1);
    duties
        .into_iter()
        .map(move |duty| SyncCommitteeSubscription {
            validator_index: duty.validator_index,
            sync_committee_indices: duty.validator_sync_committee_indices,
            until_epoch,
        })
}
