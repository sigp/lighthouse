use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, EthSpec, ProposerPreferences};
use validator_store::{DoppelgangerStatus, ValidatorStore};

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
}

pub struct ProposerPreferencesService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for ProposerPreferencesService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for ProposerPreferencesService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> ProposerPreferencesService<S, T> {
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                executor,
                chain_spec,
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        let slot_duration = self.chain_spec.get_slot_duration();
        info!("Proposer preferences service started");

        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                let Some(current_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };

                if !self
                    .chain_spec
                    .fork_name_at_slot::<S::E>(current_slot)
                    .gloas_enabled()
                {
                    let duration_to_next_epoch = self
                        .slot_clock
                        .duration_to_next_epoch(S::E::slots_per_epoch())
                        .unwrap_or_else(|| slot_duration * S::E::slots_per_epoch() as u32);
                    sleep(duration_to_next_epoch).await;
                    continue;
                }

                let service = self.clone();
                self.executor.spawn(
                    async move {
                        service.publish_proposer_preferences(current_slot).await;
                    },
                    "proposer_preferences_publisher",
                );

                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot).await;
                } else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                }
            }
        };

        executor.spawn(interval_fut, "proposer_preferences_service");
        Ok(())
    }

    async fn publish_proposer_preferences(&self, current_slot: types::Slot) {
        let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

        // Only sign for doppelganger-safe validators.
        let signing_pubkeys: std::collections::HashSet<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);

        // Collect all data needed while holding the lock, then drop it before any awaits.
        let preferences_to_sign: Vec<_> = {
            let proposers = self.duties_service.proposers.read();
            let Some((_, duties)) = proposers.get(&current_epoch) else {
                return;
            };

            let mut result = vec![];
            for duty in duties {
                if !signing_pubkeys.contains(&duty.pubkey) {
                    continue;
                }
                if duty.slot <= current_slot {
                    continue;
                }
                let Some(proposal_data) = self.validator_store.proposal_data(&duty.pubkey) else {
                    warn!(
                        validator = ?duty.pubkey,
                        "Missing proposal data for proposer preferences"
                    );
                    continue;
                };
                let Some(validator_index) = proposal_data.validator_index else {
                    continue;
                };
                let Some(fee_recipient) = proposal_data.fee_recipient else {
                    warn!(
                        validator = ?duty.pubkey,
                        "Missing fee recipient for proposer preferences"
                    );
                    continue;
                };
                result.push((
                    duty.pubkey,
                    ProposerPreferences {
                        proposal_slot: duty.slot,
                        validator_index,
                        fee_recipient,
                        gas_limit: proposal_data.gas_limit,
                    },
                ));
            }
            result
        };

        if preferences_to_sign.is_empty() {
            return;
        }

        debug!(
            %current_slot,
            count = preferences_to_sign.len(),
            "Signing proposer preferences"
        );

        let mut signed = Vec::with_capacity(preferences_to_sign.len());
        for (pubkey, preferences) in preferences_to_sign {
            match self
                .validator_store
                .sign_proposer_preferences(pubkey, preferences)
                .await
            {
                Ok(signed_prefs) => signed.push(signed_prefs),
                Err(e) => {
                    error!(
                        error = ?e,
                        validator = ?pubkey,
                        "Failed to sign proposer preferences"
                    );
                }
            }
        }

        if signed.is_empty() {
            return;
        }

        let count = signed.len();
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let signed = signed.clone();
                async move {
                    beacon_node
                        .post_beacon_pool_proposer_preferences(&signed)
                        .await
                        .map_err(|e| format!("Failed to publish proposer preferences: {e:?}"))
                }
            })
            .await;

        match result {
            Ok(()) => {
                info!(
                    %current_slot,
                    %count,
                    "Successfully published proposer preferences"
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    %current_slot,
                    "Failed to publish proposer preferences"
                );
            }
        }
    }
}
