use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, Epoch, EthSpec, ForkName, ProposerPreferences};
use validator_store::ValidatorStore;

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

                let current_epoch = current_slot.epoch(S::E::slots_per_epoch());
                let fork_name = self.chain_spec.fork_name_at_slot::<S::E>(current_slot);
                self.publish_proposer_preferences(current_epoch, fork_name)
                    .await;

                let duration_to_next_epoch = self
                    .slot_clock
                    .duration_to_next_epoch(S::E::slots_per_epoch())
                    .unwrap_or_else(|| slot_duration * S::E::slots_per_epoch() as u32);
                sleep(duration_to_next_epoch).await;
            }
        };

        executor.spawn(interval_fut, "proposer_preferences_service");
        Ok(())
    }

    async fn publish_proposer_preferences(&self, current_epoch: Epoch, fork_name: ForkName) {
        let (dependent_root, duties) = {
            let proposers = self.duties_service.proposers.read();
            match proposers.get(&current_epoch) {
                Some((root, duties)) => (*root, duties.clone()),
                None => return,
            }
        };

        let preferences_to_sign: Vec<_> = {
            let mut result = vec![];
            for duty in &duties {
                let Some(proposal_data) = self.validator_store.proposal_data(&duty.pubkey) else {
                    warn!(
                        validator = ?duty.pubkey,
                        "Missing proposal data for proposer preferences"
                    );
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
                        dependent_root,
                        proposal_slot: duty.slot,
                        validator_index: duty.validator_index,
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
            %current_epoch,
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
        let signed = Arc::new(signed);
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let signed = signed.clone();
                async move {
                    match beacon_node
                        .post_validator_proposer_preferences_ssz(&signed, fork_name)
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(ssz_err) => {
                            debug!(error = ?ssz_err, "SSZ publish failed, falling back to JSON");
                            beacon_node
                                .post_validator_proposer_preferences(&signed, fork_name)
                                .await
                                .map_err(|e| {
                                    format!("Failed to publish proposer preferences: {e:?}")
                                })
                        }
                    }
                }
            })
            .await;

        match result {
            Ok(()) => {
                info!(
                    %current_epoch,
                    %count,
                    "Successfully published proposer preferences"
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    %current_epoch,
                    "Failed to publish proposer preferences"
                );
            }
        }
    }
}
