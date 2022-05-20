use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{
    fee_recipient_file::FeeRecipientFile,
    validator_store::{DoppelgangerStatus, ValidatorStore},
};
use environment::RuntimeContext;
use slog::{debug, error, info};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use types::{Address, ChainSpec, EthSpec, ProposerPreparationData};

/// Number of epochs before the Bellatrix hard fork to begin posting proposer preparations.
const PROPOSER_PREPARATION_LOOKAHEAD_EPOCHS: u64 = 2;

/// Builds an `PreparationService`.
pub struct PreparationServiceBuilder<T: SlotClock + 'static, E: EthSpec> {
    validator_store: Option<Arc<ValidatorStore<T, E>>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: Option<RuntimeContext<E>>,
    fee_recipient: Option<Address>,
    fee_recipient_file: Option<FeeRecipientFile>,
}

impl<T: SlotClock + 'static, E: EthSpec> PreparationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            context: None,
            fee_recipient: None,
            fee_recipient_file: None,
        }
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

    pub fn fee_recipient(mut self, fee_recipient: Option<Address>) -> Self {
        self.fee_recipient = fee_recipient;
        self
    }

    pub fn fee_recipient_file(mut self, fee_recipient_file: Option<FeeRecipientFile>) -> Self {
        self.fee_recipient_file = fee_recipient_file;
        self
    }

    pub fn build(self) -> Result<PreparationService<T, E>, String> {
        Ok(PreparationService {
            inner: Arc::new(Inner {
                validator_store: self
                    .validator_store
                    .ok_or("Cannot build PreparationService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build PreparationService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build PreparationService without beacon_nodes")?,
                context: self
                    .context
                    .ok_or("Cannot build PreparationService without runtime_context")?,
                fee_recipient: self.fee_recipient,
                fee_recipient_file: self.fee_recipient_file,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    validator_store: Arc<ValidatorStore<T, E>>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
    fee_recipient: Option<Address>,
    fee_recipient_file: Option<FeeRecipientFile>,
}

/// Attempts to produce proposer preparations for all known validators at the beginning of each epoch.
pub struct PreparationService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for PreparationService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for PreparationService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> PreparationService<T, E> {
    /// Starts the service which periodically produces proposer preparations.
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();

        let slot_duration = Duration::from_secs(spec.seconds_per_slot);
        info!(
            log,
            "Proposer preparation service started";
        );

        let executor = self.context.executor.clone();
        let spec = spec.clone();

        let interval_fut = async move {
            loop {
                if self.should_publish_at_current_slot(&spec) {
                    // Poll the endpoint immediately to ensure fee recipients are received.
                    self.prepare_proposers_and_publish(&spec)
                        .await
                        .map_err(|e| {
                            error!(
                                log,
                                "Error during proposer preparation";
                                "error" => ?e,
                            )
                        })
                        .unwrap_or(());
                }

                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot).await;
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                }
            }
        };

        executor.spawn(interval_fut, "preparation_service");
        Ok(())
    }

    /// Return `true` if the current slot is close to or past the Bellatrix fork epoch.
    ///
    /// This avoids spamming the BN with preparations before the Bellatrix fork epoch, which may
    /// cause errors if it doesn't support the preparation API.
    fn should_publish_at_current_slot(&self, spec: &ChainSpec) -> bool {
        let current_epoch = self
            .slot_clock
            .now()
            .map_or(E::genesis_epoch(), |slot| slot.epoch(E::slots_per_epoch()));
        spec.bellatrix_fork_epoch.map_or(false, |fork_epoch| {
            current_epoch + PROPOSER_PREPARATION_LOOKAHEAD_EPOCHS >= fork_epoch
        })
    }

    /// Prepare proposer preparations and send to beacon node
    async fn prepare_proposers_and_publish(&self, spec: &ChainSpec) -> Result<(), String> {
        let preparation_data = self.collect_preparation_data(spec);
        if !preparation_data.is_empty() {
            self.publish_preparation_data(preparation_data).await?;
        }

        Ok(())
    }

    fn collect_preparation_data(&self, spec: &ChainSpec) -> Vec<ProposerPreparationData> {
        let log = self.context.log();

        let fee_recipient_file = self
            .fee_recipient_file
            .clone()
            .map(|mut fee_recipient_file| {
                fee_recipient_file
                    .read_fee_recipient_file()
                    .map_err(|e| {
                        error!(
                            log,
                            "Error loading fee-recipient file";
                            "error" => ?e
                        );
                    })
                    .unwrap_or(());
                fee_recipient_file
            });

        let all_pubkeys: Vec<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::ignored);

        all_pubkeys
            .into_iter()
            .filter_map(|pubkey| {
                // Ignore fee recipients for keys without indices, they are inactive.
                let validator_index = self.validator_store.validator_index(&pubkey)?;

                // If there is a `suggested_fee_recipient` in the validator definitions yaml
                // file, use that value.
                let fee_recipient = self
                    .validator_store
                    .suggested_fee_recipient(&pubkey)
                    .or_else(|| {
                        // If there's nothing in the validator defs file, check the fee
                        // recipient file.
                        fee_recipient_file
                            .as_ref()?
                            .get_fee_recipient(&pubkey)
                            .ok()?
                    })
                    // If there's nothing in the file, try the process-level default value.
                    .or(self.fee_recipient);

                if let Some(fee_recipient) = fee_recipient {
                    Some(ProposerPreparationData {
                        validator_index,
                        fee_recipient,
                    })
                } else {
                    if spec.bellatrix_fork_epoch.is_some() {
                        error!(
                            log,
                            "Validator is missing fee recipient";
                            "msg" => "update validator_definitions.yml",
                            "pubkey" => ?pubkey
                        );
                    }
                    None
                }
            })
            .collect()
    }

    async fn publish_preparation_data(
        &self,
        preparation_data: Vec<ProposerPreparationData>,
    ) -> Result<(), String> {
        let log = self.context.log();

        // Post the proposer preparations to the BN.
        let preparation_data_len = preparation_data.len();
        let preparation_entries = preparation_data.as_slice();
        match self
            .beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .post_validator_prepare_beacon_proposer(preparation_entries)
                    .await
            })
            .await
        {
            Ok(()) => debug!(
                log,
                "Published proposer preparation";
                "count" => preparation_data_len,
            ),
            Err(e) => error!(
                log,
                "Unable to publish proposer preparation";
                "error" => %e,
            ),
        }
        Ok(())
    }
}
