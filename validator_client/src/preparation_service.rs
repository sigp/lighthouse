use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::validator_store::{DoppelgangerStatus, ValidatorStore};
use crate::OfflineOnFailure;
use bls::PublicKeyBytes;
use environment::RuntimeContext;
use parking_lot::RwLock;
use slog::{debug, error, info, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use types::{
    Address, ChainSpec, EthSpec, ProposerPreparationData, SignedValidatorRegistrationData,
    ValidatorRegistrationData,
};

/// Number of epochs before the Bellatrix hard fork to begin posting proposer preparations.
const PROPOSER_PREPARATION_LOOKAHEAD_EPOCHS: u64 = 2;

/// Number of epochs to wait before re-submitting validator registration.
const EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION: u64 = 1;

/// The number of validator registrations to include per request to the beacon node.
const VALIDATOR_REGISTRATION_BATCH_SIZE: usize = 500;

/// Builds an `PreparationService`.
pub struct PreparationServiceBuilder<T: SlotClock + 'static, E: EthSpec> {
    validator_store: Option<Arc<ValidatorStore<T, E>>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: Option<RuntimeContext<E>>,
    builder_registration_timestamp_override: Option<u64>,
}

impl<T: SlotClock + 'static, E: EthSpec> PreparationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            context: None,
            builder_registration_timestamp_override: None,
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

    pub fn builder_registration_timestamp_override(
        mut self,
        builder_registration_timestamp_override: Option<u64>,
    ) -> Self {
        self.builder_registration_timestamp_override = builder_registration_timestamp_override;
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
                builder_registration_timestamp_override: self
                    .builder_registration_timestamp_override,
                validator_registration_cache: RwLock::new(HashMap::new()),
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
    builder_registration_timestamp_override: Option<u64>,
    // Used to track unpublished validator registration changes.
    validator_registration_cache:
        RwLock<HashMap<ValidatorRegistrationKey, SignedValidatorRegistrationData>>,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ValidatorRegistrationKey {
    pub fee_recipient: Address,
    pub gas_limit: u64,
    pub pubkey: PublicKeyBytes,
}

impl From<ValidatorRegistrationData> for ValidatorRegistrationKey {
    fn from(data: ValidatorRegistrationData) -> Self {
        let ValidatorRegistrationData {
            fee_recipient,
            gas_limit,
            timestamp: _,
            pubkey,
        } = data;
        Self {
            fee_recipient,
            gas_limit,
            pubkey,
        }
    }
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
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        self.clone().start_validator_registration_service(spec)?;
        self.start_proposer_prepare_service(spec)
    }

    /// Starts the service which periodically produces proposer preparations.
    pub fn start_proposer_prepare_service(self, spec: &ChainSpec) -> Result<(), String> {
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

    /// Starts the service which periodically sends connected beacon nodes validator registration information.
    pub fn start_validator_registration_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();

        info!(
            log,
            "Validator registration service started";
        );

        let spec = spec.clone();
        let slot_duration = Duration::from_secs(spec.seconds_per_slot);

        let executor = self.context.executor.clone();

        let validator_registration_fut = async move {
            loop {
                // Poll the endpoint immediately to ensure fee recipients are received.
                if let Err(e) = self.register_validators().await {
                    error!(log,"Error during validator registration";"error" => ?e);
                }

                // Wait one slot if the register validator request fails or if we should not publish at the current slot.
                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot).await;
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(slot_duration).await;
                }
            }
        };
        executor.spawn(validator_registration_fut, "validator_registration_service");
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
        self.collect_proposal_data(|pubkey, proposal_data| {
            if let Some(fee_recipient) = proposal_data.fee_recipient {
                Some(ProposerPreparationData {
                    // Ignore fee recipients for keys without indices, they are inactive.
                    validator_index: proposal_data.validator_index?,
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
    }

    fn collect_validator_registration_keys(&self) -> Vec<ValidatorRegistrationKey> {
        self.collect_proposal_data(|pubkey, proposal_data| {
            // Ignore fee recipients for keys without indices, they are inactive.
            proposal_data.validator_index?;

            // We don't log for missing fee recipients here because this will be logged more
            // frequently in `collect_preparation_data`.
            proposal_data.fee_recipient.and_then(|fee_recipient| {
                proposal_data
                    .builder_proposals
                    .then_some(ValidatorRegistrationKey {
                        fee_recipient,
                        gas_limit: proposal_data.gas_limit,
                        pubkey,
                    })
            })
        })
    }

    fn collect_proposal_data<G, U>(&self, map_fn: G) -> Vec<U>
    where
        G: Fn(PublicKeyBytes, ProposalData) -> Option<U>,
    {
        let all_pubkeys: Vec<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::ignored);

        all_pubkeys
            .into_iter()
            .filter_map(|pubkey| {
                let proposal_data = self.validator_store.proposal_data(&pubkey)?;
                map_fn(pubkey, proposal_data)
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
            .run(
                RequireSynced::Yes,
                OfflineOnFailure::Yes,
                |beacon_node| async move {
                    beacon_node
                        .post_validator_prepare_beacon_proposer(preparation_entries)
                        .await
                },
            )
            .await
        {
            Ok(()) => debug!(
                log,
                "Published proposer preparation";
                "count" => preparation_data_len,
            ),
            Err(e) => error!(
                log,
                "Unable to publish proposer preparation to all beacon nodes";
                "error" => %e,
            ),
        }
        Ok(())
    }

    /// Register validators with builders, used in the blinded block proposal flow.
    async fn register_validators(&self) -> Result<(), String> {
        let registration_keys = self.collect_validator_registration_keys();

        let mut changed_keys = vec![];

        // Need to scope this so the read lock is not held across an await point (I don't know why
        // but the explicit `drop` is not enough).
        {
            let guard = self.validator_registration_cache.read();
            for key in registration_keys.iter() {
                if !guard.contains_key(key) {
                    changed_keys.push(key.clone());
                }
            }
            drop(guard);
        }

        // Check if any have changed or it's been `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION`.
        if let Some(slot) = self.slot_clock.now() {
            if slot % (E::slots_per_epoch() * EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION) == 0 {
                self.publish_validator_registration_data(registration_keys)
                    .await?;
            } else if !changed_keys.is_empty() {
                self.publish_validator_registration_data(changed_keys)
                    .await?;
            }
        }

        Ok(())
    }

    async fn publish_validator_registration_data(
        &self,
        registration_keys: Vec<ValidatorRegistrationKey>,
    ) -> Result<(), String> {
        let log = self.context.log();

        let registration_data_len = registration_keys.len();
        let mut signed = Vec::with_capacity(registration_data_len);

        for key in registration_keys {
            let cached_registration_opt =
                self.validator_registration_cache.read().get(&key).cloned();

            let signed_data = if let Some(signed_data) = cached_registration_opt {
                signed_data
            } else {
                let timestamp =
                    if let Some(timestamp) = self.builder_registration_timestamp_override {
                        timestamp
                    } else {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|e| format!("{e:?}"))?
                            .as_secs()
                    };

                let ValidatorRegistrationKey {
                    fee_recipient,
                    gas_limit,
                    pubkey,
                } = key.clone();

                let signed_data = match self
                    .validator_store
                    .sign_validator_registration_data(ValidatorRegistrationData {
                        fee_recipient,
                        gas_limit,
                        timestamp,
                        pubkey,
                    })
                    .await
                {
                    Ok(data) => data,
                    Err(e) => {
                        error!(log, "Unable to sign validator registration data"; "error" => ?e, "pubkey" => ?pubkey);
                        continue;
                    }
                };

                self.validator_registration_cache
                    .write()
                    .insert(key, signed_data.clone());

                signed_data
            };
            signed.push(signed_data);
        }

        if !signed.is_empty() {
            for batch in signed.chunks(VALIDATOR_REGISTRATION_BATCH_SIZE) {
                match self
                    .beacon_nodes
                    .first_success(
                        RequireSynced::Yes,
                        OfflineOnFailure::No,
                        |beacon_node| async move {
                            beacon_node.post_validator_register_validator(batch).await
                        },
                    )
                    .await
                {
                    Ok(()) => info!(
                        log,
                        "Published validator registrations to the builder network";
                        "count" => registration_data_len,
                    ),
                    Err(e) => warn!(
                        log,
                        "Unable to publish validator registrations to the builder network";
                        "error" => %e,
                    ),
                }
            }
        }
        Ok(())
    }
}

/// A helper struct, used for passing data from the validator store to services.
pub struct ProposalData {
    pub(crate) validator_index: Option<u64>,
    pub(crate) fee_recipient: Option<Address>,
    pub(crate) gas_limit: u64,
    pub(crate) builder_proposals: bool,
}
