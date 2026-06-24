use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use eth2::types::ProposerData;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, Epoch, EthSpec, ForkName, Hash256, ProposerPreferences};
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
        info!("Proposer preferences service started");

        let executor = self.executor.clone();

        let interval_fut = async move {
            let mut published_preferences: HashMap<Epoch, Hash256> = HashMap::new();

            loop {
                let Some(current_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };

                let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

                self.poll_and_publish_preferences(current_epoch, &mut published_preferences)
                    .await;

                let duration_to_next_slot = self
                    .slot_clock
                    .duration_to_next_slot()
                    .unwrap_or(slot_duration);
                sleep(duration_to_next_slot).await;
            }
        };

        executor.spawn(interval_fut, "proposer_preferences_service");
        Ok(())
    }

    /// Publish proposer preferences for `current_epoch` and `current_epoch + 1`.
    /// Will only publish preferences for a given epoch once per dependent root.
    async fn poll_and_publish_preferences(
        &self,
        current_epoch: Epoch,
        published_preferences: &mut HashMap<Epoch, Hash256>,
    ) {
        for (epoch, fork_name) in [
            (
                current_epoch,
                self.chain_spec.fork_name_at_epoch(current_epoch),
            ),
            (
                current_epoch + 1,
                self.chain_spec.fork_name_at_epoch(current_epoch + 1),
            ),
        ] {
            if !fork_name.gloas_enabled() {
                continue;
            }

            let (dependent_root, duties) = {
                let proposers = self.duties_service.proposers.read();
                match proposers.get(&epoch) {
                    Some((root, duties)) => (*root, duties.clone()),
                    None => continue,
                }
            };

            if published_preferences.get(&epoch) == Some(&dependent_root) {
                continue;
            }

            if self
                .publish_proposer_preferences(epoch, fork_name, dependent_root, duties)
                .await
            {
                published_preferences.insert(epoch, dependent_root);
            }
        }

        published_preferences.retain(|epoch, _| *epoch >= current_epoch);
    }

    async fn publish_proposer_preferences(
        &self,
        epoch: Epoch,
        fork_name: ForkName,
        dependent_root: Hash256,
        duties: Vec<ProposerData>,
    ) -> bool {
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
                        target_gas_limit: proposal_data.gas_limit,
                    },
                ));
            }
            result
        };

        if preferences_to_sign.is_empty() {
            return false;
        }

        debug!(
            %epoch,
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
            return false;
        }

        let count = signed.len();
        let signed = Arc::new(signed);
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let signed = signed.clone();
                async move {
                    beacon_node
                        .post_validator_proposer_preferences_ssz(&signed, fork_name)
                        .await
                        .map_err(|e| format!("Failed to publish proposer preferences (SSZ): {e:?}"))
                }
            })
            .await;

        let result = match result {
            Ok(()) => Ok(()),
            Err(ssz_err) => {
                debug!(error = %ssz_err, "SSZ publish failed, falling back to JSON");
                self.beacon_nodes
                    .first_success(|beacon_node| {
                        let signed = signed.clone();
                        async move {
                            beacon_node
                                .post_validator_proposer_preferences(&signed, fork_name)
                                .await
                                .map_err(|e| {
                                    format!("Failed to publish proposer preferences (JSON): {e:?}")
                                })
                        }
                    })
                    .await
            }
        };

        match result {
            Ok(()) => {
                info!(
                    %epoch,
                    %count,
                    "Successfully published proposer preferences"
                );
                true
            }
            Err(e) => {
                error!(
                    error = %e,
                    %epoch,
                    "Failed to publish proposer preferences"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use eth2::types::ProposerData;
    use futures::FutureExt;
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::{Address, EthSpec, ForkName, Hash256, MainnetEthSpec, Slot};
    use validator_test_rig::validator_client_harness::{
        S, ValidatorClientHarness, ValidatorStoreConfig,
    };

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: ProposerPreferencesService<S, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(num_validators: usize) -> Self {
            let config = ValidatorStoreConfig {
                // Need to have a fee_recipient for proposer preferences
                fee_recipient: Some(Address::ZERO),
                ..Default::default()
            };
            let harness = ValidatorClientHarness::new_with_config(num_validators, &config).await;

            let duties_service = Arc::new(
                DutiesServiceBuilder::new()
                    .validator_store(harness.validator_store.clone())
                    .slot_clock(harness.slot_clock.clone())
                    .beacon_nodes(harness.beacon_nodes.clone())
                    .executor(harness.test_runtime.task_executor.clone())
                    .spec(harness.spec.clone())
                    .build()
                    .unwrap(),
            );

            let service = ProposerPreferencesService::new(
                duties_service,
                harness.validator_store.clone(),
                harness.slot_clock.clone(),
                harness.beacon_nodes.clone(),
                harness.test_runtime.task_executor.clone(),
                harness.spec.clone(),
            );

            Self { harness, service }
        }

        fn insert_proposer_duties(&self, epoch: Epoch) {
            let duties = self
                .harness
                .pubkeys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| ProposerData {
                    pubkey: *pubkey,
                    validator_index: i as u64,
                    slot: Slot::new(0),
                })
                .collect();
            self.service
                .duties_service
                .proposers
                .write()
                .insert(epoch, (Hash256::ZERO, duties));
        }
    }

    // advance_time so that we don't have to wait for real-time to elapse in the test
    async fn advance_time(slot_clock: &ManualSlotClock, duration: Duration) {
        slot_clock.advance_time(duration);
        tokio::time::advance(duration).await;
    }

    #[tokio::test]
    async fn test_get_current_epoch() {
        let harness = TestHarness::new_with_validators(1).await;
        let service = &harness.service;

        let result = service.get_current_epoch().await;
        // The testnet starts with slot 0, hence Epoch 0
        assert_eq!(result, Some((Epoch::new(0), ForkName::Gloas)));
    }

    #[tokio::test]
    async fn test_wait_until_next_epoch() {
        tokio::time::pause();

        let harness = TestHarness::new_with_validators(1).await;
        let service = &harness.service;

        // sleep_until_next_epoch advances past epoch boundary
        let sleep_fut = service.wait_until_next_epoch();
        tokio::pin!(sleep_fut);

        // This first call of .now_or_never() starts the timer and registers the sleep timer with tokio
        assert!(sleep_fut.as_mut().now_or_never().is_none());

        let duration_to_next_epoch = service
            .slot_clock
            .duration_to_next_epoch(MainnetEthSpec::slots_per_epoch())
            .unwrap();

        // After the advance_time, the time should be at exactly the sleep deadline (32*12s = 384s)
        // The timer hasn't fired yet because tokio requires time to be strictly past the deadline.
        advance_time(&service.slot_clock, duration_to_next_epoch).await;
        assert!(
            sleep_fut.as_mut().now_or_never().is_none(),
            "Should return None before the sleep duration has elapsed"
        );

        // After the advance_time below, the time has now pass the deadline
        advance_time(&service.slot_clock, Duration::from_secs(1)).await;
        assert!(
            sleep_fut.as_mut().now_or_never().is_some(),
            "Sleep should complete after passing the boundary"
        );

        // After sleeping, get_current_epoch should return epoch 1
        let result = service.get_current_epoch().await;
        assert_eq!(result, Some((Epoch::new(1), ForkName::Gloas)));
    }

    #[tokio::test]
    async fn publish_proposer_preferences_ssz() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let current_epoch = Epoch::new(0);
        test_harness.insert_proposer_duties(current_epoch);

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_proposer_preferences_json();

        test_harness
            .service
            .publish_proposer_preferences(current_epoch, ForkName::Gloas)
            .await;

        // First try on beacon_node_1 (mock_ssz) is successful
        // therefore mock_json is not hit at all
        mock_ssz.expect(1).assert();
        mock_json.expect(0).assert();
    }

    #[tokio::test]
    async fn publish_proposer_preferences_ssz_fails_fallback_to_json() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let current_epoch = Epoch::new(0);
        test_harness.insert_proposer_duties(current_epoch);

        // mock_ssz returns 500 to simulate BN does not support SSZ, so that it fallbacks to mock_json
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz_error();
        let mock_json = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_json();

        test_harness
            .service
            .publish_proposer_preferences(current_epoch, ForkName::Gloas)
            .await;

        // first_success function tries both beacon nodes for SSZ post proposer preferences
        // first pass: both fail (mock_ssz returns 500, mock_json does not support SSZ)
        // second pass: repeats the first pass
        // Therefore mock_ssz is hit twice.
        // When SSZ fails, it fallbacks to JSON and should succeed on first call on mock_json.
        mock_ssz.expect(2).assert();
        mock_json.expect(1).assert();
    }

    #[tokio::test]
    async fn no_duties_no_publish() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        // We did not insert proposer duty
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();

        test_harness
            .service
            .publish_proposer_preferences(Epoch::new(0), ForkName::Gloas)
            .await;

        // When there is no proposer duty, the function should return early and does not call the post proposer preferences endpoint
        mock_ssz.expect(0).assert();
    }
}
