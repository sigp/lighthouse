use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKeyBytes;
use eth2::types::ProposerData;
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, Epoch, EthSpec, ForkName, Hash256, ProposerPreferences, Slot};
use validator_store::{ProposalData, ValidatorStore};

/// `(validator_index, proposal_slot)` duties already published, keyed by epoch and dependent
/// root. Sets for stale roots persist until their epoch is pruned, so a dependent root that
/// recurs within an epoch is not re-published.
type PublishedPreferences = HashMap<(Epoch, Hash256), HashSet<(u64, Slot)>>;

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
            let mut published_preferences = PublishedPreferences::new();

            loop {
                self.run_update(&mut published_preferences).await;
            }
        };

        executor.spawn(interval_fut, "proposer_preferences_service");
        Ok(())
    }

    async fn run_update(&self, published_preferences: &mut PublishedPreferences) {
        let slot_duration = self.chain_spec.get_slot_duration();

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock");
            sleep(slot_duration).await;
            return;
        };

        let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

        self.poll_and_publish_preferences(current_epoch, published_preferences)
            .await;

        self.sleep_until_next_slot().await;
    }

    async fn sleep_until_next_slot(&self) {
        let slot_duration = self.chain_spec.get_slot_duration();
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .unwrap_or(slot_duration);
        sleep(duration_to_next_slot).await;
    }

    /// Publish proposer preferences for `current_epoch` and `current_epoch + 1`.
    ///
    /// Each proposer duty is published once per epoch and dependent root, so a validator added
    /// after an epoch's duties were first published is still picked up, and a dependent root
    /// change re-publishes the epoch's duties. Duties that are missing proposal data or that
    /// fail to sign or publish are retried on later polls without re-publishing their siblings.
    async fn poll_and_publish_preferences(
        &self,
        current_epoch: Epoch,
        published_preferences: &mut PublishedPreferences,
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

            let published = published_preferences
                .entry((epoch, dependent_root))
                .or_default();

            let preferences_to_sign =
                preferences_to_publish(dependent_root, &duties, published, |pubkey| {
                    self.validator_store.proposal_data(pubkey)
                });

            if preferences_to_sign.is_empty() {
                continue;
            }

            let newly_published = self
                .publish_proposer_preferences(epoch, fork_name, preferences_to_sign)
                .await;
            published.extend(newly_published);
        }

        published_preferences.retain(|(epoch, _), _| *epoch >= current_epoch);
    }

    /// Sign and publish `preferences_to_sign`, returning the `(validator_index, slot)` pairs
    /// that were signed and included in a successfully published batch.
    async fn publish_proposer_preferences(
        &self,
        epoch: Epoch,
        fork_name: ForkName,
        preferences_to_sign: Vec<(PublicKeyBytes, ProposerPreferences)>,
    ) -> Vec<(u64, Slot)> {
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
            return vec![];
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
                signed
                    .iter()
                    .map(|preferences| {
                        (
                            preferences.message.validator_index,
                            preferences.message.proposal_slot,
                        )
                    })
                    .collect()
            }
            Err(e) => {
                error!(
                    error = %e,
                    %epoch,
                    "Failed to publish proposer preferences"
                );
                vec![]
            }
        }
    }
}

/// Build the proposer preferences that still need publishing: one per proposer duty whose
/// `(validator_index, slot)` is not in `published` and whose proposal data is available.
fn preferences_to_publish(
    dependent_root: Hash256,
    duties: &[ProposerData],
    published: &HashSet<(u64, Slot)>,
    proposal_data: impl Fn(&PublicKeyBytes) -> Option<ProposalData>,
) -> Vec<(PublicKeyBytes, ProposerPreferences)> {
    duties
        .iter()
        .filter(|duty| !published.contains(&(duty.validator_index, duty.slot)))
        .filter_map(|duty| {
            let Some(proposal_data) = proposal_data(&duty.pubkey) else {
                warn!(
                    validator = ?duty.pubkey,
                    "Missing proposal data for proposer preferences"
                );
                return None;
            };
            let Some(fee_recipient) = proposal_data.fee_recipient else {
                warn!(
                    validator = ?duty.pubkey,
                    "Missing fee recipient for proposer preferences"
                );
                return None;
            };
            Some((
                duty.pubkey,
                ProposerPreferences {
                    dependent_root,
                    proposal_slot: duty.slot,
                    validator_index: duty.validator_index,
                    fee_recipient,
                    target_gas_limit: proposal_data.gas_limit,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use eth2::types::ProposerData;
    use futures::FutureExt;
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::{Address, ForkName, Hash256, Slot};
    use validator_test_rig::validator_client_harness::{
        S, ValidatorClientHarness, ValidatorStoreConfig,
    };

    const FEE_RECIPIENT: Address = Address::repeat_byte(42);
    const GAS_LIMIT: u64 = 30_000_000;

    fn pubkey(i: u8) -> PublicKeyBytes {
        PublicKeyBytes::deserialize(&[i; 48]).unwrap()
    }

    fn duty(i: u8, slot: u64) -> ProposerData {
        ProposerData {
            pubkey: pubkey(i),
            validator_index: i as u64,
            slot: Slot::new(slot),
        }
    }

    fn proposal_data(fee_recipient: Option<Address>) -> ProposalData {
        ProposalData {
            validator_index: None,
            fee_recipient,
            gas_limit: GAS_LIMIT,
            builder_proposals: false,
        }
    }

    fn default_proposal_data(_: &PublicKeyBytes) -> Option<ProposalData> {
        Some(proposal_data(Some(FEE_RECIPIENT)))
    }

    /// Run the state transitions of one poll (select unpublished duties, then record them as
    /// published on success) and return how many duties were published. Mirrors the map
    /// bookkeeping in `poll_and_publish_preferences` around the signing effect.
    fn publish_round(
        published_preferences: &mut PublishedPreferences,
        epoch: Epoch,
        dependent_root: Hash256,
        duties: &[ProposerData],
    ) -> usize {
        let published = published_preferences
            .entry((epoch, dependent_root))
            .or_default();
        let to_sign =
            preferences_to_publish(dependent_root, duties, published, default_proposal_data);
        let count = to_sign.len();
        published.extend(
            to_sign
                .iter()
                .map(|(_, preferences)| (preferences.validator_index, preferences.proposal_slot)),
        );
        count
    }

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: ProposerPreferencesService<S, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(num_validators: usize) -> Self {
            let config = ValidatorStoreConfig {
                // Need to have a fee_recipient for proposer preferences
                fee_recipient: Some(FEE_RECIPIENT),
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
            self.insert_proposer_duties_with_root(epoch, Hash256::ZERO);
        }

        fn insert_proposer_duties_with_root(&self, epoch: Epoch, dependent_root: Hash256) {
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
                .insert(epoch, (dependent_root, duties));
        }
    }

    // advance_time so that we don't have to wait for real-time to elapse in the test
    async fn advance_time(slot_clock: &ManualSlotClock, duration: Duration) {
        slot_clock.advance_time(duration);
        tokio::time::advance(duration).await;
    }

    #[test]
    fn new_validator_under_same_root_yields_only_new_validator() {
        let dependent_root = Hash256::repeat_byte(1);
        let duties = [duty(1, 1), duty(2, 2), duty(3, 3)];
        let published = HashSet::from([(1, Slot::new(1)), (2, Slot::new(2))]);

        let result =
            preferences_to_publish(dependent_root, &duties, &published, default_proposal_data);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, pubkey(3));
        assert_eq!(result[0].1.proposal_slot, Slot::new(3));
    }

    #[test]
    fn built_preferences_carry_duty_fields() {
        let dependent_root = Hash256::repeat_byte(7);
        let duties = [duty(1, 5)];

        let result = preferences_to_publish(
            dependent_root,
            &duties,
            &HashSet::new(),
            default_proposal_data,
        );

        assert_eq!(result.len(), 1);
        let (pubkey_out, preferences) = &result[0];
        assert_eq!(*pubkey_out, pubkey(1));
        assert_eq!(preferences.dependent_root, dependent_root);
        assert_eq!(preferences.proposal_slot, Slot::new(5));
        assert_eq!(preferences.validator_index, 1);
        assert_eq!(preferences.fee_recipient, FEE_RECIPIENT);
        assert_eq!(preferences.target_gas_limit, GAS_LIMIT);
    }

    #[test]
    fn missing_data_excluded_and_retried() {
        let dependent_root = Hash256::repeat_byte(1);
        // Validator 1 has no fee recipient yet, validator 2 is ready, validator 3 has no
        // proposal data at all.
        let duties = [duty(1, 1), duty(2, 2), duty(3, 3)];
        let mut published = HashSet::new();

        let result =
            preferences_to_publish(
                dependent_root,
                &duties,
                &published,
                |pubkey_in| match pubkey_in {
                    pk if *pk == pubkey(1) => Some(proposal_data(None)),
                    pk if *pk == pubkey(3) => None,
                    _ => Some(proposal_data(Some(FEE_RECIPIENT))),
                },
            );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, pubkey(2));

        // A later poll, after validator 1's fee recipient becomes available and validator 2's
        // preferences were published. Validator 3 still has no proposal data.
        published.insert((2, Slot::new(2)));
        let result = preferences_to_publish(dependent_root, &duties, &published, |pubkey_in| {
            (*pubkey_in != pubkey(3)).then(|| proposal_data(Some(FEE_RECIPIENT)))
        });

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, pubkey(1));
    }

    #[test]
    fn multi_slot_proposer_yields_one_entry_per_duty() {
        let dependent_root = Hash256::repeat_byte(1);
        let duties = [duty(1, 10), duty(1, 11)];
        let published = HashSet::from([(1, Slot::new(10))]);

        let result =
            preferences_to_publish(dependent_root, &duties, &published, default_proposal_data);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, pubkey(1));
        assert_eq!(result[0].1.proposal_slot, Slot::new(11));
    }

    #[test]
    fn dependent_root_flip_flop_does_not_resign() {
        let epoch = Epoch::new(0);
        let root_a = Hash256::repeat_byte(1);
        let root_b = Hash256::repeat_byte(2);
        let duties = [duty(1, 1), duty(2, 2)];
        let mut published_preferences = PublishedPreferences::new();

        // Publish under the original root, then re-publish under the reorged root.
        assert_eq!(
            publish_round(&mut published_preferences, epoch, root_a, &duties),
            2
        );
        assert_eq!(
            publish_round(&mut published_preferences, epoch, root_b, &duties),
            2
        );

        // The head reorgs back to the original root. Its published set was retained under its own
        // key, so nothing is signed again.
        assert_eq!(
            publish_round(&mut published_preferences, epoch, root_a, &duties),
            0
        );
    }

    #[tokio::test]
    async fn test_sleep_until_next_slot() {
        tokio::time::pause();

        let test_harness = TestHarness::new_with_validators(1).await;
        let service = &test_harness.service;

        // sleep_until_next_epoch advances past epoch boundary
        let sleep_fut = service.sleep_until_next_slot();
        tokio::pin!(sleep_fut);

        // This first call of .now_or_never() starts the timer and registers the sleep timer with tokio
        assert!(sleep_fut.as_mut().now_or_never().is_none());

        let duration_to_next_slot = service.slot_clock.duration_to_next_slot().unwrap();

        // After the advance_time, the time should be at exactly the sleep deadline (12s)
        // The timer hasn't fired yet because tokio requires time to be strictly past the deadline.
        advance_time(&service.slot_clock, duration_to_next_slot).await;
        assert!(
            sleep_fut.as_mut().now_or_never().is_none(),
            "Should return None before the sleep duration has elapsed"
        );

        // After the advance_time below, the time has now pass the deadline
        // Without the advance time below, the assert! would fail
        advance_time(&service.slot_clock, Duration::from_secs(1)).await;
        assert!(
            sleep_fut.as_mut().now_or_never().is_some(),
            "Sleep should complete after passing the boundary"
        );

        // After sleeping, slot_clock should be at Slot 1
        let current_slot = service.slot_clock.now().unwrap();
        assert_eq!(current_slot, Slot::new(1));
    }

    #[tokio::test]
    async fn publish_proposer_preferences_ssz() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let current_epoch = Epoch::new(0);
        test_harness.insert_proposer_duties(current_epoch);

        let duties = test_harness
            .harness
            .pubkeys
            .iter()
            .enumerate()
            .map(|(i, pubkey)| {
                (
                    *pubkey,
                    ProposerPreferences {
                        dependent_root: Hash256::ZERO,
                        proposal_slot: Slot::new(0),
                        validator_index: i as u64,
                        fee_recipient: FEE_RECIPIENT,
                        target_gas_limit: GAS_LIMIT,
                    },
                )
            })
            .collect();

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_proposer_preferences_json();

        let result = test_harness
            .service
            .publish_proposer_preferences(current_epoch, ForkName::Gloas, duties)
            .await;

        // assert that result is ok (successfully publishes proposer preferences)
        assert!(!result.is_empty());
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

        let duties = test_harness
            .harness
            .pubkeys
            .iter()
            .enumerate()
            .map(|(i, pubkey)| {
                (
                    *pubkey,
                    ProposerPreferences {
                        dependent_root: Hash256::ZERO,
                        proposal_slot: Slot::new(0),
                        validator_index: i as u64,
                        fee_recipient: FEE_RECIPIENT,
                        target_gas_limit: GAS_LIMIT,
                    },
                )
            })
            .collect();

        // mock_ssz returns 500 to simulate BN does not support SSZ, so that it fallbacks to mock_json
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz_error();
        let mock_json = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_json();

        let result = test_harness
            .service
            .publish_proposer_preferences(current_epoch, ForkName::Gloas, duties)
            .await;

        // still successfully publishes proposer preferences because JSON BN is working
        assert!(!result.is_empty());
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

        let current_epoch = Epoch::new(0);
        // We did not insert proposer duty
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();

        let result = test_harness
            .service
            .publish_proposer_preferences(current_epoch, ForkName::Gloas, vec![])
            .await;

        // No duties, publish_proposer_preference should return false
        assert!(result.is_empty());
        // When there is no proposer duty, the function should return early and does not call the post proposer preferences endpoint
        mock_ssz.expect(0).assert();
    }

    #[tokio::test]
    async fn poll_and_publish_preferences_same_root() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let current_epoch = Epoch::new(0);
        test_harness.insert_proposer_duties(current_epoch);

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();

        let mut published_preferences = HashMap::new();

        // First call publishes
        test_harness
            .service
            .poll_and_publish_preferences(current_epoch, &mut published_preferences)
            .await;

        // Second call with same epoch and same dependent root should be skipped
        test_harness
            .service
            .poll_and_publish_preferences(current_epoch, &mut published_preferences)
            .await;

        // Only one call to BN is expected despite two poll_and_publish_preferences calls
        mock_ssz.expect(1).assert();
    }

    #[tokio::test]
    async fn poll_and_publish_preferences_different_root() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let current_epoch = Epoch::new(0);
        test_harness.insert_proposer_duties(current_epoch);

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();

        let mut published_preferences = HashMap::new();

        // First call publishes with default dependent_root: Hash256::ZERO
        test_harness
            .service
            .poll_and_publish_preferences(current_epoch, &mut published_preferences)
            .await;

        // Update duties with a different dependent root
        let new_root = Hash256::repeat_byte(1);
        test_harness.insert_proposer_duties_with_root(current_epoch, new_root);

        // Second call should publish again because dependent root has changed
        test_harness
            .service
            .poll_and_publish_preferences(current_epoch, &mut published_preferences)
            .await;

        // The BN should be called twice because poll_and_publish_preferences will call publish_proposer_preferences to insert the preferences
        mock_ssz.expect(2).assert();
    }

    #[tokio::test]
    async fn poll_retains_only_current_and_future_epochs() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_proposer_preferences_ssz();

        let mut published_preferences = HashMap::new();

        // Insert and publish for epoch 0
        test_harness.insert_proposer_duties(Epoch::new(0));
        test_harness
            .service
            .poll_and_publish_preferences(Epoch::new(0), &mut published_preferences)
            .await;
        assert!(published_preferences.contains_key(&(Epoch::new(0), Hash256::ZERO)));

        // Now poll with Epoch = 1
        // Epoch 0 should be removed from the HashMap
        test_harness.insert_proposer_duties(Epoch::new(1));
        test_harness
            .service
            .poll_and_publish_preferences(Epoch::new(1), &mut published_preferences)
            .await;
        assert!(published_preferences.contains_key(&(Epoch::new(1), Hash256::ZERO)));
        assert!(!published_preferences.contains_key(&(Epoch::new(0), Hash256::ZERO)));

        // The mock BN should be called once for each poll_and_publish_preferences call
        mock_ssz.expect(2).assert();
    }
}
