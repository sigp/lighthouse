use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use logging::crit;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec};
use validator_store::ValidatorStore;

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
}

pub struct PayloadAttestationService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for PayloadAttestationService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for PayloadAttestationService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> PayloadAttestationService<S, T> {
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
        let payload_attestation_due = self.chain_spec.get_payload_attestation_due();

        info!(
            payload_attestation_due_ms = payload_attestation_due.as_millis(),
            "Payload attestation service started"
        );

        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };

                let Some(current_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock after trigger");
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
                        .unwrap_or_else(|| {
                            self.chain_spec.get_slot_duration() * S::E::slots_per_epoch() as u32
                        });
                    sleep(duration_to_next_epoch).await;
                    continue;
                }

                sleep(duration_to_next_slot + payload_attestation_due).await;

                let Some(attestation_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock after sleep");
                    continue;
                };

                let service = self.clone();
                self.executor.spawn(
                    async move {
                        service.produce_and_publish(attestation_slot).await;
                    },
                    "payload_attestation_producer",
                );
            }
        };

        executor.spawn(interval_fut, "payload_attestation_service");
        Ok(())
    }

    async fn produce_and_publish(&self, slot: types::Slot) {
        let duties = self.duties_service.get_ptc_duties_for_slot(slot);

        if duties.is_empty() {
            return;
        }

        debug!(
            %slot,
            duty_count = duties.len(),
            "Producing payload attestations"
        );

        let attestation_data = match self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                beacon_node
                    .get_validator_payload_attestation_data(slot)
                    .await
                    .map(|opt| opt.map(|resp| resp.into_data()))
            })
            .await
        {
            Ok(Some(data)) => data,
            Ok(None) => {
                // Per the consensus spec, validators should not submit a
                // payload attestation when no block has been seen for the slot.
                debug!(
                    %slot,
                    "No block received for slot, skipping payload attestation"
                );
                return;
            }
            Err(e) => {
                error!(
                    error = %e,
                    %slot,
                    "Failed to produce payload attestation data"
                );
                return;
            }
        };

        debug!(
            %slot,
            beacon_block_root = ?attestation_data.beacon_block_root,
            payload_present = attestation_data.payload_present,
            "Received payload attestation data"
        );

        let mut messages = Vec::with_capacity(duties.len());

        for duty in &duties {
            match self
                .validator_store
                .sign_payload_attestation(duty.pubkey, attestation_data.clone())
                .await
            {
                Ok(message) => {
                    messages.push(message);
                }
                Err(e) => {
                    crit!(
                        error = ?e,
                        validator = ?duty.pubkey,
                        %slot,
                        "Failed to sign payload attestation"
                    );
                }
            }
        }

        if messages.is_empty() {
            return;
        }

        let count = messages.len();
        let fork_name = self.chain_spec.fork_name_at_slot::<S::E>(slot);
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let messages = messages.clone();
                async move {
                    beacon_node
                        .post_beacon_pool_payload_attestations_ssz(&messages, fork_name)
                        .await
                        .map_err(|e| format!("Failed to publish payload attestations (SSZ): {e:?}"))
                }
            })
            .await;

        let result = match result {
            Ok(()) => Ok(()),
            Err(_) => {
                debug!(%slot, "SSZ publish failed, falling back to JSON");
                self.beacon_nodes
                    .first_success(|beacon_node| {
                        let messages = messages.clone();
                        async move {
                            beacon_node
                                .post_beacon_pool_payload_attestations(&messages, fork_name)
                                .await
                                .map_err(|e| {
                                    format!("Failed to publish payload attestations (JSON): {e:?}")
                                })
                        }
                    })
                    .await
            }
        };

        match result {
            Ok(()) => {
                info!(
                    %slot,
                    %count,
                    "Successfully published payload attestations"
                );
            }
            Err(e) => {
                crit!(
                    error = %e,
                    %slot,
                    "Failed to publish payload attestations"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::{DutiesService, DutiesServiceBuilder};
    use account_utils::validator_definitions::{PasswordStorage, ValidatorDefinition};
    use beacon_node_fallback::{
        BeaconNodeFallback, CandidateBeaconNode, Config as BeaconNodeConfig,
    };
    use bls::Keypair;
    use eth2::types::PtcDuty;
    use eth2_keystore::KeystoreBuilder;
    use initialized_validators::InitializedValidators;
    use lighthouse_validator_store::LighthouseValidatorStore;
    use slashing_protection::{SLASHING_PROTECTION_FILENAME, SlashingDatabase};
    use slot_clock::ManualSlotClock;
    use std::sync::Arc;
    use std::time::Duration;
    use task_executor::test_utils::TestRuntime;
    use tempfile::{TempDir, tempdir};
    use types::{Epoch, ForkName, Hash256, MainnetEthSpec, PayloadAttestationData, Slot};
    use validator_store::DoppelgangerStatus;
    use validator_test_rig::mock_beacon_node::MockBeaconNode;

    type E = MainnetEthSpec;
    type S = LighthouseValidatorStore<ManualSlotClock, E>;

    async fn create_validator_store(
        slot_clock: ManualSlotClock,
        spec: Arc<ChainSpec>,
        executor: task_executor::TaskExecutor,
    ) -> (Arc<S>, TempDir) {
        let validator_dir = tempdir().unwrap();
        let password = b"test";
        let keypair = Keypair::random();
        let keystore = KeystoreBuilder::new(&keypair, password, String::new())
            .unwrap()
            .build()
            .unwrap();
        let keystore_path = validator_dir.path().join("voting-keystore.json");
        keystore
            .to_json_writer(std::fs::File::create(&keystore_path).unwrap())
            .unwrap();

        let validator_def = ValidatorDefinition::new_keystore_with_password(
            keystore_path,
            PasswordStorage::ValidatorDefinitions(
                String::from_utf8(password.to_vec()).unwrap().into(),
            ),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let initialized_validators = InitializedValidators::from_definitions(
            vec![validator_def].into(),
            validator_dir.path().into(),
            Default::default(),
        )
        .await
        .unwrap();

        let slashing_db_path = validator_dir.path().join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();

        let validator_store = Arc::new(LighthouseValidatorStore::<_, E>::new(
            initialized_validators,
            slashing_protection,
            Hash256::ZERO,
            spec,
            None,
            slot_clock,
            &Default::default(),
            executor,
        ));
        validator_store.set_validator_index(&keypair.pk.into(), 0);

        (validator_store, validator_dir)
    }

    struct TestHarness {
        mock_beacon_node_1: MockBeaconNode<E>,
        mock_beacon_node_2: MockBeaconNode<E>,
        duties_service: Arc<DutiesService<S, ManualSlotClock>>,
        validator_store: Arc<S>,
        slot_clock: ManualSlotClock,
        slot_duration: Duration,
        beacon_node_fallback: Arc<BeaconNodeFallback<ManualSlotClock>>,
        executor: task_executor::TaskExecutor,
        spec: Arc<ChainSpec>,
        _test_runtime: TestRuntime,
        _validator_dir: TempDir,
    }

    impl TestHarness {
        async fn new() -> Self {
            let mut default_spec = MainnetEthSpec::default_spec();
            default_spec.gloas_fork_epoch = Some(Epoch::new(0));
            let spec = Arc::new(default_spec);

            let test_runtime = TestRuntime::default();
            let executor = test_runtime.task_executor.clone();
            let slot_duration = spec.get_slot_duration();
            let slot_clock =
                ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);

            let (validator_store, validator_dir) =
                create_validator_store(slot_clock.clone(), spec.clone(), executor.clone()).await;

            let mock_beacon_node_1 = MockBeaconNode::<E>::new().await;
            let mock_beacon_node_2 = MockBeaconNode::<E>::new().await;

            let beacon_node_1 =
                CandidateBeaconNode::new(mock_beacon_node_1.beacon_api_client.clone(), 0);
            let beacon_node_2 =
                CandidateBeaconNode::new(mock_beacon_node_2.beacon_api_client.clone(), 1);

            let beacon_node_fallback = Arc::new(BeaconNodeFallback::new(
                vec![beacon_node_1, beacon_node_2],
                BeaconNodeConfig::default(),
                vec![],
                spec.clone(),
            ));

            let duties_service = Arc::new(
                DutiesServiceBuilder::new()
                    .validator_store(validator_store.clone())
                    .slot_clock(slot_clock.clone())
                    .beacon_nodes(beacon_node_fallback.clone())
                    .executor(executor.clone())
                    .spec(spec.clone())
                    .build()
                    .unwrap(),
            );

            Self {
                mock_beacon_node_1,
                mock_beacon_node_2,
                duties_service,
                validator_store,
                slot_clock,
                slot_duration,
                beacon_node_fallback,
                executor,
                spec,
                _test_runtime: test_runtime,
                _validator_dir: validator_dir,
            }
        }

        fn pubkey(&self) -> bls::PublicKeyBytes {
            let pubkeys: Vec<bls::PublicKeyBytes> = self
                .validator_store
                .voting_pubkeys(DoppelgangerStatus::only_safe);
            pubkeys.into_iter().next().unwrap()
        }

        fn insert_duty(&self, slot: Slot) {
            let duty = PtcDuty {
                pubkey: self.pubkey(),
                validator_index: 0,
                slot,
            };
            self.duties_service
                .ptc_duties
                .write()
                .insert(Epoch::new(0), (Hash256::ZERO, vec![duty]));
        }

        fn start_service(self) -> Self {
            let service = PayloadAttestationService::new(
                self.duties_service.clone(),
                self.validator_store.clone(),
                self.slot_clock.clone(),
                self.beacon_node_fallback.clone(),
                self.executor.clone(),
                self.spec.clone(),
            );
            service.start_update_service().unwrap();
            self
        }
    }

    #[tokio::test]
    async fn publish_payload_attestation_ssz() {
        let mut harness = TestHarness::new().await;

        let attestation_slot = Slot::new(1);
        harness.insert_duty(attestation_slot);

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &expected_payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));
        let mock_json = harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let harness = harness.start_service();

        // Advance slot clock to slot 1
        harness.slot_clock.advance_time(harness.slot_duration);

        // The service sleeps for: duration_to_next_slot (12s) + payload_attestation_due (9s) = 21s
        // Assert nothing is published <= 21s
        sleep(Duration::from_secs(21)).await;
        assert!(
            harness
                .mock_beacon_node_1
                .payload_attestation_message
                .lock()
                .unwrap()
                .is_empty(),
            "payload attestation should not be published before the sleep duration"
        );

        // After the sleep below, we sleep for > 21s, so messages should not be empty
        sleep(Duration::from_secs(1)).await;

        let messages = harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();

        assert_eq!(
            messages.len(),
            1,
            "Expected one payload attestation message"
        );

        // First mock beacon node try is successful, so mock_json has no call
        mock_ssz.expect(1).assert();
        mock_json.expect(0).assert();

        let result = &messages[0];
        assert_eq!(result.validator_index, 0);
        assert_eq!(
            result.data.beacon_block_root,
            expected_payload_attestation.beacon_block_root
        );
        assert_eq!(result.data.slot, attestation_slot);
        assert!(result.data.payload_present);
        assert!(result.data.blob_data_available);
    }

    #[tokio::test]
    async fn publish_payload_attestation_ssz_fails_fallback_to_json() {
        let mut harness = TestHarness::new().await;

        let attestation_slot = Slot::new(1);
        harness.insert_duty(attestation_slot);

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &expected_payload_attestation,
                ForkName::Gloas,
                Slot::new(1),
            );

        // SSZ mock bn that returns 500 to simulate BN does not support SSZ
        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz_error();
        let mock_json = harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let harness = harness.start_service();

        harness.slot_clock.advance_time(harness.slot_duration);
        sleep(Duration::from_secs(22)).await;

        // first_success tries both beacon nodes for SSZ post payload attestation:
        // first pass: both fail (mock_ssz returns 500, mock_json does not support SSZ)
        // second pass: repeats the first pass
        // Therefore mock_ssz is hit twice.
        // When SSZ fails, it falls back to JSON and succeeds on first call on mock_json.
        mock_ssz.expect(2).assert();
        mock_json.expect(1).assert();

        let messages = harness
            .mock_beacon_node_2
            .payload_attestation_message
            .lock()
            .unwrap();

        assert_eq!(
            messages.len(),
            1,
            "Expected one payload attestation via JSON fallback"
        );
    }

    #[tokio::test]
    async fn no_duties_no_publish() {
        let mut harness = TestHarness::new().await;

        // No duties, we don't call the get payload attestation endpoint

        let mock = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let harness = harness.start_service();

        harness.slot_clock.advance_time(harness.slot_duration);
        sleep(Duration::from_secs(22)).await;

        // No duties, beacon node shouldn't be called
        mock.expect(0).assert();

        assert!(
            harness
                .mock_beacon_node_1
                .payload_attestation_message
                .lock()
                .unwrap()
                .is_empty(),
            "No payload attestation should be published when there are no duties"
        );
    }
}
