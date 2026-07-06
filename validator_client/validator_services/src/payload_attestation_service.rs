use crate::duties_service::DutiesService;
use beacon_node_fallback::{BeaconNodeFallback, beacon_head_monitor::PayloadAvailableEvent};
use eth2::types::PtcDuty;
use logging::crit;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, EthSpec, Hash256, PayloadAttestationData, Slot};
use validator_store::ValidatorStore;

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
    payload_available_rx: Option<Mutex<mpsc::Receiver<PayloadAvailableEvent>>>,
    latest_voted_slot: Mutex<Slot>,
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

impl<S, T> PayloadAttestationService<S, T>
where
    S: ValidatorStore + 'static,
    T: SlotClock + 'static,
{
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
        payload_available_rx: Option<Mutex<mpsc::Receiver<PayloadAvailableEvent>>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                executor,
                chain_spec,
                payload_available_rx,
                latest_voted_slot: Mutex::new(Slot::default()),
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        info!(
            payload_attestation_due_ms = self.chain_spec.get_payload_attestation_due().as_millis(),
            "Payload attestation service started"
        );

        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                if let Err(e) = self.spawn_payload_attestation_tasks().await {
                    error!(error = e, "Failed to produce payload attestations");
                }
            }
        };

        executor.spawn(interval_fut, "payload_attestation_service");
        Ok(())
    }

    async fn poll_for_payload_available_event(&self) -> Option<PayloadAvailableEvent> {
        let Some(receiver) = &self.payload_available_rx else {
            return None;
        };
        let mut receiver = receiver.lock().await;
        loop {
            match receiver.recv().await {
                Some(payload_available_event) => {
                    // Only trigger on current-slot events
                    let current_slot = self.slot_clock.now()?;
                    if payload_available_event.slot == current_slot {
                        return Some(payload_available_event);
                    }
                    // Stale event — keep waiting for the deadline
                }
                None => {
                    warn!("payload_available channel closed unexpectedly");
                    return None;
                }
            }
        }
    }

    async fn spawn_payload_attestation_tasks(&self) -> Result<(), String> {
        let (attestation_slot, beacon_node_data) = if self.payload_available_rx.is_some() {
            tokio::select! {
                result = self.wait_for_attestation_slot() => {
                    let Some(slot) = result else { return Ok(()); };
                    (slot, None)
                }
                event = self.poll_for_payload_available_event() => {
                    let Some(slot) = self.slot_clock.now() else {
                        error!("Failed to read slot clock after payload available event");
                        return Ok(());
                    };
                    (slot, event.map(|ev| (ev.beacon_node_index, ev.block_root)))
                }
            }
        } else {
            let Some(slot) = self.wait_for_attestation_slot().await else {
                return Ok(());
            };
            (slot, None)
        };

        let mut last_slot = self.latest_voted_slot.lock().await;

        if attestation_slot <= *last_slot {
            debug!(%attestation_slot, "Payload attestation already produced for this slot");
            return Ok(());
        }
        *last_slot = attestation_slot;
        drop(last_slot);

        let triggered_early = beacon_node_data.is_some();
        let mut data_result = self
            .produce_payload_attestation_data(attestation_slot, beacon_node_data)
            .await;

        if triggered_early && !matches!(data_result, Ok(Some(_))) {
            if let Err(ref e) = data_result {
                warn!(error = %e, %attestation_slot, "Early attempt failed, retrying at deadline");
            }
            let deadline = self
                .slot_clock
                .duration_to_slot(attestation_slot + 1)
                .and_then(|d| d.checked_add(self.chain_spec.get_payload_attestation_due()))
                .map(|d| d.saturating_sub(self.chain_spec.get_slot_duration()))
                .unwrap_or_default();
            sleep(deadline).await;
            data_result = self
                .produce_payload_attestation_data(attestation_slot, None)
                .await;
        }

        let Some((duties, attestation_data)) = data_result? else {
            return Ok(());
        };

        let service = self.clone();
        self.executor.spawn(
            async move {
                if let Err(e) = service
                    .sign_and_publish(attestation_slot, duties, attestation_data)
                    .await
                {
                    crit!(error = e, %attestation_slot, "Failed to publish payload attestations");
                }
            },
            "payload_attestation_producer",
        );

        Ok(())
    }

    async fn wait_for_attestation_slot(&self) -> Option<Slot> {
        let slot_duration = self.chain_spec.get_slot_duration();
        let payload_attestation_due = self.chain_spec.get_payload_attestation_due();

        let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() else {
            error!("Failed to read slot clock");
            sleep(slot_duration).await;
            return None;
        };

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after trigger");
            return None;
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
            return None;
        }

        sleep(duration_to_next_slot + payload_attestation_due).await;

        let Some(attestation_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after sleep");
            return None;
        };

        Some(attestation_slot)
    }

    /// Produce the payload attestation data for `slot`, returned alongside the duties to sign.
    ///
    /// Returns `Ok(None)` when there is nothing to publish (no duties, or no block for the slot)
    /// and `Err` when data production failed.
    async fn produce_payload_attestation_data(
        &self,
        slot: Slot,
        beacon_node_data: Option<(usize, Hash256)>,
    ) -> Result<Option<(Vec<PtcDuty>, PayloadAttestationData)>, String> {
        let duties = self.duties_service.get_ptc_duties_for_slot(slot);
        if duties.is_empty() {
            return Ok(None);
        }

        debug!(%slot, duty_count = duties.len(), "Producing payload attestations");

        let mut payload_data_from_event = None;

        if let Some((beacon_node_index, expected_block_root)) = beacon_node_data {
            match self
                .beacon_nodes
                .run_on_candidate_index(beacon_node_index, |beacon_node| async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::PAYLOAD_ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::PAYLOAD_ATTESTATIONS_HTTP_GET],
                    );
                    let data = beacon_node
                        .get_validator_payload_attestation_data(slot)
                        .await
                        .map_err(|e| format!("Failed to get payload attestation data: {e:?}"))?
                        .map(|resp| resp.into_data())
                        .ok_or_else(|| format!("No payload attestation data on node {beacon_node_index}"))?;
                    if data.beacon_block_root != expected_block_root {
                        return Err(format!(
                            "Payload attestation block root mismatch: expected {expected_block_root:?}, got {:?}",
                            data.beacon_block_root
                        ));
                    }
                    Ok(data)
                })
                .await
            {
                Ok(data) => payload_data_from_event = Some(data),
                Err(e) => warn!(error = ?e, %slot, "Failed to attest based on payload available event"),
            }
        }

        let attestation_data = if let Some(data) = payload_data_from_event {
            data
        } else {
            match self
                .beacon_nodes
                .first_success(|beacon_node| async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::PAYLOAD_ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::PAYLOAD_ATTESTATIONS_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_payload_attestation_data(slot)
                        .await
                        .map(|opt| opt.map(|resp| resp.into_data()))
                })
                .await
            {
                Ok(Some(data)) => data,
                Ok(None) => {
                    debug!(%slot, "No block received for slot, skipping payload attestation");
                    return Ok(None);
                }
                Err(e) => return Err(e.to_string()),
            }
        };

        debug!(
            %slot,
            beacon_block_root = ?attestation_data.beacon_block_root,
            payload_present = attestation_data.payload_present,
            "Received payload attestation data"
        );

        Ok(Some((duties, attestation_data)))
    }

    /// Sign `attestation_data` for each duty and publish the resulting messages, preferring SSZ
    /// and falling back to JSON.
    async fn sign_and_publish(
        &self,
        slot: Slot,
        duties: Vec<PtcDuty>,
        attestation_data: PayloadAttestationData,
    ) -> Result<(), String> {
        let _timer = validator_metrics::start_timer_vec(
            &validator_metrics::PAYLOAD_ATTESTATION_SERVICE_TIMES,
            &[validator_metrics::PAYLOAD_ATTESTATIONS],
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
            return Ok(());
        }

        let count = messages.len();
        let fork_name = self.chain_spec.fork_name_at_slot::<S::E>(slot);
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let messages = messages.clone();
                async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::PAYLOAD_ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::PAYLOAD_ATTESTATIONS_HTTP_POST],
                    );
                    beacon_node
                        .post_beacon_pool_payload_attestations_ssz(&messages, fork_name)
                        .await
                        .map_err(|e| format!("Failed to publish payload attestations (SSZ): {e:?}"))
                }
            })
            .await;

        if result.is_err() {
            debug!(%slot, "SSZ publish failed, falling back to JSON");
            self.beacon_nodes
                .first_success(|beacon_node| {
                    let messages = messages.clone();
                    async move {
                        let _timer = validator_metrics::start_timer_vec(
                            &validator_metrics::PAYLOAD_ATTESTATION_SERVICE_TIMES,
                            &[validator_metrics::PAYLOAD_ATTESTATIONS_HTTP_POST],
                        );
                        beacon_node
                            .post_beacon_pool_payload_attestations(&messages, fork_name)
                            .await
                            .map_err(|e| {
                                format!("Failed to publish payload attestations (JSON): {e:?}")
                            })
                    }
                })
                .await
                .map_err(|e| e.to_string())?;
        }

        info!(
            %slot,
            %count,
            "Successfully published payload attestations"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use account_utils::validator_definitions::{PasswordStorage, ValidatorDefinition};
    use beacon_node_fallback::{
        BeaconNodeFallback, CandidateBeaconNode, Config as BeaconNodeConfig,
        beacon_head_monitor::PayloadAvailableEvent,
    };
    use bls::{FixedBytesExtended, Keypair, PublicKeyBytes};
    use eth2::types::PtcDuty;
    use eth2_keystore::KeystoreBuilder;
    use futures::FutureExt;
    use initialized_validators::InitializedValidators;
    use lighthouse_validator_store::LighthouseValidatorStore;
    use slashing_protection::{SLASHING_PROTECTION_FILENAME, SlashingDatabase};
    use slot_clock::ManualSlotClock;
    use std::sync::Arc;
    use std::time::Duration;
    use task_executor::test_utils::TestRuntime;
    use tempfile::{TempDir, tempdir};
    use types::{Epoch, ForkName, Hash256, MainnetEthSpec, PayloadAttestationData, Slot};
    use validator_test_rig::mock_beacon_node::MockBeaconNode;

    type E = MainnetEthSpec;
    type S = LighthouseValidatorStore<ManualSlotClock, E>;

    async fn create_validator_store(
        slot_clock: ManualSlotClock,
        spec: Arc<ChainSpec>,
        executor: TaskExecutor,
        num_validators: usize,
    ) -> (Arc<S>, Vec<PublicKeyBytes>, TempDir) {
        let validator_dir = tempdir().unwrap();
        let password = b"test";

        let mut validator_definitions = Vec::with_capacity(num_validators);
        let mut pubkeys = Vec::with_capacity(num_validators);

        for i in 0..num_validators {
            let keypair = Keypair::random();
            let keystore = KeystoreBuilder::new(&keypair, password, String::new())
                .unwrap()
                .build()
                .unwrap();
            let keystore_path = validator_dir
                .path()
                .join(format!("voting-keystore-{i}.json"));
            keystore
                .to_json_writer(std::fs::File::create(&keystore_path).unwrap())
                .unwrap();

            let validator_definition = ValidatorDefinition::new_keystore_with_password(
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

            pubkeys.push(keypair.pk.into());
            validator_definitions.push(validator_definition);
        }

        let initialized_validators = InitializedValidators::from_definitions(
            validator_definitions.into(),
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

        for (i, pubkey) in pubkeys.iter().enumerate() {
            validator_store.set_validator_index(pubkey, i as u64);
        }

        (validator_store, pubkeys, validator_dir)
    }

    struct TestHarness {
        mock_beacon_node_1: MockBeaconNode<E>,
        mock_beacon_node_2: MockBeaconNode<E>,
        service: PayloadAttestationService<S, ManualSlotClock>,
        pubkeys: Vec<PublicKeyBytes>,
        _test_runtime: TestRuntime,
        _validator_dir: TempDir,
    }

    impl TestHarness {
        async fn create_validators(
            num_validators: usize,
            payload_rx: Option<mpsc::Receiver<PayloadAvailableEvent>>,
        ) -> Self {
            let mut default_spec = MainnetEthSpec::default_spec();
            default_spec.gloas_fork_epoch = Some(Epoch::new(0));
            let spec = Arc::new(default_spec);

            let test_runtime = TestRuntime::default();
            let executor = test_runtime.task_executor.clone();
            let slot_duration = spec.get_slot_duration();
            let slot_clock =
                ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);

            let (validator_store, pubkeys, validator_dir) = create_validator_store(
                slot_clock.clone(),
                spec.clone(),
                executor.clone(),
                num_validators,
            )
            .await;

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

            let service = PayloadAttestationService::new(
                duties_service,
                validator_store,
                slot_clock,
                beacon_node_fallback,
                executor,
                spec,
                payload_rx.map(Mutex::new), // converts Option<Receiver> to Option<Mutex<Receiver>>
            );

            Self {
                mock_beacon_node_1,
                mock_beacon_node_2,
                service,
                pubkeys,
                _test_runtime: test_runtime,
                _validator_dir: validator_dir,
            }
        }

        fn insert_ptc_duties(&self, slot: Slot) {
            let duties = self
                .pubkeys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| PtcDuty {
                    pubkey: *pubkey,
                    validator_index: i as u64,
                    slot,
                })
                .collect();
            self.service
                .duties_service
                .ptc_duties
                .write()
                .insert(Epoch::new(0), (Hash256::ZERO, duties));
        }
    }

    // advance_time so that we don't have to wait for real-time to elapse in the test
    async fn advance_time(slot_clock: &ManualSlotClock, duration: Duration) {
        slot_clock.advance_time(duration);
        tokio::time::advance(duration).await;
    }

    #[tokio::test]
    async fn test_wait_for_attestation_slot() {
        tokio::time::pause();

        let harness = TestHarness::create_validators(1, None).await;
        let service = &harness.service;
        let service_wait = service.wait_for_attestation_slot();
        tokio::pin!(service_wait);

        // This first call of .now_or_never() starts the timer and registers the sleep timer with tokio
        // It calls sleep(duration_to_next_slot + payload_attestation_due).await which registers a timer with a deadline of 21s
        assert!(service_wait.as_mut().now_or_never().is_none());

        let duration_to_next_slot = harness.service.slot_clock.duration_to_next_slot().unwrap();
        let payload_attestation_due = harness.service.chain_spec.get_payload_attestation_due();
        let duration_to_wait = duration_to_next_slot + payload_attestation_due;
        // Advance both slot_clock and tokio::time to 21s (the sleep deadline)
        // The timer hasn't fired yet because tokio requires time to be strictly past the deadline.
        // so the following assert! should return None
        // This verifies that the function wait_for_attestation_slot waits for the correct duration before returning a slot.
        advance_time(&harness.service.slot_clock, duration_to_wait).await;
        assert!(
            service_wait.as_mut().now_or_never().is_none(),
            "Function should return None before the sleep duration has elapsed"
        );

        // Advance time for 1 more second, the sleep should have completed and the function should return Some(attestation_slot)
        // slot_clock is now at 22s, which is slot 1
        // Removing this advance_time should cause the following assert_eq! to fail
        advance_time(&harness.service.slot_clock, Duration::from_secs(1)).await;
        assert_eq!(
            service_wait.as_mut().now_or_never().unwrap(),
            Some(Slot::new(1))
        );
    }

    #[tokio::test]
    async fn publish_payload_attestation_ssz() {
        let mut harness = TestHarness::create_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

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

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, None)
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        let messages = harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();

        // We create one validator with one PTC duty, so the PayloadAttestationMessage length should be 1
        assert_eq!(
            messages.len(),
            1,
            "Expected one payload attestation message"
        );

        // First try on beacon_node_1 (mock_ssz) is successful
        // therefore mock_json is not hit at all
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
        let mut harness = TestHarness::create_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

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

        // mock_ssz returns 500 to simulate BN does not support SSZ, so that it fallbacks to mock_json
        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz_error();
        let mock_json = harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, None)
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        // first_success function tries both beacon nodes for SSZ post payload attestation:
        // first pass: both fail (mock_ssz returns 500, mock_json does not support SSZ)
        // second pass: repeats the first pass
        // Therefore mock_ssz is hit twice.
        // When SSZ fails, it fallbacks to JSON and should succeed on first call on mock_json.
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
        let mut harness = TestHarness::create_validators(1, None).await;

        // we do not insert any duties in this test
        let mock = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = harness.service;

        // when there is no duty, data production returns `None` so there is nothing to publish
        // therefore, the beacon node is not called, expected to hit 0
        let data = service
            .produce_payload_attestation_data(Slot::new(1), None)
            .await
            .unwrap();
        assert!(
            data.is_none(),
            "Expected no data to be produced without duties"
        );
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

    #[tokio::test]
    async fn test_get_payload_attestation_data_error() {
        let mut harness = TestHarness::create_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        // We have PTC duties
        harness.insert_ptc_duties(attestation_slot);

        // However, we simulate that both BNs have error in get_validator_payload_attestation_data
        harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data_error(attestation_slot);
        harness
            .mock_beacon_node_2
            .mock_get_validator_payload_attestation_data_error(attestation_slot);

        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));
        let mock_json = harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = harness.service;
        // Data production should error before any signing/publishing happens.
        let result = service
            .produce_payload_attestation_data(attestation_slot, None)
            .await;
        assert!(result.is_err());

        // Both beacon nodes should not be called at all
        mock_ssz.expect(0).assert();
        mock_json.expect(0).assert();

        // No payload attestation message published
        assert!(
            harness
                .mock_beacon_node_1
                .payload_attestation_message
                .lock()
                .unwrap()
                .is_empty(),
            "No payload attestation should be published when get data fails"
        );
    }

    #[tokio::test]
    async fn publish_multiple_payload_attestation_messages() {
        // Create 3 validators with 1 PTC duty for each validator
        let mut harness = TestHarness::create_validators(3, None).await;

        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

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

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, None)
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        let messages = harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();

        // With 3 PTC duties in total, we should have 3 PayloadAttestationMessage
        assert_eq!(
            messages.len(),
            3,
            "Expected three payload attestation messages"
        );
        // mock_ssz is only hit once
        // this is to verify that a single call to the POST endpoint can publish multiple messages in one go
        mock_ssz.expect(1).assert();
    }

    #[tokio::test]
    async fn early_event_uses_specific_beacon_node() {
        let mut harness = TestHarness::create_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

        let expected_block_root = Hash256::from_low_u64_be(42);
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: expected_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Only node 1 (index 0) is set up for GET.
        // If the code incorrectly calls first_success and hits node 2, it would fail.
        let mock_get = harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, Some((0, expected_block_root)))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        mock_ssz.expect(1).assert();
        mock_get.expect(1).assert();

        let messages = harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.beacon_block_root, expected_block_root);
    }

    #[tokio::test]
    async fn early_event_block_root_mismatch_falls_back_to_first_success() {
        let mut harness = TestHarness::create_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

        let actual_block_root = Hash256::from_low_u64_be(1);
        let event_block_root = Hash256::from_low_u64_be(2); // mismatch!

        let payload_attestation = PayloadAttestationData {
            beacon_block_root: actual_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Node 1 returns actual_block_root, but the event says event_block_root.
        // run_on_candidate_index should detect mismatch, warn, then fall back to first_success.
        // first_success calls node 1 again (no block root check) and succeeds.
        let mock_get = harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, Some((0, event_block_root)))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        // Despite the mismatch, the fallback path still published successfully.
        mock_ssz.expect(1).assert();
        // Assert GET was called twice: once in run_on_candidate_index (fails due to mismatch),
        // once in first_success (succeeds)
        mock_get.expect(2).assert();

        let messages = harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[tokio::test]
    async fn early_event_node_error_falls_back_to_first_success() {
        let mut harness = TestHarness::create_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        harness.insert_ptc_duties(attestation_slot);

        let expected_block_root = Hash256::from_low_u64_be(42);
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: expected_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Node 1 (index 0) errors on GET — run_on_candidate_index(0) fails.
        harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data_error(attestation_slot);

        // first_success tries node 1 (fails), then node 2 (succeeds).
        harness
            .mock_beacon_node_2
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        // SSZ fails on node 1, so falls back to JSON on node 2.
        let mock_ssz_error = harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz_error();
        let mock_json = harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(attestation_slot, Some((0, expected_block_root)))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        // SSZ was attempted (and failed), JSON fallback succeeded.
        mock_ssz_error.expect(2).assert(); // first_success retries both nodes before giving up
        mock_json.expect(1).assert();

        let messages = harness
            .mock_beacon_node_2
            .payload_attestation_message
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.beacon_block_root, expected_block_root);
    }

    #[tokio::test]
    async fn poll_for_payload_available_event_filters_stale_events() {
        let (payload_tx, payload_rx) = mpsc::channel::<PayloadAvailableEvent>(10);
        let harness = TestHarness::create_validators(1, Some(payload_rx)).await;

        // Advance to slot 1
        let slot_duration = harness.service.chain_spec.get_slot_duration();
        harness.service.slot_clock.advance_time(slot_duration);
        let current_slot = harness.service.slot_clock.now().unwrap();

        // Send a stale slot 0 event first, then a valid slot 1 event.
        // The function should discard the stale one and return the valid one.
        payload_tx
            .send(PayloadAvailableEvent {
                beacon_node_index: 0,
                slot: Slot::new(0), // stale — must be skipped
                block_root: Hash256::from_low_u64_be(1),
            })
            .await
            .unwrap();

        payload_tx
            .send(PayloadAvailableEvent {
                beacon_node_index: 0,
                slot: current_slot, // valid — must be returned
                block_root: Hash256::from_low_u64_be(2),
            })
            .await
            .unwrap();

        let event = harness.service.poll_for_payload_available_event().await;

        assert!(event.is_some(), "Should have received a valid event");
        let event = event.unwrap();
        assert_eq!(
            event.slot, current_slot,
            "Should have skipped stale slot 0 event and returned slot 1 event"
        );
        assert_eq!(event.block_root, Hash256::from_low_u64_be(2));
    }
}
