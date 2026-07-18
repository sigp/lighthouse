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
use types::{ChainSpec, EthSpec, PayloadAttestationData, Slot};
use validator_store::ValidatorStore;

/// The reason payload attestation production was triggered.
#[derive(Debug)]
enum PayloadAttestationTrigger {
    /// The payload attestation deadline fired for this slot.
    Deadline(Slot),
    /// A beacon node reported the payload available mid-slot.
    PayloadAvailable(PayloadAvailableEvent),
}

impl PayloadAttestationTrigger {
    fn slot(&self) -> Slot {
        match self {
            Self::Deadline(slot) => *slot,
            Self::PayloadAvailable(event) => event.slot,
        }
    }
}

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

    /// Wait for a payload available event for the current slot.
    async fn poll_for_payload_available_event(&self) -> PayloadAvailableEvent {
        if let Some(receiver) = &self.payload_available_rx {
            let mut receiver = receiver.lock().await;
            loop {
                match receiver.recv().await {
                    Some(payload_available_event) => {
                        // Only trigger on current-slot events
                        let Some(current_slot) = self.slot_clock.now() else {
                            error!("Failed to read slot clock; ignoring payload available event");
                            continue;
                        };
                        if payload_available_event.slot == current_slot {
                            return payload_available_event;
                        }
                        // Stale event — keep waiting for the deadline
                    }
                    None => {
                        error!("Payload available channel closed, deadline attestations only");
                        break;
                    }
                }
            }
        }
        // No event sourced, or the channel died. This enures we never resolve so that payload attestation
        // duties are always performed at the deadline.
        std::future::pending().await
    }

    async fn spawn_payload_attestation_tasks(&self) -> Result<(), String> {
        let trigger = if self.payload_available_rx.is_some() {
            tokio::select! {
                result = self.wait_for_attestation_slot() => {
                    let Some(slot) = result else { return Ok(()); };
                    PayloadAttestationTrigger::Deadline(slot)
                }
                event = self.poll_for_payload_available_event() => {
                    PayloadAttestationTrigger::PayloadAvailable(event)
                }
            }
        } else {
            let Some(slot) = self.wait_for_attestation_slot().await else {
                return Ok(());
            };
            PayloadAttestationTrigger::Deadline(slot)
        };

        let attestation_slot = trigger.slot();

        let mut last_slot = self.latest_voted_slot.lock().await;

        if attestation_slot <= *last_slot {
            debug!(%attestation_slot, "Payload attestation already produced for this slot");
            return Ok(());
        }
        *last_slot = attestation_slot;
        drop(last_slot);

        let triggered_early = matches!(trigger, PayloadAttestationTrigger::PayloadAvailable(_));
        let mut data_result = self.produce_payload_attestation_data(trigger).await;

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
                .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(
                    attestation_slot,
                ))
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

        // TODO(gloas) we can delete all gloas gating logic after mainnet forks to gloas
        // At each slot we sleep for `duration_to_next_slot + payload_attestation_due`.
        // So we evaluate if gloas is enabled at `current_slot + 1` to ensure that we don't
        // skip PTC duties at the fork slot.
        let attestation_slot = current_slot + 1;

        if !self
            .chain_spec
            .fork_name_at_slot::<S::E>(attestation_slot)
            .gloas_enabled()
        {
            let sleep_duration = self
                .chain_spec
                .gloas_fork_epoch
                .and_then(|fork_epoch| {
                    let pre_fork_slot = fork_epoch
                        .start_slot(S::E::slots_per_epoch())
                        .saturating_sub(1u64);
                    self.slot_clock.duration_to_slot(pre_fork_slot)
                })
                .unwrap_or(slot_duration);
            sleep(sleep_duration).await;
            return None;
        }

        sleep(duration_to_next_slot + payload_attestation_due).await;

        let Some(post_sleep_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after sleep");
            return None;
        };
        if post_sleep_slot != attestation_slot {
            warn!(
                %attestation_slot,
                %post_sleep_slot,
                "Skipping payload attestation, slot clock drifted during sleep"
            );
            return None;
        }

        Some(attestation_slot)
    }

    /// Produce the payload attestation data for the trigger's slot, returned alongside the
    /// duties to sign.
    ///
    /// Returns `Ok(None)` when there is nothing to publish (no duties, or no block for the slot)
    /// and `Err` when data production failed.
    async fn produce_payload_attestation_data(
        &self,
        trigger: PayloadAttestationTrigger,
    ) -> Result<Option<(Vec<PtcDuty>, PayloadAttestationData)>, String> {
        let slot = trigger.slot();
        let duties = self.duties_service.get_ptc_duties_for_slot(slot);
        if duties.is_empty() {
            return Ok(None);
        }

        debug!(%slot, duty_count = duties.len(), "Producing payload attestations");

        let attestation_data = match trigger {
            PayloadAttestationTrigger::PayloadAvailable(event) => {
                let beacon_node_index = event.beacon_node_index;
                let expected_block_root = event.block_root;
                // Only publish early if payload is present and blob data is available.
                self.beacon_nodes
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
                            .ok_or_else(|| {
                                format!("No payload attestation data on node {beacon_node_index}")
                            })?;
                        if data.beacon_block_root != expected_block_root {
                            return Err(format!(
                                "Payload attestation block root mismatch: expected {expected_block_root:?}, got {:?}",
                                data.beacon_block_root
                            ));
                        }
                        if !data.payload_present {
                            return Err(format!(
                                "Node {beacon_node_index} does not report payload present for block {expected_block_root:?}"
                            ));
                        }
                        if !data.blob_data_available {
                            return Err(format!(
                                "Node {beacon_node_index} does not report blob data available for block {expected_block_root:?}"
                            ));
                        }
                        Ok(data)
                    })
                    .await
                    .map_err(|e| {
                        format!("Failed to attest based on payload available event: {e:?}")
                    })?
            }
            PayloadAttestationTrigger::Deadline(_) => {
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
    use beacon_node_fallback::beacon_head_monitor::PayloadAvailableEvent;
    use bls::FixedBytesExtended;
    use eth2::types::PtcDuty;
    use futures::FutureExt;
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::{Epoch, ForkName, Hash256, PayloadAttestationData, Slot};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: PayloadAttestationService<S, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(
            num_validators: usize,
            payload_rx: Option<mpsc::Receiver<PayloadAvailableEvent>>,
        ) -> Self {
            // Delegate logic, unified with create_validators
            Self::create_validators_with_gloas_fork_epoch(num_validators, payload_rx, Epoch::new(0))
                .await
        }

        async fn create_validators_with_gloas_fork_epoch(
            num_validators: usize,
            payload_rx: Option<mpsc::Receiver<PayloadAvailableEvent>>,
            gloas_fork_epoch: Epoch,
        ) -> Self {
            // Create harness and update spec to desired fork epoch
            let mut harness = ValidatorClientHarness::new(num_validators).await;
            harness.spec = Arc::new({
                let mut spec = (*harness.spec).clone();
                spec.gloas_fork_epoch = Some(gloas_fork_epoch);
                spec
            });

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

            let service = PayloadAttestationService::new(
                duties_service,
                harness.validator_store.clone(),
                harness.slot_clock.clone(),
                harness.beacon_nodes.clone(),
                harness.test_runtime.task_executor.clone(),
                harness.spec.clone(),
                payload_rx.map(Mutex::new),
            );

            Self { harness, service }
        }

        fn insert_ptc_duties(&self, slot: Slot) {
            let duties = self
                .harness
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

        let harness = TestHarness::new_with_validators(1, None).await;
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

    // The first Gloas slot must not be skipped: the iteration running in the last pre-Gloas
    // slot has to arm the attestation for the fork slot.
    // See https://github.com/sigp/lighthouse/issues/9584
    #[tokio::test]
    async fn test_wait_for_attestation_slot_at_fork_boundary() {
        tokio::time::pause();

        // Gloas activates at epoch 1, i.e. fork slot 32. The clock starts at slot 0.
        let harness =
            TestHarness::create_validators_with_gloas_fork_epoch(1, None, Epoch::new(1)).await;
        let service = &harness.service;
        let slot_clock = &harness.service.slot_clock;

        // First iteration: the next slot (1) is pre-Gloas, so the service sleeps until one
        // slot before the fork (slot 31 starts at 372s) and returns None.
        let service_wait = service.wait_for_attestation_slot();
        tokio::pin!(service_wait);
        assert!(service_wait.as_mut().now_or_never().is_none());

        advance_time(slot_clock, Duration::from_secs(372)).await;
        assert!(
            service_wait.as_mut().now_or_never().is_none(),
            "Pre-Gloas sleep should not end before one slot ahead of the fork"
        );
        advance_time(slot_clock, Duration::from_secs(1)).await;
        assert_eq!(
            service_wait.as_mut().now_or_never().unwrap(),
            None,
            "Pre-Gloas iteration should wake at the last pre-fork slot and return None"
        );
        assert_eq!(slot_clock.now().unwrap(), Slot::new(31));

        // Second iteration: runs during slot 31, so it arms the attestation for the first
        // Gloas slot (32) and wakes 75% into it (slot 32 starts at 384s, due at 393s).
        let service_wait = service.wait_for_attestation_slot();
        tokio::pin!(service_wait);
        assert!(service_wait.as_mut().now_or_never().is_none());

        advance_time(slot_clock, Duration::from_secs(20)).await;
        assert!(
            service_wait.as_mut().now_or_never().is_none(),
            "Should not fire before the payload attestation deadline of the fork slot"
        );
        advance_time(slot_clock, Duration::from_secs(1)).await;
        assert_eq!(
            service_wait.as_mut().now_or_never().unwrap(),
            Some(Slot::new(32)),
            "The first Gloas slot must be attested"
        );
    }

    #[tokio::test]
    async fn publish_payload_attestation_ssz() {
        let mut test_harness = TestHarness::new_with_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &expected_payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = test_harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(attestation_slot))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        let messages = test_harness
            .harness
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
        let mut test_harness = TestHarness::new_with_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &expected_payload_attestation,
                ForkName::Gloas,
                Slot::new(1),
            );

        // mock_ssz returns 500 to simulate BN does not support SSZ, so that it fallbacks to mock_json
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz_error();
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = test_harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(attestation_slot))
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

        let messages = test_harness
            .harness
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
        let mut test_harness = TestHarness::new_with_validators(1, None).await;

        // we do not insert any duties in this test
        let mock = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = test_harness.service;

        // when there is no duty, data production returns `None` so there is nothing to publish
        // therefore, the beacon node is not called, expected to hit 0
        let data = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(Slot::new(1)))
            .await
            .unwrap();
        assert!(
            data.is_none(),
            "Expected no data to be produced without duties"
        );
        mock.expect(0).assert();

        assert!(
            test_harness
                .harness
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
        let mut test_harness = TestHarness::new_with_validators(1, None).await;

        let attestation_slot = Slot::new(1);
        // We have PTC duties
        test_harness.insert_ptc_duties(attestation_slot);

        // However, we simulate that both BNs have error in get_validator_payload_attestation_data
        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data_error(attestation_slot);
        test_harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_payload_attestation_data_error(attestation_slot);

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_beacon_pool_payload_attestations();

        let service = test_harness.service;
        // Data production should error before any signing/publishing happens.
        let result = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(attestation_slot))
            .await;
        assert!(result.is_err());

        // Both beacon nodes should not be called at all
        mock_ssz.expect(0).assert();
        mock_json.expect(0).assert();

        // No payload attestation message published
        assert!(
            test_harness
                .harness
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
        let mut test_harness = TestHarness::new_with_validators(3, None).await;

        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &expected_payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = test_harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(attestation_slot))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        let messages = test_harness
            .harness
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
        let mut test_harness = TestHarness::new_with_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_block_root = Hash256::from_low_u64_be(42);
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: expected_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Only node 1 (index 0) is set up for GET.
        // If the code incorrectly calls first_success and hits node 2, it would fail.
        let mock_get = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = test_harness.service;
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::PayloadAvailable(
                PayloadAvailableEvent {
                    beacon_node_index: 0,
                    slot: attestation_slot,
                    block_root: expected_block_root,
                },
            ))
            .await
            .unwrap()
            .unwrap();
        service
            .sign_and_publish(attestation_slot, duties, attestation_data)
            .await
            .unwrap();

        mock_ssz.expect(1).assert();
        mock_get.expect(1).assert();

        let messages = test_harness
            .harness
            .mock_beacon_node_1
            .payload_attestation_message
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.beacon_block_root, expected_block_root);
    }

    #[tokio::test]
    async fn early_event_block_root_mismatch_defers_to_deadline() {
        let mut test_harness = TestHarness::new_with_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let actual_block_root = Hash256::from_low_u64_be(1);
        let event_block_root = Hash256::from_low_u64_be(2); // mismatch!

        let payload_attestation = PayloadAttestationData {
            beacon_block_root: actual_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Node 1 returns actual_block_root, but the event says event_block_root.
        // run_on_candidate_index should detect the mismatch and error out so the caller
        // retries at the deadline, rather than publishing early.
        let mock_get = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = test_harness.service;
        let result = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::PayloadAvailable(
                PayloadAvailableEvent {
                    beacon_node_index: 0,
                    slot: attestation_slot,
                    block_root: event_block_root,
                },
            ))
            .await;
        assert!(result.is_err(), "mismatch must not produce data early");

        // GET was only called once (no first_success fallback), and nothing was published.
        mock_get.expect(1).assert();
        mock_ssz.expect(0).assert();

        assert!(
            test_harness
                .harness
                .mock_beacon_node_1
                .payload_attestation_message
                .lock()
                .unwrap()
                .is_empty(),
            "No payload attestation should be published on block root mismatch"
        );
    }

    #[tokio::test]
    async fn early_event_payload_not_present_defers_to_deadline() {
        let mut test_harness = TestHarness::new_with_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_block_root = Hash256::from_low_u64_be(42);
        // Root matches the event, but the node reports a negative vote. Publishing this
        // early would be premature: the payload may still arrive before the deadline.
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: expected_block_root,
            slot: attestation_slot,
            payload_present: false,
            blob_data_available: false,
        };

        let mock_get = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_pool_payload_attestations_ssz(Duration::from_secs(0));

        let service = test_harness.service;
        let result = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::PayloadAvailable(
                PayloadAvailableEvent {
                    beacon_node_index: 0,
                    slot: attestation_slot,
                    block_root: expected_block_root,
                },
            ))
            .await;
        assert!(
            result.is_err(),
            "negative vote must not be published before the deadline"
        );

        mock_get.expect(1).assert();
        mock_ssz.expect(0).assert();

        assert!(
            test_harness
                .harness
                .mock_beacon_node_1
                .payload_attestation_message
                .lock()
                .unwrap()
                .is_empty(),
            "No payload attestation should be published early on a negative vote"
        );
    }

    #[tokio::test]
    async fn early_event_node_error_defers_to_deadline() {
        let mut test_harness = TestHarness::new_with_validators(1, None).await;
        let attestation_slot = Slot::new(1);
        test_harness.insert_ptc_duties(attestation_slot);

        let expected_block_root = Hash256::from_low_u64_be(42);
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: expected_block_root,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: true,
        };

        // Node 1 (index 0) errors on GET — run_on_candidate_index(0) fails and the early
        // attempt must error out instead of falling back to another node.
        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_payload_attestation_data_error(attestation_slot);

        // Node 2 would answer, but must not be queried by the early path.
        let mock_get_node_2 = test_harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_payload_attestation_data(
                &payload_attestation,
                ForkName::Gloas,
                attestation_slot,
            );

        let service = test_harness.service;
        let result = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::PayloadAvailable(
                PayloadAvailableEvent {
                    beacon_node_index: 0,
                    slot: attestation_slot,
                    block_root: expected_block_root,
                },
            ))
            .await;
        assert!(result.is_err(), "node error must not produce data early");

        let mock_get_node_2 = mock_get_node_2.expect(0);
        mock_get_node_2.assert();

        // The caller retries at the deadline without event data; first_success is then free
        // to use any node.
        let (duties, attestation_data) = service
            .produce_payload_attestation_data(PayloadAttestationTrigger::Deadline(attestation_slot))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attestation_data.beacon_block_root, expected_block_root);
        assert_eq!(duties.len(), 1);
        mock_get_node_2.expect(1).assert();
    }

    #[tokio::test]
    async fn poll_for_payload_available_event_filters_stale_events() {
        let (payload_tx, payload_rx) = mpsc::channel::<PayloadAvailableEvent>(10);
        let test_harness = TestHarness::new_with_validators(1, Some(payload_rx)).await;

        // Advance to slot 1
        let slot_duration = test_harness.service.chain_spec.get_slot_duration();
        test_harness.service.slot_clock.advance_time(slot_duration);
        let current_slot = test_harness.service.slot_clock.now().unwrap();

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

        let event = test_harness
            .service
            .poll_for_payload_available_event()
            .await;

        assert_eq!(
            event.slot, current_slot,
            "Should have skipped stale slot 0 event and returned slot 1 event"
        );
        assert_eq!(event.block_root, Hash256::from_low_u64_be(2));
    }
}
