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
    use crate::duties_service::DutiesServiceBuilder;
    use beacon_node_fallback::{
        BeaconNodeFallback, CandidateBeaconNode, Config as BeaconNodeConfig,
    };
    use eth2::types::PtcDuty;
    use slot_clock::ManualSlotClock;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use task_executor::test_utils::TestRuntime;
    use types::{Epoch, ForkName, Hash256, MainnetEthSpec, PayloadAttestationData, Slot};
    use validator_test_rig::mock_beacon_node::MockBeaconNode;
    use validator_test_rig::mock_validator_store::MockValidatorStore;

    type E = MainnetEthSpec;

    fn build_gloas_spec() -> Arc<ChainSpec> {
        let mut spec = E::default_spec();
        spec.gloas_fork_epoch = Some(Epoch::new(0));
        spec.payload_attestation_due = Duration::from_secs(0);
        Arc::new(spec)
    }

    #[tokio::test]
    async fn start_update_service_publishes_payload_attestation() {
        let test_runtime = TestRuntime::default();
        let executor = test_runtime.task_executor.clone();
        let slot_duration = Duration::from_millis(50);
        let slot_clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        let spec = build_gloas_spec();

        let attestation_slot = Slot::new(1);
        let validator_index = 0;

        let validator_store = Arc::new(MockValidatorStore::new(validator_index));
        let pubkey = validator_store.pubkey;

        let duty = PtcDuty {
            pubkey,
            validator_index,
            slot: attestation_slot,
        };

        let duties_service = Arc::new(
            DutiesServiceBuilder::new()
                .validator_store(validator_store.clone())
                .slot_clock(slot_clock.clone())
                .beacon_nodes(Arc::new(BeaconNodeFallback::new(
                    vec![],
                    BeaconNodeConfig::default(),
                    vec![],
                    spec.clone(),
                )))
                .executor(executor.clone())
                .spec(spec.clone())
                .build()
                .expect("build duties service"),
        );

        duties_service
            .ptc_duties
            .write()
            .insert(Epoch::new(0), (Hash256::ZERO, vec![duty]));

        let mut mock_beacon_node = MockBeaconNode::<E>::new().await;

        let expected_payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: attestation_slot,
            payload_present: true,
            blob_data_available: false,
        };

        mock_beacon_node.mock_get_validator_payload_attestation_data(
            &expected_payload_attestation,
            ForkName::Gloas,
            attestation_slot,
        );
        println!("mock beacon node is: {:?}", mock_beacon_node);

        let received = Arc::new(Mutex::new(Vec::new()));

        mock_beacon_node.mock_post_beacon_pool_payload_attestations(received.clone());

        let candidate = CandidateBeaconNode::new(mock_beacon_node.beacon_api_client.clone(), 0);
        let beacon_node_fallback = Arc::new(BeaconNodeFallback::new(
            vec![candidate],
            BeaconNodeConfig::default(),
            vec![],
            spec.clone(),
        ));

        let service = PayloadAttestationService::new(
            duties_service,
            validator_store,
            slot_clock.clone(),
            beacon_node_fallback,
            executor,
            spec,
        );

        service.start_update_service().unwrap();

        // Advance slot clock to slot 1 and wait for the service to process.
        slot_clock.advance_time(slot_duration);
        sleep(Duration::from_millis(200)).await;

        let received = received.lock().unwrap();
        assert!(!received.is_empty(), "expected at least one POST request");

        let messages = &received[0];
        println!("messages is: {:?}", messages);
        assert_eq!(
            messages.len(),
            1,
            "expected one payload attestation message"
        );

        let result = &messages[0];
        println!("result is: {:?}", result);
        assert_eq!(result.validator_index, validator_index);
        assert_eq!(
            result.data.beacon_block_root,
            expected_payload_attestation.beacon_block_root
        );
        assert_eq!(result.data.slot, attestation_slot);
        assert!(result.data.payload_present);
        assert!(!result.data.blob_data_available);
        assert!(
            !result.signature.is_empty(),
            "signature should not be empty"
        );
    }
}
