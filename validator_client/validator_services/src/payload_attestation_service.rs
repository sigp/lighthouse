use crate::duties_service::DutiesService;
use beacon_node_fallback::{BeaconNodeFallback, beacon_head_monitor::PayloadAvailableEvent};
use logging::crit;
use slot_clock::{SlotClock};
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};
use types::{ChainSpec, EthSpec, Slot};
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

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> PayloadAttestationService<S, T> {
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

                let _early_payload_event = if self.payload_available_rx.is_some() {
                    tokio::select! {
                        _ = sleep(duration_to_next_slot + payload_attestation_due) => None,
                        event = self.poll_for_payload_available_event() => event,
                    }
                } else {
                    sleep(duration_to_next_slot + payload_attestation_due).await;
                    None
                };                

                let Some(attestation_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock after sleep");
                    continue;
                };

                let mut last_slot = self.latest_voted_slot.lock().await;

                if attestation_slot <= *last_slot {
                    debug!(%attestation_slot, "Payload attestation already produced for this slot");
                    continue;
                };

                let service = self.clone();
                self.executor.spawn(
                    async move {
                        service.produce_and_publish(attestation_slot).await;
                    },
                    "payload_attestation_producer",
                );
                *last_slot = attestation_slot;
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
