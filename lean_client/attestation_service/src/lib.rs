use lean_consensus::attestation::{Checkpoint, Slot};
use slot_clock::SlotClock;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::EthSpec;

/// Messages that can be sent to the attestation service
#[derive(Debug, Clone)]
pub enum AttestationServiceMessage {
    /// Network message received from gossipsub
    NetworkMessage {
        topic: String,
        data: Vec<u8>,
    },
    /// Request to produce an attestation for the given slot
    ProduceAttestation {
        slot: u64,
        validator_id: u64,
    },
    /// Notification of a new head block
    NewHeadBlock {
        slot: u64,
        block_root: types::Hash256,
    },
    /// Notification of a new justified checkpoint
    NewJustifiedCheckpoint {
        slot: u64,
        root: types::Hash256,
    },
    /// Notification of a new finalized checkpoint
    NewFinalizedCheckpoint {
        slot: u64,
        root: types::Hash256,
    },
}

/// Attestation service that processes attestation duties
pub struct AttestationService<T: SlotClock, E: EthSpec> {
    /// Receiver for messages from the network service
    message_rx: mpsc::UnboundedReceiver<AttestationServiceMessage>,
    /// Slot clock for timing
    #[allow(dead_code)]
    slot_clock: T,
    /// Current head block root
    head_block_root: Option<types::Hash256>,
    /// Current justified checkpoint
    justified_checkpoint: Option<Checkpoint>,
    /// Current finalized checkpoint
    finalized_checkpoint: Option<Checkpoint>,
    /// Phantom data for EthSpec
    _phantom: std::marker::PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationService<T, E> {
    /// Creates a new attestation service and returns it along with a sender for messages
    pub fn new(
        slot_clock: T,
    ) -> (Self, mpsc::UnboundedSender<AttestationServiceMessage>) {
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        let service = Self {
            message_rx,
            slot_clock,
            head_block_root: None,
            justified_checkpoint: None,
            finalized_checkpoint: None,
            _phantom: std::marker::PhantomData,
        };

        (service, message_tx)
    }

    /// Runs the attestation service, processing messages as they arrive
    pub async fn run(mut self) {
        info!("Attestation service started");

        let mut current_slot = 0u64;

        loop {
            // Get duration to next slot
            let duration_to_next_slot = self.slot_clock.duration_to_next_slot()
                .unwrap_or(std::time::Duration::from_millis(100));

            tokio::select! {
                // Handle slot timing
                _ = sleep(duration_to_next_slot) => {
                    // Only perform duties if we have a valid slot time
                    if self.slot_clock.duration_to_next_slot().is_some() {
                        // Perform attestation duties for the current slot
                        info!(slot = current_slot, "Performing attestation duties");

                        // TODO: Determine validator assignments for this slot
                        // https://github.com/sigp/lighthouse/issues/XXXX
                        if let Err(e) = self.produce_attestation(current_slot, 0).await {
                            error!(slot = current_slot, error = %e, "Failed to produce attestation");
                        }

                        current_slot += 1;
                    }
                },

                // Handle incoming messages
                Some(message) = self.message_rx.recv() => {
                    if let Err(e) = self.handle_message(message).await {
                        error!("Error handling attestation service message: {}", e);
                    }
                },

                // Channel closed
                else => {
                    warn!("Attestation service message channel closed, shutting down");
                    break;
                }
            }
        }
    }

    /// Handles an incoming message
    async fn handle_message(&mut self, message: AttestationServiceMessage) -> Result<(), String> {
        match message {
            AttestationServiceMessage::NetworkMessage { topic, data } => {
                self.handle_network_message(topic, data).await
            }
            AttestationServiceMessage::ProduceAttestation { slot, validator_id } => {
                self.produce_attestation(slot, validator_id).await
            }
            AttestationServiceMessage::NewHeadBlock { slot, block_root } => {
                self.update_head_block(slot, block_root).await
            }
            AttestationServiceMessage::NewJustifiedCheckpoint { slot, root } => {
                self.update_justified_checkpoint(slot, root).await
            }
            AttestationServiceMessage::NewFinalizedCheckpoint { slot, root } => {
                self.update_finalized_checkpoint(slot, root).await
            }
        }
    }

    /// Handles a network message received from gossipsub
    async fn handle_network_message(&mut self, topic: String, data: Vec<u8>) -> Result<(), String> {
        info!(
            topic = %topic,
            data_len = data.len(),
            "Received network message"
        );

        // TODO: Parse and process the network message based on topic
        // https://github.com/sigp/lighthouse/issues/XXXX

        Ok(())
    }

    /// Produces an attestation for the given slot and validator
    async fn produce_attestation(&self, slot: u64, validator_id: u64) -> Result<(), String> {
        info!(slot, validator_id, "Producing attestation");

        // TODO: Implement attestation production logic
        // https://github.com/sigp/lighthouse/issues/XXXX

        Ok(())
    }

    /// Updates the current head block
    async fn update_head_block(&mut self, slot: u64, block_root: types::Hash256) -> Result<(), String> {
        debug!(slot, ?block_root, "Updating head block");
        self.head_block_root = Some(block_root);
        Ok(())
    }

    /// Updates the justified checkpoint
    async fn update_justified_checkpoint(&mut self, slot: u64, root: types::Hash256) -> Result<(), String> {
        debug!(slot, ?root, "Updating justified checkpoint");
        self.justified_checkpoint = Some(Checkpoint {
            slot: Slot(slot),
            root,
        });
        Ok(())
    }

    /// Updates the finalized checkpoint
    async fn update_finalized_checkpoint(&mut self, slot: u64, root: types::Hash256) -> Result<(), String> {
        debug!(slot, ?root, "Updating finalized checkpoint");
        self.finalized_checkpoint = Some(Checkpoint {
            slot: Slot(slot),
            root,
        });
        Ok(())
    }
}
