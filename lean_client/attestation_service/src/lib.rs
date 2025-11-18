use lean_consensus::attestation::{Attestation, AttestationData, Checkpoint, Slot};
use lean_consensus::lean_block::SignedLeanBlockWithAttestation;
use lean_consensus::lean_state::LeanState;
pub use lean_network::NetworkMessage;
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tree_hash::TreeHash;
use types::{EthSpec, Hash256, VariableList};

/// Attestation service that processes attestation duties
pub struct AttestationService<T: SlotClock, E: EthSpec> {
    /// Receiver for network messages from the network service
    network_recv: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Sender for publishing messages to the network service
    network_send: mpsc::UnboundedSender<NetworkMessage<E>>,
    /// Slot clock for timing
    slot_clock: T,
    /// Lean consensus state for processing blocks and attestations
    lean_state: Option<LeanState<E>>,
    /// Current head block root
    head_block_root: Option<Hash256>,
    /// Current justified checkpoint
    justified_checkpoint: Option<Checkpoint>,
    /// Current finalized checkpoint
    finalized_checkpoint: Option<Checkpoint>,
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationService<T, E> {
    /// Creates a new attestation service with the provided channels
    pub fn new(
        slot_clock: T,
        network_recv: mpsc::UnboundedReceiver<NetworkMessage<E>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<E>>,
    ) -> Self {
        Self {
            network_recv,
            network_send,
            slot_clock,
            lean_state: None,
            head_block_root: None,
            justified_checkpoint: None,
            finalized_checkpoint: None,
        }
    }

    /// Sets the lean state for consensus processing
    pub fn set_lean_state(&mut self, state: LeanState<E>) {
        self.lean_state = Some(state);
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
                        if let Err(e) = self.produce_attestation(current_slot, 0).await {
                            error!(slot = current_slot, error = %e, "Failed to produce attestation");
                        }

                        current_slot += 1;
                    }
                },

                // Handle network messages from the wire
                Some(network_msg) = self.network_recv.recv() => {
                    if let Err(e) = self.handle_network_message(network_msg).await {
                        error!("Error handling network message: {}", e);
                    }
                },

                // Channel closed
                else => {
                    warn!("Attestation service channel closed, shutting down");
                    break;
                }
            }
        }
    }

    /// Handles network messages received from the wire
    async fn handle_network_message(&mut self, network_msg: NetworkMessage<E>) -> Result<(), String> {
        match network_msg {
            NetworkMessage::Attestation(attestation) => {
                self.handle_attestation(attestation).await
            }
            NetworkMessage::Block(block) => {
                self.handle_block(block).await
            }
        }
    }

    /// Handles an attestation received from the network
    async fn handle_attestation(&mut self, attestation: Arc<Attestation>) -> Result<(), String> {
        info!(
            slot = attestation.attestation_data.slot.0,
            validator_id = attestation.validator_id,
            "Processing lean attestation from network"
        );

        // Use lean_consensus::lean_state::process_attestations
        if let Some(ref mut state) = self.lean_state {
            let mut attestations = VariableList::<Attestation, E::MaxAttestations>::empty();
            attestations.push((*attestation).clone()).map_err(|e| format!("Failed to add attestation: {:?}", e))?;

            state.process_attestations(&attestations)?;

            // Update our local checkpoints from the state
            self.justified_checkpoint = Some(state.latest_justified.clone());
            self.finalized_checkpoint = Some(state.latest_finalized.clone());

            debug!("Attestation processed using lean_state");
        } else {
            warn!("No lean_state available to process attestation");
        }

        Ok(())
    }

    /// Handles a block received from the network
    async fn handle_block(&mut self, block: Arc<SignedLeanBlockWithAttestation<E>>) -> Result<(), String> {
        let lean_block = &block.message.block;

        info!(
            slot = lean_block.slot.0,
            proposer_index = lean_block.proposer_index,
            "Processing lean block from network"
        );

        // Use lean_consensus::lean_state::state_transition
        if let Some(ref mut state) = self.lean_state {
            // Process block using state_transition (without signature validation for now)
            state.state_transition(lean_block, false)?;

            // Update our local checkpoints from the state
            self.justified_checkpoint = Some(state.latest_justified.clone());
            self.finalized_checkpoint = Some(state.latest_finalized.clone());

            // Update head block root
            let block_root = state.latest_block_header.tree_hash_root();
            self.update_head_block(lean_block.slot.0, block_root).await?;

            debug!("Block processed using lean_state::state_transition");
        } else {
            warn!("No lean_state available to process block");
        }

        Ok(())
    }

    /// Produces an attestation for the given slot and validator
    async fn produce_attestation(&self, slot: u64, validator_id: u64) -> Result<(), String> {
        info!(slot, validator_id, "Producing attestation");

        // Ensure we have the necessary state to produce an attestation
        let head_root = self.head_block_root
            .ok_or_else(|| "No head block root available".to_string())?;

        let source = self.justified_checkpoint
            .clone()
            .ok_or_else(|| "No justified checkpoint available".to_string())?;

        let target = self.finalized_checkpoint
            .clone()
            .ok_or_else(|| "No finalized checkpoint available".to_string())?;

        // Create head checkpoint
        let head = Checkpoint {
            slot: Slot(slot),
            root: head_root,
        };

        // Create attestation data
        let attestation_data = AttestationData {
            slot: Slot(slot),
            head,
            source,
            target,
        };

        // Create attestation
        let attestation = Attestation {
            validator_id,
            attestation_data,
        };

        debug!(
            slot,
            validator_id,
            ?head_root,
            "Produced attestation"
        );

        // Publish attestation to network
        if let Err(e) = self.network_send.send(NetworkMessage::Attestation(Arc::new(attestation))) {
            error!(slot, validator_id, "Failed to send attestation to network: {}", e);
            return Err(format!("Failed to send attestation to network: {}", e));
        }

        Ok(())
    }

    /// Updates the current head block
    async fn update_head_block(&mut self, slot: u64, block_root: Hash256) -> Result<(), String> {
        debug!(slot, ?block_root, "Updating head block");
        self.head_block_root = Some(block_root);
        Ok(())
    }

    /// Updates the justified checkpoint
    async fn update_justified_checkpoint(&mut self, slot: u64, root: Hash256) -> Result<(), String> {
        debug!(slot, ?root, "Updating justified checkpoint");
        self.justified_checkpoint = Some(Checkpoint {
            slot: Slot(slot),
            root,
        });
        Ok(())
    }

    /// Updates the finalized checkpoint
    async fn update_finalized_checkpoint(&mut self, slot: u64, root: Hash256) -> Result<(), String> {
        debug!(slot, ?root, "Updating finalized checkpoint");
        self.finalized_checkpoint = Some(Checkpoint {
            slot: Slot(slot),
            root,
        });
        Ok(())
    }
}
