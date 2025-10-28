use beacon_chain::{BeaconChain, BeaconChainTypes, ProofGenerationEvent};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, error, info};
use types::{EthSpec, ExecPayload, ExecutionProofId, Hash256, SignedBeaconBlock, Slot};

/// Service responsible for "altruistic" proof generation
///
/// This service receives notifications about newly imported blocks and generates
/// execution proofs for blocks that don't have proofs yet. This allows any node
/// (not just the block proposer) to generate and publish proofs.
///
/// Note: While proofs are optional, we don't have the proposer making proofs
/// for their own block. The proposer should insert the block into their own
/// chain, so this should trigger.
pub struct ProofGenerationService<T: BeaconChainTypes> {
    /// Reference to the beacon chain
    chain: Arc<BeaconChain<T>>,
    /// Receiver for proof generation events
    event_rx: UnboundedReceiver<ProofGenerationEvent<T::EthSpec>>,
    /// Sender to publish proofs to the network
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
}

impl<T: BeaconChainTypes> ProofGenerationService<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        event_rx: UnboundedReceiver<ProofGenerationEvent<T::EthSpec>>,
        network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) -> Self {
        Self {
            chain,
            event_rx,
            network_tx,
        }
    }

    /// Run the service event loop
    pub async fn run(mut self) {
        info!("Proof generation service started");

        while let Some(event) = self.event_rx.recv().await {
            let (block_root, slot, block) = event;

            debug!(
                slot = ?slot,
                block_root = ?block_root,
                "Received block import notification"
            );

            // Handle the event
            self.handle_block_import(block_root, slot, block).await;
        }

        info!("Proof generation service stopped");
    }

    /// Handle a block import event
    async fn handle_block_import(
        &self,
        block_root: Hash256,
        slot: Slot,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) {
        // Check if proofs are required for this epoch
        // TODO(zkproofs): alternative is to only enable this when
        // the zkvm fork is enabled. Check if this is possible
        let block_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        if !self
            .chain
            .data_availability_checker
            .execution_proof_check_required_for_epoch(block_epoch)
        {
            debug!(
                slot = ?slot,
                epoch = ?block_epoch,
                "Proofs not required for this epoch, skipping proof generation"
            );
            return;
        }

        // Check if we have a proof generator registry
        let registry = match &self.chain.zkvm_generator_registry {
            Some(registry) => registry.clone(),
            None => {
                debug!(
                    slot = ?slot,
                    "No generator registry configured, skipping proof generation"
                );
                return;
            }
        };

        // Get the list of proof types we should generate
        let proof_types = registry.proof_ids();

        if proof_types.is_empty() {
            debug!(
                slot = ?slot,
                "No proof generators registered"
            );
            return;
        }

        debug!(
            slot = ?slot,
            block_root = ?block_root,
            proof_types = proof_types.len(),
            "Checking for locally missing proofs"
        );

        // Check which proofs are missing/we haven't received yet
        for proof_id in proof_types {
            // Check if we already have this proof
            let has_proof = self.check_if_proof_exists(slot, block_root, proof_id);

            if has_proof {
                debug!(
                    slot = ?slot,
                    proof_id = ?proof_id,
                    "Proof already exists, skipping"
                );
                continue;
            }

            self.spawn_proof_generation(
                block_root,
                slot,
                block.clone(),
                proof_id,
                registry.clone(),
                self.network_tx.clone(),
            );
        }
    }

    /// Check if a proof already exists for this block
    fn check_if_proof_exists(
        &self,
        slot: Slot,
        block_root: Hash256,
        proof_id: ExecutionProofId,
    ) -> bool {
        let observed = self.chain.observed_execution_proofs.read();
        observed
            .is_known(slot, block_root, proof_id)
            .unwrap_or(false)
    }

    /// Spawn a task to generate a proof
    fn spawn_proof_generation(
        &self,
        block_root: Hash256,
        slot: Slot,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        proof_id: ExecutionProofId,
        registry: Arc<zkvm_execution_layer::GeneratorRegistry>,
        network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) {
        let chain = self.chain.clone();

        // Get the generator for this proof type
        let generator = match registry.get_generator(proof_id) {
            Some(gen) => gen,
            None => {
                debug!(
                    slot = ?slot,
                    proof_id = ?proof_id,
                    "No generator found for proof type"
                );
                return;
            }
        };

        // Spawn the generation task (async because generator.generate() is async)
        self.chain.task_executor.spawn(
            async move {
                info!(
                    slot = ?slot,
                    block_root = ?block_root,
                    proof_id = ?proof_id,
                    "Generating execution proof"
                );

                // Extract execution payload hash from the block
                let block_hash = match block.message().execution_payload() {
                    Ok(payload) => payload.block_hash(),
                    Err(e) => {
                        debug!(
                            slot = ?slot,
                            block_root = ?block_root,
                            error = ?e,
                            "Block has no execution payload, skipping proof generation"
                        );
                        return;
                    }
                };

                // Generate the proof using the generator
                let proof_result = generator.generate(slot, &block_hash, &block_root).await;

                match proof_result {
                    Ok(proof) => {
                        info!(
                            slot = ?slot,
                            proof_id = ?proof_id,
                            "Successfully generated proof"
                        );

                        // Double-check that proof didn't arrive via gossip while we were generating
                        let observed = chain.observed_execution_proofs.read();
                        if observed
                            .is_known(slot, block_root, proof_id)
                            .unwrap_or(false)
                        {
                            info!(
                                slot = ?slot,
                                proof_id = ?proof_id,
                                "Proof arrived via gossip while generating, discarding our copy"
                            );
                            return;
                        }
                        drop(observed);

                        // Note: We don't store the proof in the data availability checker because:
                        // 1. The block has already been imported and is no longer in the availability cache
                        // 2. This is altruistic proof generation - we're generating proofs for OTHER nodes
                        // 3. We already have the block, so we don't need the proof for ourselves

                        // Publish the proof to the network
                        let pubsub_message = PubsubMessage::ExecutionProof(Arc::new(proof));

                        let network_message = NetworkMessage::Publish {
                            messages: vec![pubsub_message],
                        };

                        if let Err(e) = network_tx.send(network_message) {
                            error!(
                                slot = ?slot,
                                proof_id = ?proof_id,
                                error = ?e,
                                "Failed to send proof to network service"
                            );
                        } else {
                            info!(
                                slot = ?slot,
                                proof_id = ?proof_id,
                                "Proof successfully published to network"
                            );

                            // Mark the proof as observed so we don't regenerate it
                            if let Err(e) = chain
                                .observed_execution_proofs
                                .write()
                                .observe_proof(slot, block_root, proof_id)
                            {
                                error!(
                                    slot = ?slot,
                                    proof_id = ?proof_id,
                                    error = ?e,
                                    "Failed to mark proof as observed"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            slot = ?slot,
                            proof_id = ?proof_id,
                            error = %e,
                            "Failed to generate proof"
                        );
                    }
                }
            },
            "proof_generation",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    };
    use tokio::sync::mpsc;
    use types::MinimalEthSpec as E;

    type TestHarness = BeaconChainHarness<EphemeralHarnessType<E>>;

    /// Create a test harness with minimal setup
    fn build_test_harness(validator_count: usize) -> TestHarness {
        let harness = BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .build();
        harness
    }

    #[tokio::test]
    async fn test_check_if_proof_exists_returns_false_for_new_proof() {
        let harness = build_test_harness(8);
        let chain = harness.chain.clone();

        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let service = ProofGenerationService::new(chain, event_rx, network_tx);

        let block_root = Hash256::random();
        let slot = types::Slot::new(1);
        let proof_id = ExecutionProofId::new(0).unwrap();

        // Should return false for a proof that hasn't been observed
        assert_eq!(
            service.check_if_proof_exists(slot, block_root, proof_id),
            false
        );
    }

    #[tokio::test]
    async fn test_check_if_proof_exists_returns_true_after_observation() {
        let harness = build_test_harness(8);
        let chain = harness.chain.clone();

        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let service = ProofGenerationService::new(chain.clone(), event_rx, network_tx);

        let block_root = Hash256::random();
        let slot = types::Slot::new(1);
        let proof_id = ExecutionProofId::new(0).unwrap();

        // Mark the proof as observed
        chain
            .observed_execution_proofs
            .write()
            .observe_proof(slot, block_root, proof_id)
            .unwrap();

        // Should return true for an observed proof
        assert_eq!(
            service.check_if_proof_exists(slot, block_root, proof_id),
            true
        );
    }

    #[tokio::test]
    async fn test_handle_block_import_skips_when_epoch_not_required() {
        let harness = build_test_harness(8);
        let chain = harness.chain.clone();

        // Note: zkVM is NOT enabled in this harness
        // TODO(zkproofs): can we make a harness with zkVM enabled to test this functionality in a unit test

        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let (network_tx, mut network_rx) = mpsc::unbounded_channel();

        let service = ProofGenerationService::new(chain.clone(), event_rx, network_tx);

        harness.advance_slot();

        harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let block = harness.chain.head_snapshot().beacon_block.clone();
        let block_root = block.canonical_root();
        let slot = block.slot();

        service.handle_block_import(block_root, slot, block).await;

        // Give async tasks time to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Should not have published any proofs because epoch doesn't require them
        assert!(
            network_rx.try_recv().is_err(),
            "Should not publish proofs when epoch doesn't require them"
        );
    }
}
