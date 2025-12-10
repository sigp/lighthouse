use lean_consensus::attestation::{
    Attestation, AttestationData, Checkpoint, SignedAttestation, Slot as LeanSlot,
};
use lean_consensus::lean_block::{
    LeanBlock, LeanBlockBody, LeanBlockWithAttestation, SignedLeanBlockWithAttestation,
};
use lean_consensus::lean_state::{INTERVALS_PER_SLOT, JUSTIFICATION_LOOKBACK_SLOTS, LeanState, SECONDS_PER_INTERVAL};
use lean_crypto::Signature;
use lean_forkchoice::helpers::get_fork_choice_head;
use lean_keystore::{KeyStore, ValidatorKeyPair};
pub use lean_network::NetworkMessage;
use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use slot_clock::SlotClock;
use std::sync::Arc;
use store::KeyValueStore;
use tokio::sync::mpsc;
use tokio::time::{Duration as TokioDuration, sleep};
use tracing::{debug, error, info, warn};
use tree_hash::TreeHash;
use types::{EthSpec, Hash256, List, Slot, VariableList};

mod chain;

use chain::LeanChain;

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8 as Scheme;

/// Validator service that processes validator duties including attestations
///
/// Manages interval ticks and network message processing using tokio::select! for simple
/// async handling without complex pinning or stream implementation.
pub struct ValidatorService<T: SlotClock, E: EthSpec, D: KeyValueStore<E>> {
    /// Receiver for network messages from the network service
    network_recv: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Sender for publishing messages to the network service
    network_send: mpsc::UnboundedSender<NetworkMessage<E>>,
    /// Slot clock for timing
    slot_clock: T,
    /// Chain coordinator handling fork choice and storage interactions
    chain: LeanChain<E, D>,
    /// Validator index managed by this node
    validator_index: u64,
    /// Hash-sig secret key decoded from the keystore JSON
    hashsig_secret_key: <Scheme as SignatureScheme>::SecretKey,
    /// Key store for loading validator public keys for signature verification
    keystore: KeyStore,
    /// Counter for periodic status logging
    status_interval_counter: u64,
}

impl<T: SlotClock + 'static, E: EthSpec, D: KeyValueStore<E>> ValidatorService<T, E, D> {
    /// Creates a new validator service with the provided channels
    pub fn new(
        slot_clock: T,
        network_recv: mpsc::UnboundedReceiver<NetworkMessage<E>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<E>>,
        db: Arc<D>,
        validator_index: u64,
        validator_key_pair: ValidatorKeyPair,
        keystore: KeyStore,
    ) -> Result<Self, String> {
        let chain = LeanChain::new(db);
        let hashsig_secret_key = validator_key_pair.hashsig_secret_key()?;
        // Ensure the public key JSON is well-formed even if we do not store it explicitly.
        let _ = validator_key_pair.hashsig_public_key()?;

        Ok(Self {
            network_recv,
            network_send,
            slot_clock,
            chain,
            validator_index,
            hashsig_secret_key,
            keystore,
            status_interval_counter: 0,
        })
    }

    /// Signs an attestation message using XMSS private key
    ///
    /// The message to sign is the SSZ-encoded Attestation.
    /// Uses the hash-sig crate to create an XMSS signature.
    fn sign_attestation(
        &self,
        validator_id: u64,
        attestation: &Attestation,
        epoch: u64,
    ) -> Result<Signature, String> {
        // Hash the attestation message using tree hash (32 bytes)
        let message_hash = attestation.tree_hash_root();

        if validator_id != self.validator_index {
            return Err(format!(
                "Validator {} is not assigned to this node (controls {})",
                validator_id, self.validator_index
            ));
        }

        // Sign the message hash using the XMSS scheme
        // The epoch parameter is used for XMSS signature generation (must be u32)
        let epoch_u32 = epoch
            .try_into()
            .map_err(|_| format!("Epoch {} is too large for u32", epoch))?;
        let xmss_signature = Scheme::sign(&self.hashsig_secret_key, epoch_u32, &message_hash.0)
            .map_err(|e| format!("Failed to sign attestation with XMSS: {:?}", e))?;

        // Serialize the XMSS signature to bytes using leanSig's serialization
        let signature_bytes_vec = xmss_signature.to_bytes();

        if signature_bytes_vec.len() != lean_crypto::signature::SIGNATURE_SIZE {
            return Err(format!(
                "Invalid signature size: expected {}, got {}",
                lean_crypto::signature::SIGNATURE_SIZE,
                signature_bytes_vec.len()
            ));
        }

        // Convert to fixed-size array
        let mut signature_bytes = [0u8; lean_crypto::signature::SIGNATURE_SIZE];
        signature_bytes.copy_from_slice(&signature_bytes_vec);

        // Create Signature from fixed-size array
        Ok(Signature::from_bytes(signature_bytes))
    }

    /// Sets the lean state for consensus processing by storing it in cache and database
    pub fn set_lean_state(&mut self, state: LeanState<E>) -> Result<(), String> {
        // Save state keyed by its block root (genesis or current block)
        let state_root = state.latest_block_header.tree_hash_root();
        self.chain.save_state(state_root, &state)
    }

    /// Waits for genesis time to arrive
    async fn wait_for_genesis(&self) {
        // SystemTimeSlotClock::genesis_duration() returns the duration since UNIX_EPOCH to genesis
        let genesis_time = self.slot_clock.genesis_duration();

        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(n) => n,
            Err(_) => {
                error!("System time is before UNIX EPOCH!");
                return;
            }
        };

        if now < genesis_time {
            let wait_duration = genesis_time - now;
            info!(
                wait_seconds = wait_duration.as_secs(),
                genesis_time = genesis_time.as_secs(),
                "Waiting for genesis"
            );
            sleep(wait_duration).await;
            info!("Genesis time reached");
        } else {
            debug!("Genesis time is in the past, starting immediately");
        }
    }

    /// Runs the validator service, processing messages and interval ticks
    ///
    /// Uses tokio::select! to handle:
    /// - Interval tick timing (calculated from slot_clock)
    /// - Network messages from the network service
    pub async fn run(mut self) {
        info!("Validator service started");

        // Wait for genesis
        self.wait_for_genesis().await;

        loop {
            // Use slot_clock to determine when the next interval occurs
            let next_interval_duration = match self.get_time_to_next_interval() {
                Some(d) => d,
                None => {
                    // Critical failure: slot clock is unavailable or broken
                    // The validator service cannot function without access to the slot clock
                    error!(
                        "CRITICAL: Unable to determine next interval - slot clock is unavailable. \
                        Validator service cannot proceed. This indicates a serious system failure."
                    );
                    break;
                }
            };

            tokio::select! {
                // Wait for the next interval boundary
                _ = sleep(next_interval_duration) => {
                    // Process the interval tick
                    if let Err(e) = self.process_interval_tick().await {
                        error!(error = %e, "Failed to process interval tick");
                    }
                }

                // Handle network messages
                Some(network_msg) = self.network_recv.recv() => {
                    if let Err(e) = self.handle_network_message(network_msg).await {
                        error!("Error handling network message: {}", e);
                    }
                }

                // If both channels are closed, exit
                else => {
                    warn!("Network message channel closed, validator service shutting down");
                    break;
                }
            }
        }

        info!("Validator service stopped");
    }

    /// Calculates the time until the next interval boundary using the slot clock
    fn get_time_to_next_interval(&self) -> Option<TokioDuration> {
        let now = self.slot_clock.now_duration()?;
        let current_slot = self.slot_clock.now()?;
        let slot_start = self.slot_clock.start_of(current_slot)?;

        // Time elapsed since slot start
        let time_since_slot_start = now.checked_sub(slot_start)?;
        let elapsed_secs = time_since_slot_start.as_secs();

        // Current interval (0-3)
        let current_interval = elapsed_secs / SECONDS_PER_INTERVAL;

        // If we're past all 4 intervals in this slot, wait for next slot
        if current_interval >= INTERVALS_PER_SLOT {
            return self.slot_clock.duration_to_next_slot().map(|d| {
                TokioDuration::from_secs(d.as_secs())
                    + TokioDuration::from_nanos(d.subsec_nanos() as u64)
            });
        }

        // Calculate when the next interval starts
        let next_interval_secs = (current_interval + 1) * SECONDS_PER_INTERVAL;
        let time_to_next_interval =
            std::time::Duration::from_secs(next_interval_secs - elapsed_secs);

        Some(
            TokioDuration::from_secs(time_to_next_interval.as_secs())
                + TokioDuration::from_nanos(time_to_next_interval.subsec_nanos() as u64),
        )
    }

    /// Processes an interval tick: calculates current interval and executes appropriate duties
    async fn process_interval_tick(&mut self) -> Result<(), String> {
        if let Some((current_slot, current_interval)) = self.get_current_interval() {
            debug!(
                slot = current_slot.as_u64(),
                interval = current_interval,
                "Processing interval tick"
            );

            self.tick_interval().await?;
        }

        Ok(())
    }

    /// Gets the current slot and interval number
    ///
    /// Returns `Some((slot, interval))` if we can determine the current interval,
    /// or `None` if the slot clock cannot be read.
    fn get_current_interval(&self) -> Option<(Slot, u64)> {
        let current_slot = self.slot_clock.now()?;
        let now = self.slot_clock.now_duration()?;
        let slot_start = self.slot_clock.start_of(current_slot)?;

        // Calculate time since slot start
        let time_since_slot_start = now.checked_sub(slot_start)?;

        // Calculate current interval (0-3)
        let current_interval =
            (time_since_slot_start.as_secs() / SECONDS_PER_INTERVAL) % INTERVALS_PER_SLOT;

        Some((current_slot, current_interval))
    }

    /// Log the current chain status (similar to other clients' CHAIN STATUS)
    fn log_chain_status(&self, current_slot: Slot) -> Result<(), String> {
        // Get head root, return early if not available
        let head_root = match self.chain.fetch_head_root()? {
            Some(root) => root,
            None => {
                debug!("Head root not available for chain status logging");
                return Ok(());
            }
        };

        // Get head block, return early if not available
        let head_block = match self.chain.fetch_block(head_root)? {
            Some(block) => block,
            None => {
                debug!("Head block not found for chain status logging");
                return Ok(());
            }
        };

        // Get head state, return early if not available
        let state = match self.chain.get_head_state() {
            Some(state) => state,
            None => {
                debug!("Head state not available for chain status logging");
                return Ok(());
            }
        };

        let justified = &state.latest_justified;
        let finalized = &state.latest_finalized;

        let sep = "=".repeat(63);
        info!(
            separator = %sep,
            current_slot = current_slot.as_u64(),
            head_slot = head_block.slot.0,
            head_block_root = %head_root,
            parent_block_root = %head_block.parent_root,
            state_root = %state.latest_block_header.state_root,
            justified_slot = justified.slot.0,
            justified_root = %justified.root,
            finalized_slot = finalized.slot.0,
            finalized_root = %finalized.root,
            "CHAIN STATUS: Current Slot: {} | Head Slot: {} | Behind: 0",
            current_slot.as_u64(),
            head_block.slot.0
        );

        Ok(())
    }
}

impl<T: SlotClock + 'static, E: EthSpec, D: KeyValueStore<E>> ValidatorService<T, E, D> {
    /// Processes a single interval tick
    ///
    /// Implements the `tick_interval()` logic from the spec:
    /// - Interval 0: Accept new attestations if proposal exists, update fork choice
    /// - Interval 1: Validators create and gossip attestations
    /// - Interval 2: Update safe target with 2/3+ majority
    /// - Interval 3: Accept accumulated attestations (new → known), update fork choice
    pub async fn tick_interval(&mut self) -> Result<(), String> {
        let current_slot = self
            .slot_clock
            .now()
            .ok_or_else(|| "Unable to determine current slot".to_string())?;
        let now = self
            .slot_clock
            .now_duration()
            .ok_or_else(|| "Unable to determine current time".to_string())?;
        let slot_u64 = current_slot.as_u64();
        let slot_start = self
            .slot_clock
            .start_of(current_slot)
            .ok_or_else(|| format!("Unable to determine start of slot {}", slot_u64))?;

        // Calculate current interval within slot (0-3)
        let time_since_slot_start = now
            .checked_sub(slot_start)
            .ok_or_else(|| "Current time is before slot start".to_string())?;
        let interval =
            (time_since_slot_start.as_secs() / SECONDS_PER_INTERVAL) % INTERVALS_PER_SLOT;

        debug!(slot = slot_u64, interval, "Processing interval tick");

        // Log chain status every slot (every 4 intervals)
        if interval == 3 {
            self.log_chain_status(current_slot)?;
        }
        self.status_interval_counter += 1;

        // Handle each interval
        match interval {
            0 => {
                // Interval 0: Produce block if this validator is proposer, then accept attestations if proposal exists
                if let Err(e) = self.perform_proposal_duties(current_slot).await {
                    warn!(error = %e, "Failed to perform proposal duties");
                }

                if self.has_proposal_for_slot(current_slot)? {
                    info!(slot = slot_u64, "Interval 0: Accepting new attestations");
                    self.chain.promote_new_attestations()?;
                    self.update_fork_choice_head().await?;
                } else {
                    debug!(
                        slot = slot_u64,
                        "Interval 0: No proposal, skipping attestation acceptance"
                    );
                }
            }
            1 => {
                // Interval 1: Validators create and gossip attestations
                debug!(slot = slot_u64, "Interval 1: Validator attesting");
                if let Err(e) = self.perform_attestation_duties(slot_u64).await {
                    warn!(error = %e, "Failed to perform attestation duties");
                }

                // Log chain status at interval 1
                if let Ok(state) = self
                    .chain
                    .get_head_state()
                    .ok_or_else(|| "No state".to_string())
                {
                    info!(
                        current_slot = slot_u64,
                        head_slot = state.slot.0,
                        justified_slot = state.latest_justified.slot.0,
                        justified_root = ?state.latest_justified.root,
                        finalized_slot = state.latest_finalized.slot.0,
                        finalized_root = ?state.latest_finalized.root,
                        "CHAIN STATUS | Slot {} | Justified: {} | Finalized: {}",
                        slot_u64,
                        state.latest_justified.slot.0,
                        state.latest_finalized.slot.0
                    );
                }
            }
            2 => {
                // Interval 2: Update safe target with 2/3+ majority
                debug!(slot = slot_u64, "Interval 2: Updating safe target");
                self.update_safe_target().await?;
            }
            3 => {
                // Interval 3: Accept accumulated attestations
                info!(
                    slot = slot_u64,
                    "Interval 3: Accepting accumulated attestations"
                );
                self.chain.promote_new_attestations()?;
                self.update_fork_choice_head().await?;
            }
            _ => {
                warn!(interval, "Unexpected interval value (should be 0-3)");
            }
        }

        Ok(())
    }

    /// Checks if there's a proposal (block) for the given slot
    fn has_proposal_for_slot(&self, slot: Slot) -> Result<bool, String> {
        // Check if we have a block for this slot
        // Load all blocks and check if any match this slot
        let blocks = self.chain.load_all_blocks()?;
        let slot_u64 = slot.as_u64();
        // Compare using the u64 value since block.slot is lean_consensus::Slot(u64)
        Ok(blocks.values().any(|block| block.slot.0 == slot_u64))
    }

    /// Updates the fork choice head after accepting new attestations
    async fn update_fork_choice_head(&mut self) -> Result<(), String> {
        // Get current head state from cache
        let state = self
            .chain
            .get_head_state()
            .ok_or_else(|| "No lean_state available for fork choice".to_string())?;

        // Update head using fork choice algorithm
        let new_head = self.chain.update_head(&state)?;
        debug!(
            ?new_head,
            "Updated fork choice head after attestation promotion"
        );

        Ok(())
    }

    /// Updates the safe target checkpoint
    ///
    /// Computes target that has sufficient (2/3+ majority) attestation support.
    /// The safe target represents a block with enough attestation weight to be
    /// considered "safe" for validators to attest to.
    ///
    /// The safe target is calculated using fork choice with a minimum score threshold
    /// of 2/3 of validators, then persisted to the database.
    async fn update_safe_target(&mut self) -> Result<(), String> {
        // Load all blocks and attestations
        let all_blocks = self.chain.load_all_blocks()?;
        let all_attestations = self.chain.load_known_attestations()?;

        // Get current head state from cache for validator count
        let state = self
            .chain
            .get_head_state()
            .ok_or_else(|| "No lean_state available for safe target calculation".to_string())?;

        let num_validators = state.validators.len();

        // Calculate 2/3 majority threshold (ceiling division)
        let min_target_score = (num_validators * 2 + 2) / 3; // Ceiling division

        // Find head with minimum attestation threshold
        let latest_justified = &state.latest_justified;
        let safe_target = get_fork_choice_head(
            &all_blocks,
            latest_justified.root,
            &all_attestations,
            min_target_score,
        );

        // Persist safe target to database
        self.chain.save_safe_target(safe_target)?;

        debug!(
            ?safe_target,
            num_validators, min_target_score, "Updated and persisted safe target"
        );

        Ok(())
    }
    /// Handles network messages received from the wire
    async fn handle_network_message(
        &mut self,
        network_msg: NetworkMessage<E>,
    ) -> Result<(), String> {
        match network_msg {
            NetworkMessage::Attestation(signed_attestation) => {
                // Network gossip attestations are processed as "new" (pending)
                // Verify the signature before processing
                self.verify_and_handle_attestation(signed_attestation, false)
                    .await
            }
            NetworkMessage::Block(block) => self.handle_block(block).await,
        }
    }

    /// Verifies the attestation signature and then handles it
    ///
    /// # Arguments
    /// * `signed_attestation` - The signed attestation to verify and process
    /// * `is_from_block` - True if attestation came from block body, False if from network gossip
    async fn verify_and_handle_attestation(
        &mut self,
        signed_attestation: Arc<SignedAttestation>,
        is_from_block: bool,
    ) -> Result<(), String> {
        // Verify the attestation signature
        let epoch = signed_attestation.message.attestation_data.slot.0 / 32;
        let message_hash = signed_attestation.message.tree_hash_root();
        let validator_id = signed_attestation.message.validator_id;

        // NOTE: Signature verification will be implemented when signature verification functions
        // become available from the leansig library. For now, we accept all attestations.

        debug!(validator_id, epoch, "Attestation received and accepted");

        // Process the attestation
        self.handle_attestation(signed_attestation.clone(), is_from_block)
            .await
    }

    /// Handles an attestation received from the network or block
    ///
    /// Implements attestation pipelining according to the spec:
    /// - Network gossip attestations → saved as "new" (pending)
    /// - Block body attestations → saved as "known" (immediately contribute to fork choice)
    ///
    /// # Arguments
    /// * `signed_attestation` - The signed attestation to process
    /// * `is_from_block` - True if attestation came from block body, False if from network gossip
    async fn handle_attestation(
        &mut self,
        signed_attestation: Arc<SignedAttestation>,
        is_from_block: bool,
    ) -> Result<(), String> {
        let attestation = &signed_attestation.message;
        let attestation_slot = attestation.attestation_data.slot.0;
        let validator_id = attestation.validator_id;

        info!(
            slot = attestation_slot,
            validator_id, is_from_block, "Processing lean attestation"
        );

        // NOTE: Attestations do NOT modify state outside of block processing.
        // States are immutable snapshots at each block root. Only block.body.attestations
        // modify state during state_transition. Gossip attestations only affect fork choice.
        //
        // Attestation processing:
        // 1. Block body attestations → processed during state_transition in handle_block
        // 2. Gossip attestations → saved for fork choice only, don't modify state
        //
        // This prevents state corruption where gossip attestations would overwrite
        // block post-states, causing parent root mismatches.

        // Use the SignedAttestation received from the network (already has signature)
        // No need to create a new signature - the attestation was signed by the original validator

        // Implement attestation pipelining:
        // - Block body attestations → known (immediately contribute to fork choice)
        // - Network gossip attestations → new (pending, wait for interval tick)
        if is_from_block {
            // On-chain attestation: process immediately as "known"
            // Check if this supersedes existing known attestation
            if let Ok(existing_known) = self.chain.load_known_attestations() {
                if let Some(existing) = existing_known.get(&validator_id) {
                    // Only replace if new attestation is from a later slot
                    if existing.message.attestation_data.slot.0 >= attestation_slot {
                        debug!(
                            validator_id,
                            existing_slot = existing.message.attestation_data.slot.0,
                            new_slot = attestation_slot,
                            "Skipping attestation - existing known attestation is newer or equal"
                        );
                        return Ok(());
                    }
                }
            }

            // Save as known attestation (contributes to fork choice immediately)
            self.chain
                .save_known_attestation(validator_id, &signed_attestation)?;

            let head_root = attestation.attestation_data.head.root;
            if let Err(e) = self.chain.apply_attestation_weight(validator_id, head_root) {
                warn!(
                    validator_id,
                    ?head_root,
                    error = %e,
                    "Failed to update fork choice weight for known attestation"
                );
            }

            // Remove from new attestations if this supersedes it
            // Check if there's a new attestation that should be removed
            if let Ok(new_attestations) = self.chain.load_new_attestations() {
                if let Some(new_att) = new_attestations.get(&validator_id) {
                    if new_att.message.attestation_data.slot.0 <= attestation_slot {
                        // Remove the new attestation as it's superseded by the known one
                        self.chain.delete_new_attestation(validator_id)?;
                    }
                }
            }

            debug!(
                validator_id,
                slot = attestation_slot,
                "Saved attestation as known (from block body)"
            );
        } else {
            // Network gossip attestation: save as "new" (pending)
            // Check if this supersedes existing new attestation
            if let Ok(existing_new) = self.chain.load_new_attestations() {
                if let Some(existing) = existing_new.get(&validator_id) {
                    // Only replace if new attestation is from a later slot
                    if existing.message.attestation_data.slot.0 >= attestation_slot {
                        debug!(
                            validator_id,
                            existing_slot = existing.message.attestation_data.slot.0,
                            new_slot = attestation_slot,
                            "Skipping attestation - existing new attestation is newer or equal"
                        );
                        return Ok(());
                    }
                }
            }

            // Save as new attestation (does not contribute to fork choice yet)
            self.chain
                .save_new_attestation(validator_id, &signed_attestation)?;

            debug!(
                validator_id,
                slot = attestation_slot,
                "Saved attestation as new (from network gossip)"
            );
        }

        debug!(
            validator_id,
            slot = attestation_slot,
            is_from_block,
            "Attestation saved for fork choice (state unchanged)"
        );

        Ok(())
    }

    /// Handles a block received from the network (implements on_block from spec)
    ///
    /// This method integrates a block into the forkchoice store by:
    /// 1. Validating the block's parent exists
    /// 2. Computing the post-state via the state transition function
    /// 3. Processing attestations included in the block body (on-chain)
    /// 4. Updating the forkchoice head
    /// 5. Processing the proposer's attestation (as if gossiped)
    async fn handle_block(
        &mut self,
        signed_block: Arc<SignedLeanBlockWithAttestation<E>>,
    ) -> Result<(), String> {
        // Unpack block components
        let block = &signed_block.message.block;
        let proposer_attestation = &signed_block.message.proposer_attestation;
        let block_root = block.tree_hash_root();

        info!(
            slot = block.slot.0,
            proposer_index = block.proposer_index,
            ?block_root,
            "Processing lean block from network (on_block)"
        );

        // Skip duplicate blocks (idempotent operation)
        if self.chain.block_exists(block_root)? {
            debug!(?block_root, "Block already processed, skipping");
            return Ok(());
        }

        // Fetch parent state from cache
        //
        // The parent state must exist before processing this block.
        // If missing, the node must sync the parent chain first.
        let parent_state = self.chain.fetch_state(&block.parent_root)
            .ok_or_else(|| {
                format!(
                    "Parent state not found in cache (root={:?}). Sync parent chain before processing block at slot {}.",
                    block.parent_root, block.slot.0
                )
            })?;

        debug!(
            parent_slot = parent_state.slot.0,
            parent_justified = parent_state.latest_justified.slot.0,
            "Fetched parent state from cache for block processing"
        );

        // Clone parent state to create post-state
        let mut post_state = LeanChain::<E, D>::clone_state(&parent_state)?;

        debug!("Cloned parent state for state transition");

        // Validate cryptographic signatures
        //
        // NOTE: XMSS signature verification is not yet implemented.
        // This is blocked on:
        // 1. KoalaBear finite field implementation (P = 2^31 - 2^24 + 1)
        // 2. Poseidon2 permutation implementation
        // 3. Full XMSS signature scheme implementation
        //
        // For now, signature validation is skipped (devnet mode).
        // Once XMSS is implemented, this should call:
        //   signed_block.verify_all_signatures(state, epoch)?
        //
        // See: lean_client/crypto/src/signature.rs for signature structure
        // See: lean_client/IMPLEMENTATION_STATUS.md for implementation status
        let valid_signatures = false;

        // Execute state transition function to compute post-block state
        post_state.state_transition(block, valid_signatures)?;

        debug!(
            post_slot = post_state.slot.0,
            post_justified = post_state.latest_justified.slot.0,
            post_finalized = post_state.latest_finalized.slot.0,
            "State transition completed"
        );

        // Save block and post-state to cache and database
        // Post-state is keyed by block_root, representing the state after processing this block
        // IMPORTANT: Update latest_block_header.state_root to the block's state_root
        // so that when this state is loaded later, the header's tree_hash will match the block_root
        post_state.latest_block_header.state_root = block.state_root;

        self.chain.save_block(block_root, block)?;
        self.chain.save_state(block_root, &post_state)?;

        debug!(?block_root, "Block and state saved to cache and database");

        // Ensure parent chain exists in proto array and register the new block.
        self.chain
            .register_block(block_root, block.slot, block.parent_root)?;

        // Process block body attestations
        //
        // Iterate over attestations in the block body.
        // These are historical attestations from other validators included by the proposer.
        // They are processed immediately as "known" attestations (is_from_block=true).
        for attestation in block.body.attestations.iter() {
            let signed_attestation = Arc::new(SignedAttestation {
                message: attestation.clone(),
                signature: lean_crypto::Signature::zero(),
            });

            if let Err(e) = self
                .verify_and_handle_attestation(signed_attestation, true)
                .await
            {
                warn!(
                    validator_id = attestation.validator_id,
                    error = %e,
                    "Failed to process block body attestation"
                );
                // Continue processing other attestations even if one fails
            }
        }

        debug!(
            attestation_count = block.body.attestations.len(),
            "Block body attestations processed"
        );

        // Update forkchoice head
        //
        // IMPORTANT: This must happen BEFORE processing proposer attestation
        // to prevent the proposer from gaining circular weight advantage.

        // Run fork choice algorithm
        let new_head = self.chain.update_head(&post_state)?;

        debug!(?new_head, "Fork choice updated head");

        // Process proposer attestation as if received via gossip
        //
        // The proposer casts their attestation in interval 1, after block
        // proposal. This attestation should:
        // 1. NOT affect this block's fork choice position (processed as "new")
        // 2. Be available for inclusion in future blocks
        // 3. Influence fork choice only after interval 3 (end of slot)
        let signed_proposer_attestation = Arc::new(SignedAttestation {
            message: proposer_attestation.clone(),
            signature: lean_crypto::Signature::zero(),
        });

        if let Err(e) = self
            .verify_and_handle_attestation(signed_proposer_attestation, false)
            .await
        {
            warn!(
                validator_id = proposer_attestation.validator_id,
                error = %e,
                "Failed to process proposer attestation"
            );
        }

        // Log chain status
        info!(
            slot = block.slot.0,
            head_block_root = ?block_root,
            parent_root = ?block.parent_root,
            state_root = ?post_state.latest_block_header.state_root,
            justified_slot = post_state.latest_justified.slot.0,
            justified_root = ?post_state.latest_justified.root,
            finalized_slot = post_state.latest_finalized.slot.0,
            finalized_root = ?post_state.latest_finalized.root,
            attestation_count = block.body.attestations.len(),
            "CHAIN STATUS: Block processed | Slot {} | Justified: {} | Finalized: {}",
            block.slot.0,
            post_state.latest_justified.slot.0,
            post_state.latest_finalized.slot.0
        );

        Ok(())
    }

    /// Performs proposal duties if this validator is the proposer for the slot
    ///
    /// Checks if this validator is the proposer for the given slot. If so, produces
    /// a block and publishes it to the network.
    async fn perform_proposal_duties(&mut self, slot: Slot) -> Result<(), String> {
        let slot_u64 = slot.as_u64();

        // Fetch current head state from cache
        let state = self
            .chain
            .get_head_state()
            .ok_or_else(|| "No lean_state available to check proposal duties".to_string())?;

        // For now, just try to produce a block if we're one of the validators
        // In a full implementation, we would check the proposer schedule
        let num_validators = state.validators.len() as u64;
        if num_validators == 0 {
            return Err("No validators in state".to_string());
        }

        let expected_proposer = slot_u64 % num_validators;
        if expected_proposer != self.validator_index {
            debug!(
                slot = slot_u64,
                expected_proposer,
                validator_id = self.validator_index,
                "Not proposer for this slot"
            );
            return Ok(());
        }

        debug!(
            slot = slot_u64,
            proposer = self.validator_index,
            num_validators,
            "Performing proposal duties"
        );

        if let Err(e) = self.produce_block(slot).await {
            debug!(
                slot = slot_u64,
                error = %e,
                "Failed to produce block"
            );
        }

        Ok(())
    }

    /// Produces a block for the given slot
    ///
    /// Creates a simple block with:
    /// 1. Current head as parent
    /// 2. State root computed from current state
    /// 3. Signs and publishes the block to the network
    async fn produce_block(&mut self, slot: Slot) -> Result<(), String> {
        let slot_u64 = slot.as_u64();
        debug!(slot = slot_u64, "=== BLOCK PRODUCTION START ===");

        // Fetch current head state from cache
        debug!(slot = slot_u64, "Fetching head state from cache");
        let parent_state = self
            .chain
            .get_head_state()
            .ok_or_else(|| "No lean_state available to produce block".to_string())?;

        debug!(
            slot = slot_u64,
            parent_slot = parent_state.slot.0,
            "Head state fetched"
        );

        let num_validators = parent_state.validators.len() as u64;
        debug!(
            slot = slot_u64,
            num_validators = num_validators,
            "Validator count"
        );

        if num_validators == 0 {
            return Err("No validators available in state".to_string());
        }

        let expected_proposer = slot_u64 % num_validators;
        debug!(
            slot = slot_u64,
            expected_proposer = expected_proposer,
            self_validator_index = self.validator_index,
            "Proposer check"
        );

        if self.validator_index != expected_proposer {
            return Err(format!(
                "Validator {} is proposer for slot {} but this node controls validator {}",
                expected_proposer, slot_u64, self.validator_index
            ));
        }

        debug!(
            slot = slot_u64,
            "This validator IS the proposer, proceeding"
        );

        // Clone parent state to compute post-state
        // Advances state before computing state_root
        debug!(slot = slot_u64, "Cloning parent state");
        let mut post_state = LeanChain::<E, D>::clone_state(&parent_state)?;
        debug!(
            slot = slot_u64,
            cloned_state_slot = post_state.slot.0,
            "State cloned successfully"
        );

        // Create the block with LeanSlot type
        let lean_slot = LeanSlot(slot_u64);
        let validator_id = self.validator_index;

        // Load known attestations from store and include them in block body
        let known_attestations = match self.chain.load_known_attestations() {
            Ok(attestations) => attestations,
            Err(e) => {
                warn!("Failed to load known attestations: {}", e);
                Default::default()
            }
        };

        // Convert HashMap to VariableList of Attestations (extract just the message)
        let mut attestation_list = VariableList::default();
        for (_, signed_att) in known_attestations.iter() {
            attestation_list
                .push(signed_att.message.clone())
                .map_err(|e| format!("Failed to add attestation to block body: {:?}", e))?;
        }

        let body = LeanBlockBody {
            attestations: attestation_list,
        };

        debug!(
            slot = slot_u64,
            attestation_count = body.attestations.len(),
            "Created block body with attestations"
        );

        debug!(slot = slot_u64, "Fetching parent root from fork choice");
        // The parent root is the root of the block that this state came from.
        // This is the head of the fork choice tree (the most recent block we've processed).
        let parent_root = self.chain.store().fetch_head_root()?.unwrap_or_else(|| {
            // Fallback: reconstruct from genesis state
            debug!(
                slot = slot_u64,
                "No fork choice head found, using genesis block header hash"
            );
            let parent_block_header = &parent_state.latest_block_header;
            debug!(
                slot = slot_u64,
                genesis_header_slot = parent_block_header.slot.0,
                "Computing parent root from genesis header"
            );
            parent_state.latest_block_header.tree_hash_root()
        });

        debug!(
            slot = slot_u64,
            ?parent_root,
            parent_state_slot = parent_state.slot.0,
            "Block parent root set from fork choice head"
        );

        let block = LeanBlock {
            slot: lean_slot,
            proposer_index: validator_id,
            parent_root,
            state_root: Hash256::ZERO,
            body,
        };

        debug!(
            slot = slot_u64,
            "Initial block created with parent_root. Starting state transitions"
        );

        // Advance post-state to block's slot
        // This must happen BEFORE computing state_root
        debug!(
            slot = slot_u64,
            pre_slot = post_state.slot.0,
            target_slot = lean_slot.0,
            "Processing empty slots"
        );
        post_state.process_slots(lean_slot)?;
        debug!(
            slot = slot_u64,
            post_slot = post_state.slot.0,
            "Empty slots processed"
        );

        // Process the block header to update latest_block_header in state
        // This is critical! Without this, state.latest_block_header stays pointing to parent,
        // causing all subsequent blocks to reference the wrong parent root
        debug!(slot = slot_u64, "Processing block header");
        post_state.process_block(&block)?;
        debug!(
            slot = slot_u64,
            latest_header_slot = post_state.latest_block_header.slot.0,
            "Block header processed"
        );

        // Compute state root from post-state
        debug!(slot = slot_u64, ?post_state, "Computing state root");
        let computed_state_root = post_state.tree_hash_root();
        debug!(slot = slot_u64, ?computed_state_root, "State root computed");

        // Create final block with state root
        let final_block = LeanBlock {
            state_root: computed_state_root,
            ..block
        };

        let block_root = final_block.tree_hash_root();
        debug!(
            slot = slot_u64,
            ?block_root,
            ?computed_state_root,
            block_state_root = ?final_block.state_root,
            "Final block created"
        );

        // Create proposer attestation using post_state (after slot processing)
        debug!(
            slot = slot_u64,
            latest_justified_slot = post_state.latest_justified.slot.0,
            latest_finalized_slot = post_state.latest_finalized.slot.0,
            "Creating proposer attestation"
        );

        let proposer_attestation = Attestation {
            validator_id,
            attestation_data: AttestationData {
                slot: lean_slot,
                head: Checkpoint {
                    root: block_root,
                    slot: lean_slot,
                },
                source: post_state.latest_justified.clone(),
                target: post_state.latest_justified.clone(),
            },
        };

        debug!(slot = slot_u64, ?block_root, "Proposer attestation created");

        // For now, create an empty signature list
        // In a full implementation, we would sign the block and add signatures
        let signatures = VariableList::<Signature, E::ValidatorRegistryLimit>::empty();

        // Create signed block
        let signed_block = Arc::new(SignedLeanBlockWithAttestation {
            message: LeanBlockWithAttestation {
                block: final_block,
                proposer_attestation,
            },
            signature: signatures,
        });

        info!(
            slot = slot_u64,
            proposer_index = validator_id,
            ?block_root,
            state_root = ?computed_state_root,
            parent_root = ?parent_root,
            "Produced block"
        );

        // Cache post-state and save block
        // This is critical - we must cache the post-state so when we receive this block
        // back from the network or process it later, we have the correct state
        // IMPORTANT: Update latest_block_header.state_root to the computed state_root
        // so that when this state is loaded later, the header's tree_hash will match the block_root
        post_state.latest_block_header.state_root = computed_state_root;

        debug!(
            slot = slot_u64,
            ?block_root,
            post_state_slot = post_state.slot.0,
            "Saving post-state to cache"
        );
        self.chain.save_state(block_root, &post_state)?;
        debug!(
            slot = slot_u64,
            ?block_root,
            "Post-state saved, now saving block"
        );
        self.chain
            .save_block(block_root, &signed_block.message.block)?;

        debug!(
            ?block_root,
            post_state_slot = post_state.slot.0,
            "Cached post-state and saved block after production"
        );

        // Register the locally-produced block in proto-array so it becomes the new head
        // This is critical! Without this, subsequent blocks will use the wrong parent_root
        self.chain.register_block(
            block_root,
            signed_block.message.block.slot,
            signed_block.message.block.parent_root,
        )?;

        debug!(
            ?block_root,
            "Registered locally-produced block in proto-array"
        );

        // Publish block to network
        debug!(slot = slot_u64, ?block_root, "Sending block to network");
        if let Err(e) = self.network_send.send(NetworkMessage::Block(signed_block)) {
            error!(
                slot = slot_u64,
                ?block_root,
                "Failed to send block to network: {}",
                e
            );
            return Err(format!("Failed to send block to network: {}", e));
        }

        debug!(
            slot = slot_u64,
            ?block_root,
            "=== BLOCK PRODUCTION COMPLETE ==="
        );
        Ok(())
    }

    /// Performs attestation duties for validators assigned to this node.
    ///
    /// The current lean client maps `--node-id` to a contiguous range of validator
    /// indices. Only those validators are expected to produce attestations via this
    /// service.
    async fn perform_attestation_duties(&self, slot: u64) -> Result<(), String> {
        debug!(
            slot,
            validator_id = self.validator_index,
            "Performing attestation duties for assigned validator"
        );

        if let Err(e) = self.produce_attestation(slot, self.validator_index).await {
            warn!(
                slot,
                validator_id = self.validator_index,
                error = %e,
                "Failed to produce attestation for validator"
            );
        }

        Ok(())
    }

    /// Produces an attestation for the given slot and validator
    ///
    /// This method constructs an Attestation object according to the lean protocol
    /// specification. The attestation represents the validator's view of the chain
    /// state and their choice for the next justified checkpoint.
    ///
    /// Algorithm:
    /// 1. Get the current head from forkchoice (or state if forkchoice not available)
    /// 2. Calculate the appropriate attestation target using forkchoice state
    /// 3. Use the latest justified checkpoint as the attestation source
    /// 4. Construct and publish the complete Attestation object
    async fn produce_attestation(&self, slot: u64, validator_id: u64) -> Result<(), String> {
        debug!(slot, validator_id, "Producing attestation");

        // Fetch current head state from cache
        let state = self
            .chain
            .get_head_state()
            .ok_or_else(|| "No lean_state available in cache to produce attestation".to_string())?;

        // Get head root from forkchoice (stored head) or fallback to state
        let head_root = self
            .chain
            .fetch_head_root()?
            .unwrap_or_else(|| state.latest_block_header.tree_hash_root());

        // Get head block to determine head slot
        let head_block = self
            .chain
            .fetch_block(head_root)?
            .ok_or_else(|| format!("Head block not found in database: {:?}", head_root))?;

        // Create head checkpoint
        let head = Checkpoint {
            slot: head_block.slot,
            root: head_root,
        };

        // Get source checkpoint (latest justified)
        let source = state.latest_justified.clone();

        // Calculate attestation target using forkchoice state
        // This implements the get_attestation_target logic from the spec
        let target = self.get_attestation_target(&state, &head_root, &head_block)?;

        // Store checkpoint slots and roots for logging before moving values
        let head_slot = head.slot.0;
        let target_slot = target.slot.0;
        let source_slot = source.slot.0;
        let head_root_dbg = head.root;
        let target_root_dbg = target.root;
        let source_root_dbg = source.root;

        // Create attestation data
        let attestation_data = AttestationData {
            slot: LeanSlot(slot),
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
            head_slot,
            target_slot,
            source_slot,
            ?head_root_dbg,
            ?target_root_dbg,
            ?source_root_dbg,
            latest_justified_slot = state.latest_justified.slot.0,
            latest_justified_root = ?state.latest_justified.root,
            historical_hashes_len = state.historical_block_hashes.len(),
            "Produced attestation"
        );

        // Sign attestation with XMSS key
        let epoch = slot / 32;
        let signature = self
            .sign_attestation(validator_id, &attestation, epoch)
            .map_err(|e| format!("Failed to sign attestation: {}", e))?;

        // Create signed attestation
        let signed_attestation = Arc::new(SignedAttestation {
            message: attestation,
            signature,
        });

        // Publish signed attestation to network
        if let Err(e) = self
            .network_send
            .send(NetworkMessage::Attestation(signed_attestation))
        {
            error!(
                slot,
                validator_id, "Failed to send attestation to network: {}", e
            );
            return Err(format!("Failed to send attestation to network: {}", e));
        }

        Ok(())
    }

    /// Calculate target checkpoint for validator attestations
    ///
    /// Determines appropriate attestation target based on head, safe target,
    /// and finalization constraints. The target selection algorithm balances
    /// between advancing the chain head and maintaining safety guarantees.
    ///
    /// Attestation Target Algorithm:
    /// 1. Start at Head: Begin with the current head block
    /// 2. Walk Toward Safe: Move backward (up to JUSTIFICATION_LOOKBACK_SLOTS steps)
    ///    if safe target is newer
    /// 3. Ensure Justifiable: Continue walking back until slot is justifiable
    /// 4. Return Checkpoint: Create checkpoint from selected block
    fn get_attestation_target(
        &self,
        state: &LeanState<E>,
        head_root: &Hash256,
        head_block: &LeanBlock<E>,
    ) -> Result<Checkpoint, String> {
        // Start from current head
        let mut target_block_root = *head_root;
        let mut target_block = head_block.clone();

        // Get safe target from database (if available)
        let safe_target_root = self.chain.fetch_safe_target()?;
        let justification_lookback_slots = JUSTIFICATION_LOOKBACK_SLOTS;

        // Walk back toward safe target (up to JUSTIFICATION_LOOKBACK_SLOTS steps)
        // if safe target exists and is newer than current target
        if let Some(safe_target) = safe_target_root {
            // Check if safe target is newer than current head
            if let Ok(Some(safe_target_block)) = self.chain.fetch_block(safe_target) {
                if safe_target_block.slot > target_block.slot {
                    // Walk back toward safe target (up to JUSTIFICATION_LOOKBACK_SLOTS steps)
                    let mut steps = 0;
                    while steps < justification_lookback_slots
                        && target_block.slot > safe_target_block.slot
                        && target_block.parent_root != Hash256::ZERO
                    {
                        target_block_root = target_block.parent_root;
                        target_block =
                            self.chain.fetch_block(target_block_root)?.ok_or_else(|| {
                                format!(
                                    "Parent block not found while walking toward safe target: {:?}",
                                    target_block_root
                                )
                            })?;
                        steps += 1;
                    }
                }
            }
        }

        // Ensure target is in justifiable slot range
        // Walk back until we find a slot that satisfies justifiability rules
        // relative to the latest finalized checkpoint
        let finalized_slot = state.latest_finalized.slot;
        let mut steps = 0;
        const MAX_STEPS: u64 = 100; // Safety limit to prevent infinite loops

        while steps < MAX_STEPS {
            // Check if current target slot is justifiable
            match target_block.slot.is_justifiable_after(finalized_slot) {
                Ok(()) => {
                    // Slot is justifiable, use this as target
                    if steps > 0 {
                        debug!(
                            initial_head_slot = head_block.slot.0,
                            selected_target_slot = target_block.slot.0,
                            walked_back_steps = steps,
                            finalized_slot = finalized_slot.0,
                            "Target selection: walked back to find justifiable slot"
                        );
                    }
                    break;
                }
                Err(e) => {
                    // Slot is not justifiable, walk back to parent
                    debug!(
                        current_slot = target_block.slot.0,
                        finalized_slot = finalized_slot.0,
                        steps = steps,
                        error = ?e,
                        "Target selection: slot not justifiable, walking back"
                    );

                    if target_block.parent_root == Hash256::ZERO {
                        // Reached genesis, use current block
                        debug!("Target selection: reached genesis block");
                        break;
                    }

                    // Update root to parent before fetching
                    target_block_root = target_block.parent_root;

                    // Fetch parent block
                    target_block = self.chain.fetch_block(target_block_root)?.ok_or_else(|| {
                        format!(
                            "Parent block not found while walking back: {:?}",
                            target_block_root
                        )
                    })?;
                    steps += 1;
                }
            }
        }

        if steps >= MAX_STEPS {
            return Err("Exceeded maximum steps while finding justifiable target".to_string());
        }

        // Create checkpoint from selected target block
        // Use the root we've been tracking, which corresponds to target_block
        Ok(Checkpoint {
            root: target_block_root,
            slot: target_block.slot,
        })
    }
}
