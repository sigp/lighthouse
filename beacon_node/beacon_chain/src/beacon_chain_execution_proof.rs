use crate::errors::BeaconChainError as Error;
use crate::{BeaconChain, BeaconChainTypes};
use tracing::{debug, info, warn};
use types::{EthSpec, ExecPayload, ExecutionBlockHash, ExecutionProof, Hash256, Slot};

// Execution Proof Management for BeaconChain
//
// This module contains all execution proof-related functionality for the
// BeaconChain, if we follow the current code structure, this would belong in
// beacon_chain.rs. It has been pulled into this separate file to make the diff
// easier to manage.
//
impl<T: BeaconChainTypes> BeaconChain<T> {
    // ========================================================================
    // Subnet Management
    // ========================================================================

    /// Determine which execution proof subnets this node should subscribe to.
    ///
    /// Currently uses a simple sequential allocation: if max_execution_proof_subnets is N,
    /// this node will subscribe to subnets [0, 1, 2, ..., N-1].
    ///
    /// Examples:
    /// - max_execution_proof_subnets = 8: subscribes to subnets [0, 1, 2, 3, 4, 5, 6, 7]
    /// - max_execution_proof_subnets = 4: subscribes to subnets [0, 1, 2, 3]
    /// - max_execution_proof_subnets = 1: subscribes to subnet [0] only
    ///
    /// In the future, this could be made more sophisticated to support:
    /// - Random assignment for better distribution
    /// - Validator-based assignment for specific responsibilities
    /// - Dynamic reassignment based on network conditions
    pub fn execution_proof_subnets(&self) -> Vec<u64> {
        (0..self.config.max_execution_proof_subnets).collect()
    }

    /// Get the maximum number of execution proof subnets for this configuration
    pub fn max_execution_proof_subnets(&self) -> u64 {
        self.config.max_execution_proof_subnets
    }

    /// Check if this node should generate execution proofs for the given subnet
    /// Returns true if the subnet is within our configured range
    pub fn should_generate_execution_proof_for_subnet(&self, subnet_id: u64) -> bool {
        // For now, we generate proofs for all subnets we're subscribed to
        // In the future, this could be more sophisticated based on:
        // - Validator duties and responsibilities
        // - Network load balancing
        // - Hardware capabilities
        if self.config.stateless_validation {
            subnet_id < self.config.max_execution_proof_subnets
        } else {
            false
        }
    }

    // ========================================================================
    // Proof Validation and Chain Updates
    // ========================================================================

    /// Re-evaluate optimistic blocks that can now be validated with received proofs
    /// This method is called when new execution proofs arrive via gossip
    /// In the dual-view architecture, this updates the proven chain but does NOT
    /// modify fork choice weights
    pub fn re_evaluate_optimistic_blocks_with_proofs(
        &self,
        execution_block_hash: ExecutionBlockHash,
    ) -> Result<bool, Error> {
        // Only perform re-evaluation if stateless validation is enabled
        if !self.config.stateless_validation {
            return Ok(false);
        }

        // Get the proofs we have for this execution block hash
        let available_proofs = self
            .execution_payload_proof_store
            .get_proofs(&execution_block_hash);
        let proof_count = available_proofs.len();

        // Check if we have enough valid proofs
        if proof_count < self.config.stateless_min_proofs_required {
            self.log_insufficient_proofs(&execution_block_hash, &available_proofs, proof_count);
            return Ok(false);
        }

        debug!(
            "PROOFCHAIN {}: minimum proofs reached ({}/{}), updating proven chain",
            execution_block_hash, proof_count, self.config.stateless_min_proofs_required
        );

        // Get current chain state
        let head = self.canonical_head.cached_head();
        let head_block_root = head.head_block_root();
        let head_slot = head.head_slot();
        let current_slot = self.slot().unwrap_or(Slot::new(0));
        let slots_per_epoch = T::EthSpec::slots_per_epoch();

        // Update the proven canonical chain based on available proofs
        // This does NOT modify fork choice - validators continue with optimistic view
        let proven_status = self
            .execution_payload_proof_store
            .update_proven_chain(
                |block_root| {
                    self.get_blinded_block(block_root).map(|result| {
                        result.map(|block| {
                            let slot = block.slot();
                            let parent_root = block.parent_root();
                            let exec_hash_opt = block
                                .message()
                                .execution_payload()
                                .ok()
                                .map(|payload| payload.block_hash());
                            (slot, parent_root, exec_hash_opt)
                        })
                    })
                },
                head_block_root,
                current_slot,
                slots_per_epoch,
                self.config.stateless_min_proofs_required,
            )
            .map_err(Error::ExecutionProofError)?;

        // Log proven chain status
        self.log_proven_chain_status(&proven_status, head_slot, slots_per_epoch);

        // Remove pending blocks that now have sufficient proofs
        let proven_blocks = self
            .execution_payload_proof_store
            .take_pending_blocks(&execution_block_hash);
        // Note: That if we were to modify fork choice, it would likely be here, where we know what set of
        // beacon blocks have valid execution payloads.

        if !proven_blocks.is_empty() {
            debug!(
                %execution_block_hash,
                proven_count = proven_blocks.len(),
                "Removed pending blocks that now have sufficient proofs"
            );
        }

        // Perform periodic cleanup of finalized pending blocks
        if proven_status.head_changed {
            // TODO: Revisit, if this is still needed
            let _cleaned_count = self.cleanup_finalized_pending_blocks();
        }

        // Return false - we never trigger head recomputation in dual-view mode
        // Fork choice remains permanently optimistic
        Ok(false)
    }

    /// Register a beacon block as pending execution proof validation
    /// This is called when a block is imported optimistically in stateless validation mode
    pub fn register_optimistic_block_for_proof(
        &self,
        beacon_block_root: Hash256,
        execution_block_hash: ExecutionBlockHash,
    ) {
        if self.config.stateless_validation {
            self.execution_payload_proof_store
                .register_pending_block(execution_block_hash, beacon_block_root);

            info!(
                %beacon_block_root,
                %execution_block_hash,
                "STATELESS: Registered optimistic block as PENDING execution proof validation"
            );
            info!(
                "STATELESS_TRACE: Block registered - beacon_root: {:?}, exec_hash: {:?} -> PENDING proof",
                beacon_block_root,
                execution_block_hash
            );
        }
    }

    // ========================================================================
    // Cleanup Operations
    // ========================================================================

    /// Clean up pending blocks that have been finalized or are too old
    /// This should be called periodically to prevent memory leaks in the proof store
    pub fn cleanup_finalized_pending_blocks(&self) -> usize {
        if !self.config.stateless_validation {
            return 0;
        }

        let finalized_slot = self
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // Remove pending blocks that are older than finalized slot
        let removed_count =
            self.execution_payload_proof_store
                .cleanup_pending_blocks(|block_root| {
                    // Check if this block is older than finalized slot
                    // We need to look up the block to get its slot
                    if let Ok(Some(block)) = self.get_blinded_block(&block_root) {
                        block.slot() <= finalized_slot
                    } else {
                        // If we can't find the block, it's likely been pruned, so remove it
                        true
                    }
                });

        if removed_count > 0 {
            debug!(
                finalized_slot = %finalized_slot,
                removed_count,
                "Cleaned up finalized pending blocks from proof store"
            );
        }

        removed_count
    }


    // ========================================================================
    // Logging and Monitoring
    // ========================================================================

    /// Log insufficient proofs for an execution block hash
    fn log_insufficient_proofs(
        &self,
        execution_block_hash: &ExecutionBlockHash,
        available_proofs: &[ExecutionProof],
        proof_count: usize,
    ) {
        let proof_details: Vec<String> = available_proofs
            .iter()
            .map(|p| format!("{} on subnet {}", p.description(), *p.subnet_id))
            .collect();

        debug!(
            "PROOFCHAIN {}: {}. Proofs: {}/{} required",
            execution_block_hash,
            proof_details.join(", "),
            proof_count,
            self.config.stateless_min_proofs_required
        );
    }

    /// Log proven chain status and detailed summary
    fn log_proven_chain_status(
        &self,
        proven_status: &crate::execution_payload_proofs::ProvenChainStatus,
        head_slot: Slot,
        slots_per_epoch: u64,
    ) {
        if let Some((_proven_root, proven_slot)) = proven_status.proven_head {
            if proven_status.head_changed {
                info!(
                    "PROOFCHAIN STATUS: Proven slot {} | Optimistic slot {} | Lag {} slots | Status: {}",
                    proven_slot.as_u64(),
                    head_slot.as_u64(),
                    head_slot.saturating_sub(proven_slot).as_u64(),
                    if head_slot == proven_slot { "Fully proven" } else { "Catching up" }
                );

                self.log_proven_chain_summary(proven_status, head_slot, slots_per_epoch);
            }
        } else {
            warn!("PROOFCHAIN: no proven head found - no blocks have sufficient proofs");
        }
    }

    /// Log detailed proven chain summary
    fn log_proven_chain_summary(
        &self,
        proven_status: &crate::execution_payload_proofs::ProvenChainStatus,
        head_slot: Slot,
        slots_per_epoch: u64,
    ) {
        let Some((_, proven_slot)) = proven_status.proven_head else {
            return;
        };

        let head = self.canonical_head.cached_head();
        let finalized_checkpoint = head.finalized_checkpoint();
        let finalized_slot = finalized_checkpoint.epoch.start_slot(slots_per_epoch);

        info!("PROOFCHAIN SUMMARY:");
        info!(
            "  Proven head: slot {} (epoch {})",
            proven_slot.as_u64(),
            proven_slot.epoch(slots_per_epoch).as_u64()
        );
        info!(
            "  Proven chain depth: {} blocks",
            proven_status.proven_chain_depth
        );
        info!(
            "  Optimistic head: slot {} (epoch {})",
            head_slot.as_u64(),
            head_slot.epoch(slots_per_epoch).as_u64()
        );
        info!(
            "  Regular finalized: slot {} (epoch {})",
            finalized_slot.as_u64(),
            finalized_checkpoint.epoch.as_u64()
        );

        if let Some((pf_root, pf_slot)) = proven_status.proven_finalized {
            info!(
                "  Proven finalized: slot {} (epoch {})",
                pf_slot.as_u64(),
                pf_slot.epoch(slots_per_epoch).as_u64()
            );
            info!(
                "PROOFCHAIN FINALIZED: block {:?} at slot {} (epoch {})",
                pf_root,
                pf_slot.as_u64(),
                pf_slot.epoch(slots_per_epoch).as_u64()
            );
        } else {
            info!("  Proven finalized: none");
        }

        info!(
            "  Proof generation lag: {} slots",
            head_slot.saturating_sub(proven_slot).as_u64()
        );
        info!(
            "  Min proofs required: {}",
            self.config.stateless_min_proofs_required
        );
    }
}
