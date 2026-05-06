use std::{sync::Arc, time::Duration};

use fork_choice::PayloadStatus;
use proto_array::{ProposerHeadError, ReOrgThreshold};
use slot_clock::SlotClock;
use tracing::{debug, error, info, instrument, warn};
use types::{BeaconState, Epoch, Hash256, SignedExecutionPayloadEnvelope, Slot};

use crate::{
    BeaconChain, BeaconChainTypes, BlockProductionError, StateSkipConfig,
    fork_choice_signal::ForkChoiceWaitResult, metrics,
};

mod gloas;

/// State loaded from the database for block production.
pub(crate) struct BlockProductionState<E: types::EthSpec> {
    pub state: BeaconState<E>,
    pub state_root: Option<Hash256>,
    pub parent_payload_status: PayloadStatus,
    pub parent_envelope: Option<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Load a beacon state from the database for block production. This is a long-running process
    /// that should not be performed in an `async` context.
    ///
    /// The returned `PayloadStatus` is the payload status of the parent block to be built upon.
    #[instrument(skip_all, level = "debug")]
    pub(crate) fn load_state_for_block_production(
        self: &Arc<Self>,
        slot: Slot,
    ) -> Result<BlockProductionState<T::EthSpec>, BlockProductionError> {
        let fork_choice_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_FORK_CHOICE_TIMES);
        self.wait_for_fork_choice_before_block_production(slot)?;
        drop(fork_choice_timer);

        let state_load_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_LOAD_TIMES);

        // Atomically read some values from the head whilst avoiding holding cached head `Arc` any
        // longer than necessary. If the head has a payload envelope (Gloas full head), cheaply
        // clone the `Arc` so we can pass it to block production without a DB load.
        let (head_slot, head_block_root, head_state_root, head_payload_status, head_envelope) = {
            let head = self.canonical_head.cached_head();
            (
                head.head_slot(),
                head.head_block_root(),
                head.head_state_root(),
                head.head_payload_status(),
                head.snapshot.execution_envelope.clone(),
            )
        };
        let result = if head_slot < slot {
            // Attempt an aggressive re-org if configured and the conditions are right.
            // TODO(gloas): re-enable reorgs
            let gloas_enabled = self
                .spec
                .fork_name_at_slot::<T::EthSpec>(slot)
                .gloas_enabled();
            if !gloas_enabled
                && let Some((re_org_state, re_org_state_root)) =
                    self.get_state_for_re_org(slot, head_slot, head_block_root)
            {
                info!(
                    %slot,
                    head_to_reorg = %head_block_root,
                    "Proposing block to re-org current head"
                );
                // TODO(gloas): ensure we use a sensible payload status when we enable reorgs
                // for Gloas
                BlockProductionState {
                    state: re_org_state,
                    state_root: Some(re_org_state_root),
                    parent_payload_status: PayloadStatus::Pending,
                    parent_envelope: None,
                }
            } else {
                // Fetch the head state advanced through to `slot`, which should be present in the
                // state cache thanks to the state advance timer.
                let parent_state_root = head_state_root;
                let (state_root, state) = self
                    .store
                    .get_advanced_hot_state(head_block_root, slot, parent_state_root)
                    .map_err(BlockProductionError::FailedToLoadState)?
                    .ok_or(BlockProductionError::UnableToProduceAtSlot(slot))?;
                BlockProductionState {
                    state,
                    state_root: Some(state_root),
                    parent_payload_status: head_payload_status,
                    parent_envelope: head_envelope,
                }
            }
        } else {
            warn!(
                message = "this block is more likely to be orphaned",
                %slot,
                "Producing block that conflicts with head"
            );
            let state = self
                .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
                .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

            // TODO(gloas): update this to read payload canonicity from fork choice once ready
            let parent_payload_status = PayloadStatus::Pending;
            BlockProductionState {
                state,
                state_root: None,
                parent_payload_status,
                parent_envelope: None,
            }
        };

        drop(state_load_timer);

        Ok(result)
    }

    /// If configured, wait for the fork choice run at the start of the slot to complete.
    #[instrument(level = "debug", skip_all)]
    fn wait_for_fork_choice_before_block_production(
        self: &Arc<Self>,
        slot: Slot,
    ) -> Result<(), BlockProductionError> {
        if let Some(rx) = &self.fork_choice_signal_rx {
            let current_slot = self
                .slot()
                .map_err(|_| BlockProductionError::UnableToReadSlot)?;

            let timeout = Duration::from_millis(self.config.fork_choice_before_proposal_timeout_ms);

            if slot == current_slot || slot == current_slot + 1 {
                match rx.wait_for_fork_choice(slot, timeout) {
                    ForkChoiceWaitResult::Success(fc_slot) => {
                        debug!(
                            %slot,
                            fork_choice_slot = %fc_slot,
                            "Fork choice successfully updated before block production"
                        );
                    }
                    ForkChoiceWaitResult::Behind(fc_slot) => {
                        warn!(
                            fork_choice_slot = %fc_slot,
                            %slot,
                            message = "this block may be orphaned",
                            "Fork choice notifier out of sync with block production"
                        );
                    }
                    ForkChoiceWaitResult::TimeOut => {
                        warn!(
                            message = "this block may be orphaned",
                            "Timed out waiting for fork choice before proposal"
                        );
                    }
                }
            } else {
                error!(
                    %slot,
                    %current_slot,
                    message = "check clock sync, this block may be orphaned",
                    "Producing block at incorrect slot"
                );
            }
        }
        Ok(())
    }

    /// Fetch the beacon state to use for producing a block if a 1-slot proposer re-org is viable.
    ///
    /// This function will return `None` if proposer re-orgs are disabled.
    #[instrument(skip_all, level = "debug")]
    fn get_state_for_re_org(
        &self,
        slot: Slot,
        head_slot: Slot,
        canonical_head: Hash256,
    ) -> Option<(BeaconState<T::EthSpec>, Hash256)> {
        let re_org_head_threshold = ReOrgThreshold(self.spec.reorg_head_weight_threshold);
        let re_org_parent_threshold = ReOrgThreshold(self.spec.reorg_parent_weight_threshold);
        let re_org_max_epochs_since_finalization =
            Epoch::new(self.spec.reorg_max_epochs_since_finalization);

        if self.spec.proposer_score_boost.is_none() {
            warn!(
                reason = "this network does not have proposer boost enabled",
                "Ignoring proposer re-org configuration"
            );
            return None;
        }

        let slot_delay = self
            .slot_clock
            .seconds_from_current_slot_start()
            .or_else(|| {
                warn!(error = "unable to read slot clock", "Not attempting re-org");
                None
            })?;

        // Attempt a proposer re-org if:
        //
        // 1. It seems we have time to propagate and still receive the proposer boost.
        // 2. The current head block was seen late.
        // 3. The `get_proposer_head` conditions from fork choice pass.
        let re_org_cutoff_duration = self
            .spec
            .compute_slot_component_duration(self.spec.proposer_reorg_cutoff_bps)
            .ok()?;

        let proposing_on_time = slot_delay < re_org_cutoff_duration;
        if !proposing_on_time {
            debug!(reason = "not proposing on time", "Not attempting re-org");
            return None;
        }

        let head_late = self.block_observed_after_attestation_deadline(canonical_head, head_slot);
        if !head_late {
            debug!(reason = "head not late", "Not attempting re-org");
            return None;
        }

        // Is the current head weak and appropriate for re-orging?
        let proposer_head_timer =
            metrics::start_timer(&metrics::BLOCK_PRODUCTION_GET_PROPOSER_HEAD_TIMES);
        let proposer_head = self
            .canonical_head
            .fork_choice_read_lock()
            .get_proposer_head(
                slot,
                canonical_head,
                re_org_head_threshold,
                re_org_parent_threshold,
                &self.config.re_org_disallowed_offsets,
                re_org_max_epochs_since_finalization,
            )
            .map_err(|e| match e {
                ProposerHeadError::DoNotReOrg(reason) => {
                    debug!(
                        %reason,
                        "Not attempting re-org"
                    );
                }
                ProposerHeadError::Error(e) => {
                    warn!(
                        error = ?e,
                        "Not attempting re-org"
                    );
                }
            })
            .ok()?;
        drop(proposer_head_timer);
        let re_org_parent_block = proposer_head.parent_node.root();

        let (state_root, state) = self
            .store
            .get_advanced_hot_state_from_cache(re_org_parent_block, slot)
            .or_else(|| {
                warn!(reason = "no state in cache", "Not attempting re-org");
                None
            })?;

        info!(
            weak_head = ?canonical_head,
            parent = ?re_org_parent_block,
            head_weight = proposer_head.head_node.weight(),
            threshold_weight = proposer_head.re_org_head_weight_threshold,
            "Attempting re-org due to weak head"
        );

        Some((state, state_root))
    }
}
