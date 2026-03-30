use std::{sync::Arc, time::Duration};

use proto_array::ProposerHeadError;
use slot_clock::SlotClock;
use tracing::{debug, error, info, instrument, warn};
use types::{BeaconState, Hash256, Slot, StatePayloadStatus};

use crate::{
    BeaconChain, BeaconChainTypes, BlockProductionError, StateSkipConfig,
    fork_choice_signal::ForkChoiceWaitResult, metrics,
};

mod gloas;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Load a beacon state from the database for block production. This is a long-running process
    /// that should not be performed in an `async` context.
    #[instrument(skip_all, level = "debug")]
    pub(crate) fn load_state_for_block_production(
        self: &Arc<Self>,
        slot: Slot,
    ) -> Result<(BeaconState<T::EthSpec>, Option<Hash256>), BlockProductionError> {
        let fork_choice_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_FORK_CHOICE_TIMES);
        self.wait_for_fork_choice_before_block_production(slot)?;
        drop(fork_choice_timer);

        let state_load_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_LOAD_TIMES);

        // Atomically read some values from the head whilst avoiding holding cached head `Arc` any
        // longer than necessary.
        let (head_slot, head_block_root, head_state_root) = {
            let head = self.canonical_head.cached_head();
            (
                head.head_slot(),
                head.head_block_root(),
                head.head_state_root(),
            )
        };
        let (state, state_root_opt) = if head_slot < slot {
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
                (re_org_state, Some(re_org_state_root))
            } else {
                // Fetch the head state advanced through to `slot`, which should be present in the
                // state cache thanks to the state advance timer.
                // TODO(gloas): need to fix this once fork choice understands payloads
                // for now we just use the existence of the head's payload envelope to determine
                // whether we should build atop it
                let (payload_status, parent_state_root) = if gloas_enabled
                    && let Ok(Some(envelope)) = self.store.get_payload_envelope(&head_block_root)
                {
                    debug!(
                        %slot,
                        parent_state_root = ?envelope.message.state_root,
                        parent_block_root = ?head_block_root,
                        "Building Gloas block on full state"
                    );
                    (StatePayloadStatus::Full, envelope.message.state_root)
                } else {
                    (StatePayloadStatus::Pending, head_state_root)
                };
                let (state_root, state) = self
                    .store
                    .get_advanced_hot_state(
                        head_block_root,
                        payload_status,
                        slot,
                        parent_state_root,
                    )
                    .map_err(BlockProductionError::FailedToLoadState)?
                    .ok_or(BlockProductionError::UnableToProduceAtSlot(slot))?;
                (state, Some(state_root))
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

            (state, None)
        };

        drop(state_load_timer);

        Ok((state, state_root_opt))
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
        let re_org_head_threshold = self.config.re_org_head_threshold?;
        let re_org_parent_threshold = self.config.re_org_parent_threshold?;

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
        let proposing_on_time =
            slot_delay < self.config.re_org_cutoff(self.spec.get_slot_duration());
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
                self.config.re_org_max_epochs_since_finalization,
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
        let re_org_parent_block = proposer_head.parent_node.root;

        let (state_root, state) = self
            .store
            .get_advanced_hot_state_from_cache(
                re_org_parent_block,
                StatePayloadStatus::Pending,
                slot,
            )
            .or_else(|| {
                warn!(reason = "no state in cache", "Not attempting re-org");
                None
            })?;

        info!(
            weak_head = ?canonical_head,
            parent = ?re_org_parent_block,
            head_weight = proposer_head.head_node.weight,
            threshold_weight = proposer_head.re_org_head_weight_threshold,
            "Attempting re-org due to weak head"
        );

        Some((state, state_root))
    }
}
