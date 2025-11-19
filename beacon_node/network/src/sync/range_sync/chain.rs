use super::RangeSyncType;
use crate::metrics;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::batch::BatchId;
use crate::sync::batch::{
    BatchConfig, BatchInfo, BatchOperationOutcome, BatchProcessingResult, BatchState,
};
use crate::sync::block_sidecar_coupling::CouplingError;
use crate::sync::network_context::{RangeRequestId, RpcRequestSendError, RpcResponseError};
use crate::sync::{BatchProcessResult, network_context::SyncNetworkContext};
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::RpcBlock;
use lighthouse_network::service::api_types::Id;
use lighthouse_network::{PeerAction, PeerId};
use lighthouse_tracing::SPAN_SYNCING_CHAIN;
use logging::crit;
use std::collections::{BTreeMap, HashSet, btree_map::Entry};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use strum::IntoStaticStr;
use tracing::{Span, debug, instrument, warn};
use types::{ColumnIndex, Epoch, EthSpec, Hash256, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many epochs worth of
/// blocks per batch are requested _at most_. A batch may request less blocks to account for
/// already requested slots. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which
/// case the responder will fill the response up to the max request size, assuming they have the
/// bandwidth to do so.
pub const EPOCHS_PER_BATCH: u64 = 1;

/// The maximum number of batches to queue before requesting more.
const BATCH_BUFFER_SIZE: u8 = 5;

/// A return type for functions that act on a `Chain` which informs the caller whether the chain
/// has been completed and should be removed or to be kept if further processing is
/// required.
///
/// Should be checked, since a failed chain must be removed. A chain that requested being removed
/// and continued is now in an inconsistent state.
pub type ProcessingResult = Result<KeepChain, RemoveChain>;

type RpcBlocks<E> = Vec<RpcBlock<E>>;
type RangeSyncBatchInfo<E> = BatchInfo<E, RangeSyncBatchConfig<E>, RpcBlocks<E>>;
type RangeSyncBatches<E> = BTreeMap<BatchId, RangeSyncBatchInfo<E>>;

/// The number of times to retry a batch before it is considered failed.
const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 5;

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 3;

pub struct RangeSyncBatchConfig<E: EthSpec> {
    marker: PhantomData<E>,
}

impl<E: EthSpec> BatchConfig for RangeSyncBatchConfig<E> {
    fn max_batch_download_attempts() -> u8 {
        MAX_BATCH_DOWNLOAD_ATTEMPTS
    }
    fn max_batch_processing_attempts() -> u8 {
        MAX_BATCH_PROCESSING_ATTEMPTS
    }
    fn batch_attempt_hash<D: Hash>(data: &D) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }
}

/// Reasons for removing a chain
#[derive(Debug)]
#[allow(dead_code)]
pub enum RemoveChain {
    EmptyPeerPool,
    ChainCompleted,
    /// A chain has failed. This boolean signals whether the chain should be blacklisted.
    ChainFailed {
        blacklist: bool,
        failing_batch: BatchId,
    },
    WrongBatchState(String),
    WrongChainState(String),
}

#[derive(Debug)]
pub struct KeepChain;

/// A chain identifier
pub type ChainId = Id;

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum SyncingChainType {
    Head,
    Finalized,
    Backfill,
}

/// A chain of blocks that need to be downloaded. Peers who claim to contain the target head
/// root are grouped into the peer pool and queried for batches when downloading the
/// chain.
#[derive(Debug)]
pub struct SyncingChain<T: BeaconChainTypes> {
    /// A random id used to identify this chain.
    id: ChainId,

    /// SyncingChain type
    pub chain_type: SyncingChainType,

    /// The start of the chain segment. Any epoch previous to this one has been validated.
    pub start_epoch: Epoch,

    /// The target head slot.
    pub target_head_slot: Slot,

    /// The target head root.
    pub target_head_root: Hash256,

    /// Sorted map of batches undergoing some kind of processing.
    batches: RangeSyncBatches<T::EthSpec>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from, as well as the batches we are currently
    /// requesting.
    peers: HashSet<PeerId>,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: BatchId,

    /// Optimistic head to sync.
    /// If a block is imported for this batch, the chain advances to this point.
    optimistic_start: Option<BatchId>,

    /// When a batch for an optimistic start is tried (either successful or not), it is stored to
    /// avoid trying it again due to chain stopping/re-starting on chain switching.
    attempted_optimistic_starts: HashSet<BatchId>,

    /// The current state of the chain.
    pub state: ChainSyncingState,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// The span to track the lifecycle of the syncing chain.
    span: Span,
}

#[derive(PartialEq, Debug)]
pub enum ChainSyncingState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
}

impl<T: BeaconChainTypes> SyncingChain<T> {
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = SPAN_SYNCING_CHAIN,
        parent = None,
        level="debug",
        skip_all,
        fields(
            chain_id = %id,
            start_epoch = %start_epoch,
            target_head_slot = %target_head_slot,
            target_head_root = %target_head_root,
            chain_type = ?chain_type,
        )
    )]
    pub fn new(
        id: Id,
        start_epoch: Epoch,
        target_head_slot: Slot,
        target_head_root: Hash256,
        peer_id: PeerId,
        chain_type: SyncingChainType,
    ) -> Self {
        let span = Span::current();
        SyncingChain {
            id,
            chain_type,
            start_epoch,
            target_head_slot,
            target_head_root,
            batches: BTreeMap::new(),
            peers: HashSet::from_iter([peer_id]),
            to_be_downloaded: start_epoch,
            processing_target: start_epoch,
            optimistic_start: None,
            attempted_optimistic_starts: HashSet::default(),
            state: ChainSyncingState::Stopped,
            current_processing_batch: None,
            span,
        }
    }

    /// Returns true if this chain has the same target
    pub fn has_same_target(&self, target_head_slot: Slot, target_head_root: Hash256) -> bool {
        self.target_head_slot == target_head_slot && self.target_head_root == target_head_root
    }

    /// Check if the chain has peers from which to process batches.
    pub fn available_peers(&self) -> usize {
        self.peers.len()
    }

    /// Get the chain's id.
    pub fn id(&self) -> ChainId {
        self.id
    }

    /// Peers currently syncing this chain.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.iter().cloned()
    }

    /// Progress in epochs made by the chain
    pub fn processed_epochs(&self) -> u64 {
        self.processing_target
            .saturating_sub(self.start_epoch)
            .into()
    }

    /// Returns the total count of pending blocks in all the batches of this chain
    pub fn pending_blocks(&self) -> usize {
        self.batches
            .values()
            .map(|batch| batch.pending_blocks())
            .sum()
    }

    /// Removes a peer from the chain.
    /// If the peer has active batches, those are considered failed and re-requested.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        debug!(peer = %peer_id, "Removing peer from chain");
        self.peers.remove(peer_id);

        if self.peers.is_empty() {
            Err(RemoveChain::EmptyPeerPool)
        } else {
            Ok(KeepChain)
        }
    }

    /// Returns the latest slot number that has been processed.
    fn current_processed_slot(&self) -> Slot {
        // the last slot we processed was included in the previous batch, and corresponds to the
        // first slot of the current target epoch
        self.processing_target
            .start_slot(T::EthSpec::slots_per_epoch())
    }

    /// A block has been received for a batch on this chain.
    /// If the block correctly completes the batch it will be processed if possible.
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: Id,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        // check if we have this batch
        let batch = match self.batches.get_mut(&batch_id) {
            None => {
                debug!(epoch = %batch_id, "Received a block for unknown batch");
                // A batch might get removed when the chain advances, so this is non fatal.
                return Ok(KeepChain);
            }
            Some(batch) => {
                // A batch could be retried without the peer failing the request (disconnecting/
                // sending an error /timeout) if the peer is removed from the chain for other
                // reasons. Check that this block belongs to the expected peer, and that the
                // request_id matches
                // TODO(das): removed peer_id matching as the node may request a different peer for data
                // columns.
                if !batch.is_expecting_request_id(&request_id) {
                    return Ok(KeepChain);
                }
                batch
            }
        };

        // A stream termination has been sent. This batch has ended. Process a completed batch.
        // Remove the request from the peer's active batches

        // TODO(das): should use peer group here https://github.com/sigp/lighthouse/issues/6258
        let received = blocks.len();
        batch.download_completed(blocks, *peer_id)?;
        let awaiting_batches = batch_id
            .saturating_sub(self.optimistic_start.unwrap_or(self.processing_target))
            / EPOCHS_PER_BATCH;
        debug!(
            epoch = %batch_id,
            blocks = received,
            batch_state = self.visualize_batch_state(),
            %awaiting_batches,
            %peer_id,
            "Batch downloaded"
        );

        // pre-emptively request more blocks from peers whilst we process current blocks,
        self.request_batches(network)?;
        self.process_completed_batches(network)
    }

    /// Processes the batch with the given id.
    /// The batch must exist and be ready for processing
    fn process_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        // Only process batches if this chain is Syncing, and only one at a time
        if self.state != ChainSyncingState::Syncing || self.current_processing_batch.is_some() {
            return Ok(KeepChain);
        }

        let Some(beacon_processor) = network.beacon_processor_if_enabled() else {
            return Ok(KeepChain);
        };

        let Some(batch) = self.batches.get_mut(&batch_id) else {
            return Err(RemoveChain::WrongChainState(format!(
                "Trying to process a batch that does not exist: {}",
                batch_id
            )));
        };

        // NOTE: We send empty batches to the processor in order to trigger the block processor
        // result callback. This is done, because an empty batch could end a chain and the logic
        // for removing chains and checking completion is in the callback.

        let (blocks, duration_in_awaiting_processing) = batch.start_processing()?;
        metrics::observe_duration(
            &metrics::SYNCING_CHAIN_BATCH_AWAITING_PROCESSING,
            duration_in_awaiting_processing,
        );

        let process_id = ChainSegmentProcessId::RangeBatchId(self.id, batch_id);
        self.current_processing_batch = Some(batch_id);

        if let Err(e) = beacon_processor.send_chain_segment(process_id, blocks) {
            crit!(msg = "process_batch",error = %e, batch = ?self.processing_target, "Failed to send chain segment to processor.");
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // blocks to continue, and the chain is expecting a processing result that won't
            // arrive.  To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(network, batch_id, &BatchProcessResult::NonFaultyFailure)
        } else {
            Ok(KeepChain)
        }
    }

    /// Processes the next ready batch, prioritizing optimistic batches over the processing target.
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> ProcessingResult {
        // Only process batches if this chain is Syncing and only process one batch at a time
        if self.state != ChainSyncingState::Syncing || self.current_processing_batch.is_some() {
            return Ok(KeepChain);
        }

        // Find the id of the batch we are going to process.
        //
        // First try our optimistic start, if any. If this batch is ready, we process it. If the
        // batch has not already been completed, check the current chain target.
        if let Some(epoch) = self.optimistic_start
            && let Some(batch) = self.batches.get(&epoch)
        {
            let state = batch.state();
            match state {
                BatchState::AwaitingProcessing(..) => {
                    // this batch is ready
                    debug!(%epoch, "Processing optimistic start");
                    return self.process_batch(network, epoch);
                }
                BatchState::Downloading(..) => {
                    // The optimistic batch is being downloaded. We wait for this before
                    // attempting to process other batches.
                    return Ok(KeepChain);
                }
                BatchState::Poisoned => unreachable!("Poisoned batch"),
                // Batches can be in `AwaitingDownload` state if there weren't good data column subnet
                // peers to send the request to.
                BatchState::AwaitingDownload => return Ok(KeepChain),
                BatchState::Processing(_) | BatchState::Failed => {
                    // these are all inconsistent states:
                    // - Processing -> `self.current_processing_batch` is None
                    // - Failed -> non recoverable batch. For an optimistic batch, it should
                    //   have been removed
                    // - AwaitingDownload -> A recoverable failed batch should have been
                    //   re-requested.
                    return Err(RemoveChain::WrongChainState(format!(
                        "Optimistic batch indicates inconsistent chain state: {:?}",
                        state
                    )));
                }
                BatchState::AwaitingValidation(_) => {
                    // If an optimistic start is given to the chain after the corresponding
                    // batch has been requested and processed we can land here. We drop the
                    // optimistic candidate since we can't conclude whether the batch included
                    // blocks or not at this point
                    debug!(batch = %epoch, "Dropping optimistic candidate");
                    self.optimistic_start = None;
                }
            }
        }

        // if the optimistic target can't be processed, check the processing target
        if let Some(batch) = self.batches.get(&self.processing_target) {
            let state = batch.state();
            match state {
                BatchState::AwaitingProcessing(..) => {
                    return self.process_batch(network, self.processing_target);
                }
                BatchState::Downloading(..) => {
                    // Batch is not ready, nothing to process
                }
                BatchState::Poisoned => unreachable!("Poisoned batch"),
                // Batches can be in `AwaitingDownload` state if there weren't good data column subnet
                // peers to send the request to.
                BatchState::AwaitingDownload => return Ok(KeepChain),
                BatchState::Failed | BatchState::Processing(_) => {
                    // these are all inconsistent states:
                    // - Failed -> non recoverable batch. Chain should have been removed
                    // - AwaitingDownload -> A recoverable failed batch should have been
                    //   re-requested.
                    // - Processing -> `self.current_processing_batch` is None
                    return Err(RemoveChain::WrongChainState(format!(
                        "Robust target batch indicates inconsistent chain state: {:?}",
                        state
                    )));
                }
                BatchState::AwaitingValidation(_) => {
                    // we can land here if an empty optimistic batch succeeds processing and is
                    // inside the download buffer (between `self.processing_target` and
                    // `self.to_be_downloaded`). In this case, eventually the chain advances to the
                    // batch (`self.processing_target` reaches this point).
                    debug!(
                        batch = %self.processing_target,
                        "Chain encountered a robust batch awaiting validation"
                    );

                    self.processing_target += EPOCHS_PER_BATCH;
                    if self.to_be_downloaded <= self.processing_target {
                        self.to_be_downloaded = self.processing_target + EPOCHS_PER_BATCH;
                    }
                    self.request_batches(network)?;
                }
            }
        } else if !self.good_peers_on_sampling_subnets(self.processing_target, network) {
            // This is to handle the case where no batch was sent for the current processing
            // target when there is no sampling peers available. This is a valid state and should not
            // return an error.
            return Ok(KeepChain);
        } else {
            // NOTE: It is possible that the batch doesn't exist for the processing id. This can happen
            // when we complete a batch and attempt to download a new batch but there are:
            // 1. No idle peers to download from
            // 2. No good peers on sampling subnets
            //
            // In these cases, a batch will not yet exist.
            debug!(batch = %self.processing_target, "The processing batch has not been scheduled for download yet. Awaiting progress");
        }

        Ok(KeepChain)
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        result: &BatchProcessResult,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        // the first two cases are possible if the chain advances while waiting for a processing
        // result
        let batch_state = self.visualize_batch_state();
        let batch = match &self.current_processing_batch {
            Some(processing_id) if *processing_id != batch_id => {
                debug!(batch_epoch = %batch_id, expected_batch_epoch = %processing_id,"Unexpected batch result");
                return Ok(KeepChain);
            }
            None => {
                debug!(batch_epoch = %batch_id,"Chain was not expecting a batch result");
                return Ok(KeepChain);
            }
            _ => {
                // batch_id matches, continue
                self.current_processing_batch = None;
                self.batches.get_mut(&batch_id).ok_or_else(|| {
                    RemoveChain::WrongChainState(format!(
                        "Current processing batch not found: {}",
                        batch_id
                    ))
                })?
            }
        };

        let peer = batch.processing_peer().cloned().ok_or_else(|| {
            RemoveChain::WrongBatchState(format!(
                "Processing target is in wrong state: {:?}",
                batch.state(),
            ))
        })?;

        // Log the process result and the batch for debugging purposes.
        debug!(
            result = ?result,
            batch_epoch = %batch_id,
            client = %network.client_type(&peer),
            batch_state = ?batch_state,
            ?batch,
            "Batch processing result"
        );

        // We consider three cases. Batch was successfully processed, Batch failed processing due
        // to a faulty peer, or batch failed processing but the peer can't be deemed faulty.
        match result {
            BatchProcessResult::Success {
                sent_blocks,
                imported_blocks,
            } => {
                if sent_blocks > imported_blocks {
                    let ignored_blocks = sent_blocks - imported_blocks;
                    metrics::inc_counter_vec_by(
                        &metrics::SYNCING_CHAINS_IGNORED_BLOCKS,
                        &[self.chain_type.into()],
                        ignored_blocks as u64,
                    );
                }
                metrics::inc_counter_vec(
                    &metrics::SYNCING_CHAINS_PROCESSED_BATCHES,
                    &[self.chain_type.into()],
                );

                batch.processing_completed(BatchProcessingResult::Success)?;

                // was not empty = sent_blocks > 0
                if *sent_blocks > 0 {
                    // If the processed batch was not empty, we can validate previous unvalidated
                    // blocks.
                    self.advance_chain(network, batch_id);
                    // we register so that on chain switching we don't try it again
                    self.attempted_optimistic_starts.insert(batch_id);
                } else if self.optimistic_start == Some(batch_id) {
                    // check if this batch corresponds to an optimistic batch. In this case, we
                    // reject it as an optimistic candidate since the batch was empty
                    self.reject_optimistic_batch(
                        network,
                        false, /* do not re-request */
                        "batch was empty",
                    )?;
                }

                if batch_id == self.processing_target {
                    self.processing_target += EPOCHS_PER_BATCH;
                }

                // check if the chain has completed syncing
                if self.current_processed_slot() >= self.target_head_slot {
                    // chain is completed
                    Err(RemoveChain::ChainCompleted)
                } else {
                    // chain is not completed
                    // attempt to request more batches
                    self.request_batches(network)?;
                    // attempt to process more batches
                    self.process_completed_batches(network)
                }
            }
            BatchProcessResult::FaultyFailure {
                imported_blocks,
                penalty,
            } => {
                // Penalize the peer appropriately.
                network.report_peer(peer, *penalty, "faulty_batch");

                // Check if this batch is allowed to continue
                match batch.processing_completed(BatchProcessingResult::FaultyFailure)? {
                    BatchOperationOutcome::Continue => {
                        // Chain can continue. Check if it can be moved forward.
                        if *imported_blocks > 0 {
                            // At least one block was successfully verified and imported, so we can be sure all
                            // previous batches are valid and we only need to download the current failed
                            // batch.
                            self.advance_chain(network, batch_id);
                        }
                        // Handle this invalid batch, that is within the re-process retries limit.
                        self.handle_invalid_batch(network, batch_id)
                    }
                    BatchOperationOutcome::Failed { blacklist } => {
                        // Check that we have not exceeded the re-process retry counter,
                        // If a batch has exceeded the invalid batch lookup attempts limit, it means
                        // that it is likely all peers in this chain are are sending invalid batches
                        // repeatedly and are either malicious or faulty. We drop the chain and
                        // report all peers.
                        // There are some edge cases with forks that could land us in this situation.
                        // This should be unlikely, so we tolerate these errors, but not often.
                        warn!(
                            score_adjustment = %penalty,
                            batch_epoch = %batch_id,
                            "Batch failed to download. Dropping chain scoring peers"
                        );

                        for peer in self.peers.drain() {
                            network.report_peer(peer, *penalty, "faulty_chain");
                        }
                        Err(RemoveChain::ChainFailed {
                            blacklist,
                            failing_batch: batch_id,
                        })
                    }
                }
            }
            BatchProcessResult::NonFaultyFailure => {
                batch.processing_completed(BatchProcessingResult::NonFaultyFailure)?;

                // Simply re-download all batches in `AwaitingDownload` state.
                self.attempt_send_awaiting_download_batches(network, "non-faulty-failure")
            }
        }
    }

    fn reject_optimistic_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        redownload: bool,
        reason: &str,
    ) -> ProcessingResult {
        if let Some(epoch) = self.optimistic_start.take() {
            self.attempted_optimistic_starts.insert(epoch);
            // if this batch is inside the current processing range, keep it, otherwise drop
            // it. NOTE: this is done to prevent non-sequential batches coming from optimistic
            // starts from filling up the buffer size
            if epoch < self.to_be_downloaded {
                debug!(%epoch, reason, "Rejected optimistic batch left for future use");
                // this batch is now treated as any other batch, and re-requested for future use
                if redownload {
                    return self.send_batch(network, epoch);
                }
            } else {
                debug!(%epoch, reason, "Rejected optimistic batch");
                self.batches.remove(&epoch);
            }
        }

        Ok(KeepChain)
    }

    /// Removes any batches previous to the given `validating_epoch` and updates the current
    /// boundaries of the chain.
    ///
    /// The `validating_epoch` must align with batch boundaries.
    ///
    /// If a previous batch has been validated and it had been re-processed, penalize the original
    /// peer.
    #[allow(clippy::modulo_one)]
    fn advance_chain(&mut self, network: &mut SyncNetworkContext<T>, validating_epoch: Epoch) {
        // make sure this epoch produces an advancement
        if validating_epoch <= self.start_epoch {
            return;
        }

        // safety check for batch boundaries
        if validating_epoch % EPOCHS_PER_BATCH != self.start_epoch % EPOCHS_PER_BATCH {
            crit!("Validating Epoch is not aligned");
            return;
        }

        // batches in the range [BatchId, ..) (not yet validated)
        let remaining_batches = self.batches.split_off(&validating_epoch);
        // batches less than `validating_epoch`
        let removed_batches = std::mem::replace(&mut self.batches, remaining_batches);

        for (id, batch) in removed_batches.into_iter() {
            // only for batches awaiting validation can we be sure the last attempt is
            // right, and thus, that any different attempt is wrong
            match batch.state() {
                BatchState::AwaitingValidation(processed_attempt) => {
                    for attempt in batch.attempts() {
                        // The validated batch has been re-processed
                        if attempt.hash != processed_attempt.hash {
                            // The re-downloaded version was different
                            if processed_attempt.peer_id != attempt.peer_id {
                                // A different peer sent the correct batch, the previous peer did not
                                // We negatively score the original peer.
                                let action = PeerAction::LowToleranceError;
                                debug!(
                                    batch_epoch = %id, score_adjustment = %action,
                                    original_peer = %attempt.peer_id, new_peer = %processed_attempt.peer_id,
                                    "Re-processed batch validated. Scoring original peer"
                                );
                                network.report_peer(
                                    attempt.peer_id,
                                    action,
                                    "batch_reprocessed_original_peer",
                                );
                            } else {
                                // The same peer corrected it's previous mistake. There was an error, so we
                                // negative score the original peer.
                                let action = PeerAction::MidToleranceError;
                                debug!(
                                    batch_epoch = %id,
                                    score_adjustment = %action,
                                    original_peer = %attempt.peer_id,
                                    new_peer = %processed_attempt.peer_id,
                                    "Re-processed batch validated by the same peer"
                                );
                                network.report_peer(
                                    attempt.peer_id,
                                    action,
                                    "batch_reprocessed_same_peer",
                                );
                            }
                        }
                    }
                }
                BatchState::Downloading(..) => {}
                BatchState::Failed | BatchState::Poisoned | BatchState::AwaitingDownload => {
                    crit!("batch indicates inconsistent chain state while advancing chain")
                }
                BatchState::AwaitingProcessing(..) => {}
                BatchState::Processing(_) => {
                    debug!(batch = %id, %batch, "Advancing chain while processing a batch");
                    if let Some(processing_id) = self.current_processing_batch
                        && id <= processing_id
                    {
                        self.current_processing_batch = None;
                    }
                }
            }
        }

        self.processing_target = self.processing_target.max(validating_epoch);
        let old_start = self.start_epoch;
        self.start_epoch = validating_epoch;
        self.to_be_downloaded = self.to_be_downloaded.max(validating_epoch);
        if self.batches.contains_key(&self.to_be_downloaded) {
            // if a chain is advanced by Range beyond the previous `self.to_be_downloaded`, we
            // won't have this batch, so we need to request it.
            self.to_be_downloaded += EPOCHS_PER_BATCH;
        }
        if let Some(epoch) = self.optimistic_start
            && epoch <= validating_epoch
        {
            self.optimistic_start = None;
        }

        debug!(
            previous_start = %old_start,
            new_start = %self.start_epoch,
            processing_target = %self.processing_target,
            id=%self.id,
            "Chain advanced"
        );
    }

    /// An invalid batch has been received that could not be processed, but that can be retried.
    ///
    /// These events occur when a peer has successfully responded with blocks, but the blocks we
    /// have received are incorrect or invalid. This indicates the peer has not performed as
    /// intended and can result in downvoting a peer.
    fn handle_invalid_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid.

        // The previous batch could be incomplete due to the block sizes being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        if let Some(epoch) = self.optimistic_start {
            // If this batch is an optimistic batch, we reject this epoch as an optimistic
            // candidate and try to re download it
            if epoch == batch_id {
                return self.reject_optimistic_batch(network, true, "batch was invalid");
                // since this is the optimistic batch, we can't consider previous batches as
                // invalid.
            }
        }
        // this is our robust `processing_target`. All previous batches must be awaiting
        // validation

        for (id, batch) in self.batches.range_mut(..batch_id) {
            if let BatchOperationOutcome::Failed { blacklist } = batch.validation_failed()? {
                // remove the chain early
                return Err(RemoveChain::ChainFailed {
                    blacklist,
                    failing_batch: *id,
                });
            }
        }

        // no batch maxed out it process attempts, so now the chain's volatile progress must be
        // reset
        self.processing_target = self.start_epoch;

        // finally, re-request the failed batch and all other batches in `AwaitingDownload` state.
        self.attempt_send_awaiting_download_batches(network, "handle_invalid_batch")
    }

    pub fn stop_syncing(&mut self) {
        debug!(parent: &self.span, "Stopping syncing");
        self.state = ChainSyncingState::Stopped;
    }

    /// Either a new chain, or an old one with a peer list
    /// This chain has been requested to start syncing.
    ///
    /// This could be new chain, or an old chain that is being resumed.
    pub fn start_syncing(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local_finalized_epoch: Epoch,
        optimistic_start_epoch: Epoch,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        debug!(
            ?local_finalized_epoch,
            ?optimistic_start_epoch,
            "Start syncing chain"
        );
        // to avoid dropping local progress, we advance the chain wrt its batch boundaries. This
        let align = |epoch| {
            // start_epoch + (number of batches in between)*length_of_batch
            self.start_epoch + ((epoch - self.start_epoch) / EPOCHS_PER_BATCH) * EPOCHS_PER_BATCH
        };
        // get the *aligned* epoch that produces a batch containing the `local_finalized_epoch`
        let validating_epoch = align(local_finalized_epoch);
        // align the optimistic_start too.
        let optimistic_epoch = align(optimistic_start_epoch);

        // advance the chain to the new validating epoch
        self.advance_chain(network, validating_epoch);
        // attempt to download any batches stuck in the `AwaitingDownload` state because of
        // a lack of peers earlier
        self.attempt_send_awaiting_download_batches(network, "start_syncing")?;
        if self.optimistic_start.is_none()
            && optimistic_epoch > self.processing_target
            && !self.attempted_optimistic_starts.contains(&optimistic_epoch)
        {
            self.optimistic_start = Some(optimistic_epoch);
        }

        // update the state
        self.state = ChainSyncingState::Syncing;

        // begin requesting blocks from the peer pool, until all peers are exhausted.
        self.request_batches(network)?;

        // start processing batches if needed
        self.process_completed_batches(network)
    }

    /// Add a peer to the chain.
    ///
    /// If the chain is active, this starts requesting batches from this peer.
    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        peer_id: PeerId,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        debug!(peer_id = %peer_id, "Adding peer to chain");
        self.peers.insert(peer_id);
        self.request_batches(network)
    }

    /// An RPC error has occurred.
    ///
    /// If the batch exists it is re-requested.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: Id,
        err: RpcResponseError,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        let batch_state = self.visualize_batch_state();
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            if let RpcResponseError::BlockComponentCouplingError(coupling_error) = &err {
                match coupling_error {
                    CouplingError::DataColumnPeerFailure {
                        error,
                        faulty_peers,
                        exceeded_retries,
                    } => {
                        debug!(?batch_id, error, "Block components coupling error");
                        // Note: we don't fail the batch here because a `CouplingError` is
                        // recoverable by requesting from other honest peers.
                        let mut failed_columns = HashSet::new();
                        let mut failed_peers = HashSet::new();
                        for (column, peer) in faulty_peers {
                            failed_columns.insert(*column);
                            failed_peers.insert(*peer);
                        }
                        // Retry the failed columns if the column requests haven't exceeded the
                        // max retries. Otherwise, remove treat it as a failed batch below.
                        if !*exceeded_retries {
                            // Set the batch back to `AwaitingDownload` before retrying.
                            // This is to ensure that the batch doesn't get stuck in `Downloading` state.
                            //
                            // DataColumn retries has a retry limit so calling `downloading_to_awaiting_download`
                            // is safe.
                            if let BatchOperationOutcome::Failed { blacklist } =
                                batch.downloading_to_awaiting_download()?
                            {
                                return Err(RemoveChain::ChainFailed {
                                    blacklist,
                                    failing_batch: batch_id,
                                });
                            }
                            return self.retry_partial_batch(
                                network,
                                batch_id,
                                request_id,
                                failed_columns,
                                failed_peers,
                            );
                        }
                    }
                    CouplingError::BlobPeerFailure(msg) => {
                        tracing::debug!(?batch_id, msg, "Blob peer failure");
                    }
                    CouplingError::InternalError(msg) => {
                        tracing::error!(?batch_id, msg, "Block components coupling internal error");
                    }
                }
            }
            // A batch could be retried without the peer failing the request (disconnecting/
            // sending an error /timeout) if the peer is removed from the chain for other
            // reasons. Check that this block belongs to the expected peer
            if !batch.is_expecting_request_id(&request_id) {
                debug!(
                    batch_epoch = %batch_id,
                    batch_state = ?batch.state(),
                    %peer_id,
                    %request_id,
                    ?batch_state,
                    "Batch not expecting block"
                );
                return Ok(KeepChain);
            }
            debug!(
                batch_epoch = %batch_id,
                batch_state = ?batch.state(),
                error = ?err,
                %peer_id,
                %request_id,
                "Batch download error"
            );
            if let BatchOperationOutcome::Failed { blacklist } =
                batch.download_failed(Some(*peer_id))?
            {
                return Err(RemoveChain::ChainFailed {
                    blacklist,
                    failing_batch: batch_id,
                });
            }
            // The errored batch is set to AwaitingDownload above.
            // We now just attempt to download all batches stuck in `AwaitingDownload`
            // state in the right order.
            self.attempt_send_awaiting_download_batches(network, "injecting error")
        } else {
            debug!(
                batch_epoch = %batch_id,
                %peer_id,
                %request_id,
                batch_state,
                "Batch not found"
            );
            // this could be an error for an old batch, removed when the chain advances
            Ok(KeepChain)
        }
    }

    /// Attempts to send all batches that are in `AwaitingDownload` state.
    ///
    /// Batches might get stuck in `AwaitingDownload` post peerdas because of lack of peers
    /// in required subnets. We need to progress them if peers are available at a later point.
    pub fn attempt_send_awaiting_download_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        src: &str,
    ) -> ProcessingResult {
        // Collect all batches in AwaitingDownload state and see if they can be sent
        let awaiting_downloads: Vec<_> = self
            .batches
            .iter()
            .filter(|(_, batch)| matches!(batch.state(), BatchState::AwaitingDownload))
            .map(|(batch_id, _)| batch_id)
            .copied()
            .collect();
        debug!(
            ?awaiting_downloads,
            src, "Attempting to send batches awaiting download"
        );

        for batch_id in awaiting_downloads {
            if self.good_peers_on_sampling_subnets(batch_id, network) {
                self.send_batch(network, batch_id)?;
            } else {
                debug!(
                    src = "attempt_send_awaiting_download_batches",
                    "Waiting for peers to be available on sampling column subnets"
                );
            }
        }
        Ok(KeepChain)
    }

    /// Requests the batch assigned to the given id from a given peer.
    pub fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        debug!(batch_epoch = %batch_id, "Requesting batch");
        let batch_state = self.visualize_batch_state();
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            let (request, batch_type) = batch.to_blocks_by_range_request();
            let failed_peers = batch.failed_peers();

            let synced_column_peers = network
                .network_globals()
                .peers
                .read()
                .synced_peers_for_epoch(batch_id)
                .cloned()
                .collect::<HashSet<_>>();

            match network.block_components_by_range_request(
                batch_type,
                request,
                RangeRequestId::RangeSync {
                    chain_id: self.id,
                    batch_id,
                },
                // Request blocks only from peers of this specific chain
                &self.peers,
                // Request column from all synced peers, even if they are not part of this chain.
                // This is to avoid splitting of good column peers across many head chains in a heavy forking
                // environment. If the column peers and block peer are on different chains, then we return
                // a coupling error and retry only the columns that failed to couple. See `Self::retry_partial_batch`.
                &synced_column_peers,
                &failed_peers,
            ) {
                Ok(request_id) => {
                    // inform the batch about the new request
                    batch.start_downloading(request_id)?;
                    if self
                        .optimistic_start
                        .map(|epoch| epoch == batch_id)
                        .unwrap_or(false)
                    {
                        debug!(epoch = %batch_id, %batch, %batch_state, "Requesting optimistic batch");
                    } else {
                        debug!(epoch = %batch_id, %batch, %batch_state, "Requesting batch");
                    }
                    return Ok(KeepChain);
                }
                Err(e) => match e {
                    // TODO(das): Handle the NoPeer case explicitly and don't drop the batch. For
                    // sync to work properly it must be okay to have "stalled" batches in
                    // AwaitingDownload state. Currently it will error with invalid state if
                    // that happens. Sync manager must periodicatlly prune stalled batches like
                    // we do for lookup sync. Then we can deprecate the redundant
                    // `good_peers_on_sampling_subnets` checks.
                    e
                    @ (RpcRequestSendError::NoPeer(_) | RpcRequestSendError::InternalError(_)) => {
                        // NOTE: under normal conditions this shouldn't happen but we handle it anyway
                        warn!(%batch_id, error = ?e, "batch_id" = %batch_id, %batch, "Could not send batch request");
                        // register the failed download and check if the batch can be retried
                        batch.start_downloading(1)?; // fake request_id = 1 is not relevant
                        match batch.download_failed(None)? {
                            BatchOperationOutcome::Failed { blacklist } => {
                                return Err(RemoveChain::ChainFailed {
                                    blacklist,
                                    failing_batch: batch_id,
                                });
                            }
                            BatchOperationOutcome::Continue => {
                                return self.send_batch(network, batch_id);
                            }
                        }
                    }
                },
            }
        }

        Ok(KeepChain)
    }

    /// Retries partial column requests within the batch by creating new requests for the failed columns.
    fn retry_partial_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        id: Id,
        failed_columns: HashSet<ColumnIndex>,
        mut failed_peers: HashSet<PeerId>,
    ) -> ProcessingResult {
        let _guard = self.span.clone().entered();
        debug!(%batch_id, %id, ?failed_columns, "Retrying partial batch");
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            failed_peers.extend(&batch.failed_peers());
            let req = batch.to_blocks_by_range_request().0;

            let synced_peers = network
                .network_globals()
                .peers
                .read()
                .synced_peers_for_epoch(batch_id)
                .cloned()
                .collect::<HashSet<_>>();

            match network.retry_columns_by_range(
                id,
                &synced_peers,
                &failed_peers,
                req,
                &failed_columns,
            ) {
                Ok(_) => {
                    // inform the batch about the new request
                    batch.start_downloading(id)?;
                    debug!(
                        ?batch_id,
                        id, "Retried column requests from different peers"
                    );
                    return Ok(KeepChain);
                }
                Err(e) => {
                    // No need to explicitly fail the batch since its in `AwaitingDownload` state
                    // before we attempted to retry.
                    debug!(?batch_id, id, e, "Failed to retry partial batch");
                }
            }
        }
        Ok(KeepChain)
    }

    /// Returns true if this chain is currently syncing.
    pub fn is_syncing(&self) -> bool {
        match self.state {
            ChainSyncingState::Syncing => true,
            ChainSyncingState::Stopped => false,
        }
    }

    /// Kickstarts the chain by sending for processing batches that are ready and requesting more
    /// batches if needed.
    pub fn resume(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<KeepChain, RemoveChain> {
        let _guard = self.span.clone().entered();
        debug!("Resuming chain");
        // attempt to download any batches stuck in the `AwaitingDownload` state because of
        // a lack of peers before.
        self.attempt_send_awaiting_download_batches(network, "resume")?;
        // Request more batches if needed.
        self.request_batches(network)?;
        // If there is any batch ready for processing, send it.
        self.process_completed_batches(network)
    }

    /// Attempts to request the next required batches from the peer pool if the chain is syncing. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(&mut self, network: &mut SyncNetworkContext<T>) -> ProcessingResult {
        if !matches!(self.state, ChainSyncingState::Syncing) {
            return Ok(KeepChain);
        }
        // find the next pending batch and request it from the peer

        // check if we have the batch for our optimistic start. If not, request it first.
        // We wait for this batch before requesting any other batches.
        if let Some(epoch) = self.optimistic_start {
            if !self.good_peers_on_sampling_subnets(epoch, network) {
                debug!(
                    src = "request_batches_optimistic",
                    "Waiting for peers to be available on sampling column subnets"
                );
                return Ok(KeepChain);
            }

            if let Entry::Vacant(entry) = self.batches.entry(epoch) {
                let batch_type = network.batch_type(epoch);
                let optimistic_batch = BatchInfo::new(&epoch, EPOCHS_PER_BATCH, batch_type);
                entry.insert(optimistic_batch);
                self.send_batch(network, epoch)?;
            } else {
                self.attempt_send_awaiting_download_batches(network, "request_batches_optimistic")?;
            }
            return Ok(KeepChain);
        }

        // find the next pending batch and request it from the peer
        // Note: for this function to not infinite loop we must:
        // - If `include_next_batch` returns Some we MUST increase the count of batches that are
        //   accounted in the `BACKFILL_BATCH_BUFFER_SIZE` limit in the `matches!` statement of
        //   that function.
        while let Some(batch_id) = self.include_next_batch(network) {
            // send the batch
            self.send_batch(network, batch_id)?;
        }

        // No more batches, simply stop
        Ok(KeepChain)
    }

    /// Checks all sampling column subnets for peers. Returns `true` if there is at least one peer in
    /// every sampling column subnet.
    fn good_peers_on_sampling_subnets(
        &self,
        epoch: Epoch,
        network: &SyncNetworkContext<T>,
    ) -> bool {
        if network.chain.spec.is_peer_das_enabled_for_epoch(epoch) {
            // Require peers on all sampling column subnets before sending batches
            let sampling_subnets = network.network_globals().sampling_subnets();
            network
                .network_globals()
                .peers
                .read()
                .has_good_custody_range_sync_peer(&sampling_subnets, epoch)
        } else {
            true
        }
    }

    /// Creates the next required batch from the chain. If there are no more batches required,
    /// `false` is returned.
    fn include_next_batch(&mut self, network: &mut SyncNetworkContext<T>) -> Option<BatchId> {
        // don't request batches beyond the target head slot
        if self
            .to_be_downloaded
            .start_slot(T::EthSpec::slots_per_epoch())
            >= self.target_head_slot
        {
            return None;
        }

        // only request batches up to the buffer size limit
        // NOTE: we don't count batches in the AwaitingValidation state, to prevent stalling sync
        // if the current processing window is contained in a long range of skip slots.
        let in_buffer = |batch: &RangeSyncBatchInfo<T::EthSpec>| {
            matches!(
                batch.state(),
                BatchState::Downloading(..) | BatchState::AwaitingProcessing(..)
            )
        };
        if self
            .batches
            .iter()
            .filter(|&(_epoch, batch)| in_buffer(batch))
            .count()
            > BATCH_BUFFER_SIZE as usize
        {
            return None;
        }

        // don't send batch requests until we have peers on sampling subnets
        // TODO(das): this is a workaround to avoid sending out excessive block requests because
        // block and data column requests are currently coupled. This can be removed once we find a
        // way to decouple the requests and do retries individually, see issue #6258.
        if !self.good_peers_on_sampling_subnets(self.to_be_downloaded, network) {
            debug!(
                src = "include_next_batch",
                "Waiting for peers to be available on custody column subnets"
            );
            return None;
        }

        // If no batch needs a retry, attempt to send the batch of the next epoch to download
        let next_batch_id = self.to_be_downloaded;
        // this batch could have been included already being an optimistic batch
        match self.batches.entry(next_batch_id) {
            Entry::Occupied(_) => {
                // this batch doesn't need downloading, let this same function decide the next batch
                self.to_be_downloaded += EPOCHS_PER_BATCH;
                self.include_next_batch(network)
            }
            Entry::Vacant(entry) => {
                let batch_type = network.batch_type(next_batch_id);
                entry.insert(BatchInfo::new(&next_batch_id, EPOCHS_PER_BATCH, batch_type));
                self.to_be_downloaded += EPOCHS_PER_BATCH;
                Some(next_batch_id)
            }
        }
    }

    /// Creates a string visualization of the current state of the chain, to make it easier for debugging and understanding
    /// where sync is up to from glancing at the logs.
    ///
    /// This produces a string of the form: [D,E,E,E,E]
    /// to indicate the current buffer state of the chain. The symbols are defined on each of the
    /// batch states. See [BatchState::visualize] for symbol definitions.
    fn visualize_batch_state(&self) -> String {
        let mut visualization_string = String::with_capacity((BATCH_BUFFER_SIZE * 3) as usize);

        // Start of the block
        visualization_string.push('[');

        for mut batch_index in 0..BATCH_BUFFER_SIZE {
            if let Some(batch) = self
                .batches
                .get(&(self.processing_target + batch_index as u64 * EPOCHS_PER_BATCH))
            {
                visualization_string.push(batch.visualize());
                if batch_index != BATCH_BUFFER_SIZE {
                    // Add a comma in between elements
                    visualization_string.push(',');
                }
            } else {
                // No batch exists, it is on our list to be downloaded
                // Fill in the rest of the gaps
                while batch_index < BATCH_BUFFER_SIZE {
                    visualization_string.push('E');
                    // Add a comma between the empty batches
                    if batch_index < BATCH_BUFFER_SIZE.saturating_sub(1) {
                        visualization_string.push(',')
                    }
                    batch_index += 1;
                }
                break;
            }
        }
        visualization_string.push(']');
        visualization_string
    }
}

use crate::sync::batch::WrongState as WrongBatchState;
impl From<WrongBatchState> for RemoveChain {
    fn from(err: WrongBatchState) -> Self {
        RemoveChain::WrongBatchState(err.0)
    }
}

impl RemoveChain {
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            RemoveChain::WrongBatchState(..) | RemoveChain::WrongChainState(..)
        )
    }
}

impl From<RangeSyncType> for SyncingChainType {
    fn from(value: RangeSyncType) -> Self {
        match value {
            RangeSyncType::Head => Self::Head,
            RangeSyncType::Finalized => Self::Finalized,
        }
    }
}
