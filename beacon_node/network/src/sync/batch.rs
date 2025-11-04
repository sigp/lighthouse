use beacon_chain::block_verification_types::RpcBlock;
use derivative::Derivative;
use lighthouse_network::PeerId;
use lighthouse_network::rpc::methods::BlocksByRangeRequest;
use lighthouse_network::rpc::methods::DataColumnsByRangeRequest;
use lighthouse_network::service::api_types::Id;
use std::collections::HashSet;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Sub;
use std::time::Duration;
use std::time::Instant;
use strum::Display;
use types::Slot;
use types::{DataColumnSidecarList, Epoch, EthSpec};

pub type BatchId = Epoch;

/// Type of expected batch.
#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ByRangeRequestType {
    BlocksAndColumns,
    BlocksAndBlobs,
    Blocks,
    Columns(HashSet<u64>),
}

/// Allows customisation of the above constants used in other sync methods such as BackFillSync.
pub trait BatchConfig {
    /// The maximum batch download attempts.
    fn max_batch_download_attempts() -> u8;
    /// The max batch processing attempts.
    fn max_batch_processing_attempts() -> u8;
    /// Hashing function of a batch's attempt. Used for scoring purposes.
    ///
    /// When a batch fails processing, it is possible that the batch is wrong (faulty or
    /// incomplete) or that a previous one is wrong. For this reason we need to re-download and
    /// re-process the batches awaiting validation and the current one. Consider this scenario:
    ///
    /// ```ignore
    /// BatchA BatchB BatchC BatchD
    /// -----X Empty  Empty  Y-----
    /// ```
    ///
    /// BatchA declares that it refers X, but BatchD declares that it's first block is Y. There is no
    /// way to know if BatchD is faulty/incomplete or if batches B and/or C are missing blocks. It is
    /// also possible that BatchA belongs to a different chain to the rest starting in some block
    /// midway in the batch's range. For this reason, the four batches would need to be re-downloaded
    /// and re-processed.
    ///
    /// If batchD was actually good, it will still register two processing attempts for the same set of
    /// blocks. In this case, we don't want to penalize the peer that provided the first version, since
    /// it's equal to the successfully processed one.
    ///
    /// The function `batch_attempt_hash` provides a way to compare two batch attempts without
    /// storing the full set of blocks.
    ///
    /// Note that simpler hashing functions considered in the past (hash of first block, hash of last
    /// block, number of received blocks) are not good enough to differentiate attempts. For this
    /// reason, we hash the complete set of blocks both in RangeSync and BackFillSync.
    fn batch_attempt_hash<D: Hash>(data: &D) -> u64;
}

#[derive(Debug)]
pub struct WrongState(pub(crate) String);

/// After batch operations, we use this to communicate whether a batch can continue or not
pub enum BatchOperationOutcome {
    Continue,
    Failed { blacklist: bool },
}

#[derive(Debug)]
pub enum BatchProcessingResult {
    Success,
    FaultyFailure,
    NonFaultyFailure,
}

#[derive(Derivative)]
#[derivative(Debug)]
/// A segment of a chain.
pub struct BatchInfo<E: EthSpec, B: BatchConfig, D: Hash> {
    /// Start slot of the batch.
    start_slot: Slot,
    /// End slot of the batch.
    end_slot: Slot,
    /// The `Attempts` that have been made and failed to send us this batch.
    failed_processing_attempts: Vec<Attempt<D>>,
    /// Number of processing attempts that have failed but we do not count.
    non_faulty_processing_attempts: u8,
    /// The number of download retries this batch has undergone due to a failed request.
    failed_download_attempts: Vec<Option<PeerId>>,
    /// State of the batch.
    state: BatchState<D>,
    /// Whether this batch contains all blocks or all blocks and blobs.
    batch_type: ByRangeRequestType,
    /// Pin the generic
    #[derivative(Debug = "ignore")]
    marker: std::marker::PhantomData<(E, B)>,
}

impl<E: EthSpec, B: BatchConfig, D: std::fmt::Debug + Hash> std::fmt::Display
    for BatchInfo<E, B, D>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, End Slot: {}, State: {}",
            self.start_slot, self.end_slot, self.state
        )
    }
}

#[derive(Display)]
/// Current state of a batch
pub enum BatchState<D: Hash> {
    /// The batch has failed either downloading or processing, but can be requested again.
    AwaitingDownload,
    /// The batch is being downloaded.
    Downloading(Id),
    /// The batch has been completely downloaded and is ready for processing.
    AwaitingProcessing(PeerId, D, Instant),
    /// The batch is being processed.
    Processing(Attempt<D>),
    /// The batch was successfully processed and is waiting to be validated.
    ///
    /// It is not sufficient to process a batch successfully to consider it correct. This is
    /// because batches could be erroneously empty, or incomplete. Therefore, a batch is considered
    /// valid, only if the next sequential batch imports at least a block.
    AwaitingValidation(Attempt<D>),
    /// Intermediate state for inner state handling.
    Poisoned,
    /// The batch has maxed out the allowed attempts for either downloading or processing. It
    /// cannot be recovered.
    Failed,
}

impl<D: Hash> BatchState<D> {
    /// Helper function for poisoning a state.
    pub fn poison(&mut self) -> BatchState<D> {
        std::mem::replace(self, BatchState::Poisoned)
    }
}

impl<E: EthSpec, B: BatchConfig, D: Hash> BatchInfo<E, B, D> {
    /// Batches are downloaded excluding the first block of the epoch assuming it has already been
    /// downloaded.
    ///
    /// For example:
    ///
    /// Epoch boundary |                                   |
    ///  ... | 30 | 31 | 32 | 33 | 34 | ... | 61 | 62 | 63 | 64 | 65 |
    ///       Batch 1       |              Batch 2              |  Batch 3
    ///
    /// NOTE: Removed the shift by one for deneb because otherwise the last batch before the blob
    /// fork boundary will be of mixed type (all blocks and one last blockblob), and I don't want to
    /// deal with this for now.
    /// This means finalization might be slower in deneb
    pub fn new(start_epoch: &Epoch, num_of_epochs: u64, batch_type: ByRangeRequestType) -> Self {
        let start_slot = start_epoch.start_slot(E::slots_per_epoch());
        let end_slot = start_slot + num_of_epochs * E::slots_per_epoch();
        Self {
            start_slot,
            end_slot,
            failed_processing_attempts: Vec::new(),
            failed_download_attempts: Vec::new(),
            non_faulty_processing_attempts: 0,
            state: BatchState::<D>::AwaitingDownload,
            batch_type,
            marker: std::marker::PhantomData,
        }
    }

    /// Gives a list of peers from which this batch has had a failed download or processing
    /// attempt.
    pub fn failed_peers(&self) -> HashSet<PeerId> {
        let mut peers = HashSet::with_capacity(
            self.failed_processing_attempts.len() + self.failed_download_attempts.len(),
        );

        for attempt in &self.failed_processing_attempts {
            peers.insert(attempt.peer_id);
        }

        for peer in self.failed_download_attempts.iter().flatten() {
            peers.insert(*peer);
        }

        peers
    }

    /// Verifies if an incoming request id to this batch.
    pub fn is_expecting_request_id(&self, request_id: &Id) -> bool {
        if let BatchState::Downloading(expected_id) = &self.state {
            return expected_id == request_id;
        }
        false
    }

    /// Returns the peer that is currently responsible for progressing the state of the batch.
    pub fn processing_peer(&self) -> Option<&PeerId> {
        match &self.state {
            BatchState::AwaitingDownload | BatchState::Failed | BatchState::Downloading(..) => None,
            BatchState::AwaitingProcessing(peer_id, _, _)
            | BatchState::Processing(Attempt { peer_id, .. })
            | BatchState::AwaitingValidation(Attempt { peer_id, .. }) => Some(peer_id),
            BatchState::Poisoned => unreachable!("Poisoned batch"),
        }
    }

    /// After different operations over a batch, this could be in a state that allows it to
    /// continue, or in failed state. When the batch has failed, we check if it did mainly due to
    /// processing failures. In this case the batch is considered failed and faulty.
    pub fn outcome(&self) -> BatchOperationOutcome {
        match self.state {
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            BatchState::Failed => BatchOperationOutcome::Failed {
                blacklist: self.failed_processing_attempts.len()
                    > self.failed_download_attempts.len(),
            },
            _ => BatchOperationOutcome::Continue,
        }
    }

    pub fn state(&self) -> &BatchState<D> {
        &self.state
    }

    pub fn attempts(&self) -> &[Attempt<D>] {
        &self.failed_processing_attempts
    }

    /// Marks the batch as ready to be processed if the data columns are in the range. The number of
    /// received columns is returned, or the wrong batch end on failure
    #[must_use = "Batch may have failed"]
    pub fn download_completed(&mut self, data_columns: D, peer: PeerId) -> Result<(), WrongState> {
        match self.state.poison() {
            BatchState::Downloading(_) => {
                self.state = BatchState::AwaitingProcessing(peer, data_columns, Instant::now());
                Ok(())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Download completed for batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    /// Mark the batch as failed and return whether we can attempt a re-download.
    ///
    /// This can happen if a peer disconnects or some error occurred that was not the peers fault.
    /// The `peer` parameter, when set to None, does not increment the failed attempts of
    /// this batch and register the peer, rather attempts a re-download.
    #[must_use = "Batch may have failed"]
    pub fn download_failed(
        &mut self,
        peer: Option<PeerId>,
    ) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            BatchState::Downloading(_) => {
                // register the attempt and check if the batch can be tried again
                self.failed_download_attempts.push(peer);

                self.state = if self.failed_download_attempts.len()
                    >= B::max_batch_download_attempts() as usize
                {
                    BatchState::Failed
                } else {
                    // drop the blocks
                    BatchState::AwaitingDownload
                };
                Ok(self.outcome())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Download failed for batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    /// Change the batch state from `Self::Downloading` to `Self::AwaitingDownload` without
    /// registering a failed attempt.
    ///
    /// Note: must use this cautiously with some level of retry protection
    /// as not registering a failed attempt could lead to requesting in a loop.
    #[must_use = "Batch may have failed"]
    pub fn downloading_to_awaiting_download(
        &mut self,
    ) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            BatchState::Downloading(_) => {
                self.state = BatchState::AwaitingDownload;
                Ok(self.outcome())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Download failed for batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    pub fn start_downloading(&mut self, request_id: Id) -> Result<(), WrongState> {
        match self.state.poison() {
            BatchState::AwaitingDownload => {
                self.state = BatchState::Downloading(request_id);
                Ok(())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Starting download for batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    pub fn start_processing(&mut self) -> Result<(D, Duration), WrongState> {
        match self.state.poison() {
            BatchState::AwaitingProcessing(peer, data_columns, start_instant) => {
                self.state = BatchState::Processing(Attempt::new::<B>(peer, &data_columns));
                Ok((data_columns, start_instant.elapsed()))
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Starting processing batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    pub fn processing_completed(
        &mut self,
        processing_result: BatchProcessingResult,
    ) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            BatchState::Processing(attempt) => {
                self.state = match processing_result {
                    BatchProcessingResult::Success => BatchState::AwaitingValidation(attempt),
                    BatchProcessingResult::FaultyFailure => {
                        // register the failed attempt
                        self.failed_processing_attempts.push(attempt);

                        // check if the batch can be downloaded again
                        if self.failed_processing_attempts.len()
                            >= B::max_batch_processing_attempts() as usize
                        {
                            BatchState::Failed
                        } else {
                            BatchState::AwaitingDownload
                        }
                    }
                    BatchProcessingResult::NonFaultyFailure => {
                        self.non_faulty_processing_attempts =
                            self.non_faulty_processing_attempts.saturating_add(1);
                        BatchState::AwaitingDownload
                    }
                };
                Ok(self.outcome())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Procesing completed for batch in wrong state: {:?}",
                    self.state
                )))
            }
        }
    }

    #[must_use = "Batch may have failed"]
    pub fn validation_failed(&mut self) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            BatchState::AwaitingValidation(attempt) => {
                self.failed_processing_attempts.push(attempt);

                // check if the batch can be downloaded again
                self.state = if self.failed_processing_attempts.len()
                    >= B::max_batch_processing_attempts() as usize
                {
                    BatchState::Failed
                } else {
                    BatchState::AwaitingDownload
                };
                Ok(self.outcome())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Validation failed for batch in wrong state: {:?}",
                    self.state
                )))
            }
        }
    }

    // Visualizes the state of this batch using state::visualize()
    pub fn visualize(&self) -> char {
        self.state.visualize()
    }
}

// BatchInfo implementations for RangeSync
impl<E: EthSpec, B: BatchConfig> BatchInfo<E, B, Vec<RpcBlock<E>>> {
    /// Returns a BlocksByRange request associated with the batch.
    pub fn to_blocks_by_range_request(&self) -> (BlocksByRangeRequest, ByRangeRequestType) {
        (
            BlocksByRangeRequest::new(
                self.start_slot.into(),
                self.end_slot.sub(self.start_slot).into(),
            ),
            self.batch_type.clone(),
        )
    }

    /// Returns the count of stored pending blocks if in awaiting processing state
    pub fn pending_blocks(&self) -> usize {
        match &self.state {
            BatchState::AwaitingProcessing(_, blocks, _) => blocks.len(),
            BatchState::AwaitingDownload
            | BatchState::Downloading { .. }
            | BatchState::Processing { .. }
            | BatchState::AwaitingValidation { .. }
            | BatchState::Poisoned
            | BatchState::Failed => 0,
        }
    }
}

// BatchInfo implementation for CustodyBackFillSync
impl<E: EthSpec, B: BatchConfig> BatchInfo<E, B, DataColumnSidecarList<E>> {
    /// Returns a DataColumnsByRange request associated with the batch.
    pub fn to_data_columns_by_range_request(
        &self,
    ) -> Result<DataColumnsByRangeRequest, WrongState> {
        match &self.batch_type {
            ByRangeRequestType::Columns(columns) => Ok(DataColumnsByRangeRequest {
                start_slot: self.start_slot.into(),
                count: self.end_slot.sub(self.start_slot).into(),
                columns: columns.clone().into_iter().collect(),
            }),
            _ => Err(WrongState(
                "Custody backfill sync can only make data columns by range requests.".to_string(),
            )),
        }
    }
}

#[derive(Debug)]
pub struct Attempt<D: Hash> {
    /// The peer that made the attempt.
    pub peer_id: PeerId,
    /// The hash of the blocks of the attempt.
    pub hash: u64,
    /// Pin the generic.
    marker: PhantomData<D>,
}

impl<D: Hash> Attempt<D> {
    fn new<B: BatchConfig>(peer_id: PeerId, data: &D) -> Self {
        let hash = B::batch_attempt_hash(data);
        Attempt {
            peer_id,
            hash,
            marker: PhantomData,
        }
    }
}

impl<D: Hash> std::fmt::Debug for BatchState<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchState::Processing(Attempt { peer_id, .. }) => {
                write!(f, "Processing({})", peer_id)
            }
            BatchState::AwaitingValidation(Attempt { peer_id, .. }) => {
                write!(f, "AwaitingValidation({})", peer_id)
            }
            BatchState::AwaitingDownload => f.write_str("AwaitingDownload"),
            BatchState::Failed => f.write_str("Failed"),
            BatchState::AwaitingProcessing(peer, ..) => {
                write!(f, "AwaitingProcessing({})", peer)
            }
            BatchState::Downloading(request_id) => {
                write!(f, "Downloading({})", request_id)
            }
            BatchState::Poisoned => f.write_str("Poisoned"),
        }
    }
}

impl<D: Hash> BatchState<D> {
    /// Creates a character representation/visualization for the batch state to display in logs for quicker and
    /// easier recognition
    fn visualize(&self) -> char {
        match self {
            BatchState::Downloading(..) => 'D',
            BatchState::Processing(_) => 'P',
            BatchState::AwaitingValidation(_) => 'v',
            BatchState::AwaitingDownload => 'd',
            BatchState::Failed => 'F',
            BatchState::AwaitingProcessing(..) => 'p',
            BatchState::Poisoned => 'X',
        }
    }
}
