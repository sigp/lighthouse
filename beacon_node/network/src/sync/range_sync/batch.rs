use crate::sync::RequestId;
use eth2_libp2p::rpc::methods::BlocksByRangeRequest;
use eth2_libp2p::PeerId;
use ssz::Encode;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::ops::Sub;
use types::{Epoch, EthSpec, SignedBeaconBlock, Slot};

/// The number of times to retry a batch before it is considered failed.
const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 5;

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 3;

/// Allows customisation of the above constants used in other sync methods such as BackFillSync.
pub trait BatchConfig {
    /// The maximum batch download attempts.
    fn max_batch_download_attempts() -> u8;
    /// The max batch processing attempts.
    fn max_batch_processing_attempts() -> u8;
}

pub struct RangeSyncBatchConfig {}

impl BatchConfig for RangeSyncBatchConfig {
    fn max_batch_download_attempts() -> u8 {
        MAX_BATCH_DOWNLOAD_ATTEMPTS
    }
    fn max_batch_processing_attempts() -> u8 {
        MAX_BATCH_PROCESSING_ATTEMPTS
    }
}

/// Error type of a batch in a wrong state.
// Such errors should never be encountered.
pub struct WrongState(pub(crate) String);

/// Auxiliary type alias for readability.
type IsFailed = bool;

/// A segment of a chain.
pub struct BatchInfo<T: EthSpec, B: BatchConfig = RangeSyncBatchConfig> {
    /// Start slot of the batch.
    start_slot: Slot,
    /// End slot of the batch.
    end_slot: Slot,
    /// The `Attempts` that have been made and failed to send us this batch.
    failed_processing_attempts: Vec<Attempt>,
    /// The number of download retries this batch has undergone due to a failed request.
    failed_download_attempts: Vec<PeerId>,
    /// State of the batch.
    state: BatchState<T>,
    /// Pin the generic
    marker: std::marker::PhantomData<B>,
}

/// Current state of a batch
pub enum BatchState<T: EthSpec> {
    /// The batch has failed either downloading or processing, but can be requested again.
    AwaitingDownload,
    /// The batch is being downloaded.
    Downloading(PeerId, Vec<SignedBeaconBlock<T>>, RequestId),
    /// The batch has been completely downloaded and is ready for processing.
    AwaitingProcessing(PeerId, Vec<SignedBeaconBlock<T>>),
    /// The batch is being processed.
    Processing(Attempt),
    /// The batch was successfully processed and is waiting to be validated.
    ///
    /// It is not sufficient to process a batch successfully to consider it correct. This is
    /// because batches could be erroneously empty, or incomplete. Therefore, a batch is considered
    /// valid, only if the next sequential batch imports at least a block.
    AwaitingValidation(Attempt),
    /// Intermediate state for inner state handling.
    Poisoned,
    /// The batch has maxed out the allowed attempts for either downloading or processing. It
    /// cannot be recovered.
    Failed,
}

impl<T: EthSpec> BatchState<T> {
    /// Helper function for poisoning a state.
    pub fn poison(&mut self) -> BatchState<T> {
        std::mem::replace(self, BatchState::Poisoned)
    }

    pub fn is_failed(&self) -> IsFailed {
        match self {
            BatchState::Failed => true,
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            _ => false,
        }
    }
}

impl<T: EthSpec, B: BatchConfig> BatchInfo<T, B> {
    /// Batches are downloaded excluding the first block of the epoch assuming it has already been
    /// downloaded.
    ///
    /// For example:
    ///
    /// Epoch boundary |                                   |
    ///  ... | 30 | 31 | 32 | 33 | 34 | ... | 61 | 62 | 63 | 64 | 65 |
    ///       Batch 1       |              Batch 2              |  Batch 3
    pub fn new(start_epoch: &Epoch, num_of_epochs: u64) -> Self {
        let start_slot = start_epoch.start_slot(T::slots_per_epoch()) + 1;
        let end_slot = start_slot + num_of_epochs * T::slots_per_epoch();
        BatchInfo {
            start_slot,
            end_slot,
            failed_processing_attempts: Vec::new(),
            failed_download_attempts: Vec::new(),
            state: BatchState::AwaitingDownload,
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

        for download in &self.failed_download_attempts {
            peers.insert(*download);
        }

        peers
    }

    /// Verifies if an incomming block belongs to this batch.
    pub fn is_expecting_block(&self, peer_id: &PeerId, request_id: &RequestId) -> bool {
        if let BatchState::Downloading(expected_peer, _, expected_id) = &self.state {
            return peer_id == expected_peer && expected_id == request_id;
        }
        false
    }

    /// Returns the peer that is currently responsible for progressing the state of the batch.
    pub fn current_peer(&self) -> Option<&PeerId> {
        match &self.state {
            BatchState::AwaitingDownload | BatchState::Failed => None,
            BatchState::Downloading(peer_id, _, _)
            | BatchState::AwaitingProcessing(peer_id, _)
            | BatchState::Processing(Attempt { peer_id, .. })
            | BatchState::AwaitingValidation(Attempt { peer_id, .. }) => Some(peer_id),
            BatchState::Poisoned => unreachable!("Poisoned batch"),
        }
    }

    /// Returns a BlocksByRange request associated with the batch.
    pub fn to_blocks_by_range_request(&self) -> BlocksByRangeRequest {
        BlocksByRangeRequest {
            start_slot: self.start_slot.into(),
            count: self.end_slot.sub(self.start_slot).into(),
            step: 1,
        }
    }

    pub fn state(&self) -> &BatchState<T> {
        &self.state
    }

    pub fn attempts(&self) -> &[Attempt] {
        &self.failed_processing_attempts
    }

    /// Adds a block to a downloading batch.
    pub fn add_block(&mut self, block: SignedBeaconBlock<T>) -> Result<(), WrongState> {
        match self.state.poison() {
            BatchState::Downloading(peer, mut blocks, req_id) => {
                blocks.push(block);
                self.state = BatchState::Downloading(peer, blocks, req_id);
                Ok(())
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Add block for batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    /// Marks the batch as ready to be processed if the blocks are in the range. The number of
    /// received blocks is returned, or the wrong batch end on failure
    #[must_use = "Batch may have failed"]
    pub fn download_completed(
        &mut self,
    ) -> Result<usize /* Received blocks */, Result<(Slot, Slot, IsFailed), WrongState>> {
        match self.state.poison() {
            BatchState::Downloading(peer, blocks, _request_id) => {
                // verify that blocks are in range
                if let Some(last_slot) = blocks.last().map(|b| b.slot()) {
                    // the batch is non-empty
                    let first_slot = blocks[0].slot();

                    let failed_range = if first_slot < self.start_slot {
                        Some((self.start_slot, first_slot))
                    } else if self.end_slot < last_slot {
                        Some((self.end_slot, last_slot))
                    } else {
                        None
                    };

                    if let Some((expected, received)) = failed_range {
                        // this is a failed download, register the attempt and check if the batch
                        // can be tried again
                        self.failed_download_attempts.push(peer);
                        self.state = if self.failed_download_attempts.len()
                            >= B::max_batch_download_attempts() as usize
                        {
                            BatchState::Failed
                        } else {
                            // drop the blocks
                            BatchState::AwaitingDownload
                        };

                        return Err(Ok((expected, received, self.state.is_failed())));
                    }
                }

                let received = blocks.len();
                self.state = BatchState::AwaitingProcessing(peer, blocks);
                Ok(received)
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(Err(WrongState(format!(
                    "Download completed for batch in wrong state {:?}",
                    self.state
                ))))
            }
        }
    }

    /// Mark the batch as failed and return whether we can attempt a re-download.
    ///
    /// This can happen if a peer disconnects or some error occurred that was not the peers fault.
    /// THe `mark_failed` parameter, when set to false, does not increment the failed attempts of
    /// this batch and register the peer, rather attempts a re-download.
    #[must_use = "Batch may have failed"]
    pub fn download_failed(&mut self, mark_failed: bool) -> Result<IsFailed, WrongState> {
        match self.state.poison() {
            BatchState::Downloading(peer, _, _request_id) => {
                // register the attempt and check if the batch can be tried again
                if mark_failed {
                    self.failed_download_attempts.push(peer);
                }
                self.state = if self.failed_download_attempts.len()
                    >= B::max_batch_download_attempts() as usize
                {
                    BatchState::Failed
                } else {
                    // drop the blocks
                    BatchState::AwaitingDownload
                };
                Ok(self.state.is_failed())
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

    pub fn start_downloading_from_peer(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
    ) -> Result<(), WrongState> {
        match self.state.poison() {
            BatchState::AwaitingDownload => {
                self.state = BatchState::Downloading(peer, Vec::new(), request_id);
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

    pub fn start_processing(&mut self) -> Result<Vec<SignedBeaconBlock<T>>, WrongState> {
        match self.state.poison() {
            BatchState::AwaitingProcessing(peer, blocks) => {
                self.state = BatchState::Processing(Attempt::new(peer, &blocks));
                Ok(blocks)
            }
            BatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Starting procesing batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    #[must_use = "Batch may have failed"]
    pub fn processing_completed(&mut self, was_sucessful: bool) -> Result<IsFailed, WrongState> {
        match self.state.poison() {
            BatchState::Processing(attempt) => {
                self.state = if !was_sucessful {
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
                } else {
                    BatchState::AwaitingValidation(attempt)
                };
                Ok(self.state.is_failed())
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
    pub fn validation_failed(&mut self) -> Result<IsFailed, WrongState> {
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
                Ok(self.state.is_failed())
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
}

/// Represents a peer's attempt and providing the result for this batch.
///
/// Invalid attempts will downscore a peer.
#[derive(PartialEq, Debug)]
pub struct Attempt {
    /// The peer that made the attempt.
    pub peer_id: PeerId,
    /// The hash of the blocks of the attempt.
    pub hash: u64,
}

impl Attempt {
    #[allow(clippy::ptr_arg)]
    fn new<T: EthSpec>(peer_id: PeerId, blocks: &Vec<SignedBeaconBlock<T>>) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        blocks.as_ssz_bytes().hash(&mut hasher);
        let hash = hasher.finish();
        Attempt { peer_id, hash }
    }
}

impl<T: EthSpec, B: BatchConfig> slog::KV for &mut BatchInfo<T, B> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::KV::serialize(*self, record, serializer)
    }
}

impl<T: EthSpec, B: BatchConfig> slog::KV for BatchInfo<T, B> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        use slog::Value;
        Value::serialize(&self.start_slot, record, "start_slot", serializer)?;
        Value::serialize(
            &(self.end_slot - 1), // NOTE: The -1 shows inclusive blocks
            record,
            "end_slot",
            serializer,
        )?;
        serializer.emit_usize("downloaded", self.failed_download_attempts.len())?;
        serializer.emit_usize("processed", self.failed_processing_attempts.len())?;
        serializer.emit_arguments("state", &format_args!("{:?}", self.state))?;
        slog::Result::Ok(())
    }
}

impl<T: EthSpec> std::fmt::Debug for BatchState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchState::Processing(Attempt {
                ref peer_id,
                hash: _,
            }) => write!(f, "Processing({})", peer_id),
            BatchState::AwaitingValidation(Attempt {
                ref peer_id,
                hash: _,
            }) => write!(f, "AwaitingValidation({})", peer_id),
            BatchState::AwaitingDownload => f.write_str("AwaitingDownload"),
            BatchState::Failed => f.write_str("Failed"),
            BatchState::AwaitingProcessing(ref peer, ref blocks) => {
                write!(f, "AwaitingProcessing({}, {} blocks)", peer, blocks.len())
            }
            BatchState::Downloading(peer, blocks, request_id) => write!(
                f,
                "Downloading({}, {} blocks, {})",
                peer,
                blocks.len(),
                request_id
            ),
            BatchState::Poisoned => f.write_str("Poisoned"),
        }
    }
}
