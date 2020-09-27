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

/// A segment of a chain.
pub struct BatchInfo<T: EthSpec> {
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
}

/// Current state of a batch
pub enum BatchState<T: EthSpec> {
    /// The batch has failed either downloading or processing, but can be requested again.
    AwaitingDownload,
    /// The batch is being downloaded.
    Downloading(PeerId, Vec<SignedBeaconBlock<T>>),
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
}

impl<T: EthSpec> BatchInfo<T> {
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
        }
    }

    /// Gives a list of peers from which this batch has had a failed download or processing
    /// attempt.
    pub fn failed_peers(&self) -> HashSet<PeerId> {
        let mut peers = HashSet::with_capacity(
            self.failed_processing_attempts.len() + self.failed_download_attempts.len(),
        );

        for attempt in &self.failed_processing_attempts {
            peers.insert(attempt.peer_id.clone());
        }

        for download in &self.failed_download_attempts {
            peers.insert(download.clone());
        }

        peers
    }

    pub fn current_peer(&self) -> Option<&PeerId> {
        match &self.state {
            BatchState::AwaitingDownload | BatchState::Failed => None,
            BatchState::Downloading(peer_id, _)
            | BatchState::AwaitingProcessing(peer_id, _)
            | BatchState::Processing(Attempt { peer_id, .. })
            | BatchState::AwaitingValidation(Attempt { peer_id, .. }) => Some(&peer_id),
            BatchState::Poisoned => unreachable!("Poisoned batch"),
        }
    }

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
    pub fn add_block(&mut self, block: SignedBeaconBlock<T>) {
        match self.state.poison() {
            BatchState::Downloading(peer, mut blocks) => {
                blocks.push(block);
                self.state = BatchState::Downloading(peer, blocks)
            }
            other => unreachable!("Add block for batch in wrong state: {:?}", other),
        }
    }

    /// Marks the batch as ready to be processed if the blocks are in the range. The number of
    /// received blocks is returned, or the wrong batch end on failure
    #[must_use = "Batch may have failed"]
    pub fn download_completed(
        &mut self,
    ) -> Result<
        usize, /* Received blocks */
        (
            Slot, /* expected slot */
            Slot, /* received slot */
            &BatchState<T>,
        ),
    > {
        match self.state.poison() {
            BatchState::Downloading(peer, blocks) => {
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

                    if let Some(range) = failed_range {
                        // this is a failed download, register the attempt and check if the batch
                        // can be tried again
                        self.failed_download_attempts.push(peer);
                        self.state = if self.failed_download_attempts.len()
                            >= MAX_BATCH_DOWNLOAD_ATTEMPTS as usize
                        {
                            BatchState::Failed
                        } else {
                            // drop the blocks
                            BatchState::AwaitingDownload
                        };
                        return Err((range.0, range.1, &self.state));
                    }
                }

                let received = blocks.len();
                self.state = BatchState::AwaitingProcessing(peer, blocks);
                Ok(received)
            }
            other => unreachable!("Download completed for batch in wrong state: {:?}", other),
        }
    }

    #[must_use = "Batch may have failed"]
    pub fn download_failed(&mut self) -> &BatchState<T> {
        match self.state.poison() {
            BatchState::Downloading(peer, _) => {
                // register the attempt and check if the batch can be tried again
                self.failed_download_attempts.push(peer);
                self.state = if self.failed_download_attempts.len()
                    >= MAX_BATCH_DOWNLOAD_ATTEMPTS as usize
                {
                    BatchState::Failed
                } else {
                    // drop the blocks
                    BatchState::AwaitingDownload
                };
                &self.state
            }
            other => unreachable!("Download failed for batch in wrong state: {:?}", other),
        }
    }

    pub fn start_downloading_from_peer(&mut self, peer: PeerId) {
        match self.state.poison() {
            BatchState::AwaitingDownload => {
                self.state = BatchState::Downloading(peer, Vec::new());
            }
            other => unreachable!("Starting download for batch in wrong state: {:?}", other),
        }
    }

    pub fn start_processing(&mut self) -> Vec<SignedBeaconBlock<T>> {
        match self.state.poison() {
            BatchState::AwaitingProcessing(peer, blocks) => {
                self.state = BatchState::Processing(Attempt::new(peer, &blocks));
                blocks
            }
            other => unreachable!("Start processing for batch in wrong state: {:?}", other),
        }
    }

    #[must_use = "Batch may have failed"]
    pub fn processing_completed(&mut self, was_sucessful: bool) -> &BatchState<T> {
        match self.state.poison() {
            BatchState::Processing(attempt) => {
                self.state = if !was_sucessful {
                    // register the failed attempt
                    self.failed_processing_attempts.push(attempt);

                    // check if the batch can be downloaded again
                    if self.failed_processing_attempts.len()
                        >= MAX_BATCH_PROCESSING_ATTEMPTS as usize
                    {
                        BatchState::Failed
                    } else {
                        BatchState::AwaitingDownload
                    }
                } else {
                    BatchState::AwaitingValidation(attempt)
                };
                &self.state
            }
            other => unreachable!("Processing completed for batch in wrong state: {:?}", other),
        }
    }

    #[must_use = "Batch may have failed"]
    pub fn validation_failed(&mut self) -> &BatchState<T> {
        match self.state.poison() {
            BatchState::AwaitingValidation(attempt) => {
                self.failed_processing_attempts.push(attempt);

                // check if the batch can be downloaded again
                self.state = if self.failed_processing_attempts.len()
                    >= MAX_BATCH_PROCESSING_ATTEMPTS as usize
                {
                    BatchState::Failed
                } else {
                    BatchState::AwaitingDownload
                };
                &self.state
            }
            other => unreachable!("Validation failed for batch in wrong state: {:?}", other),
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

impl<T: EthSpec> slog::KV for &mut BatchInfo<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::KV::serialize(*self, record, serializer)
    }
}

impl<T: EthSpec> slog::KV for BatchInfo<T> {
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
        serializer.emit_str("state", &format!("{:?}", self.state))?;
        slog::Result::Ok(())
    }
}

impl<T: EthSpec> std::fmt::Debug for BatchState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchState::Processing(_) => f.write_str("Processing"),
            BatchState::AwaitingValidation(_) => f.write_str("AwaitingValidation"),
            BatchState::AwaitingDownload => f.write_str("AwaitingDownload"),
            BatchState::Failed => f.write_str("Failed"),
            BatchState::AwaitingProcessing(ref peer, ref blocks) => {
                write!(f, "AwaitingProcessing({}, {} blocks)", peer, blocks.len())
            }
            BatchState::Downloading(peer, blocks) => {
                write!(f, "Downloading({}, {} blocks)", peer, blocks.len())
            }
            BatchState::Poisoned => f.write_str("Poisoned"),
        }
    }
}
