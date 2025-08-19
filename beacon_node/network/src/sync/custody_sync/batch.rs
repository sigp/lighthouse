use std::{
    collections::HashSet,
    hash::{DefaultHasher, Hash, Hasher},
    ops::Sub,
    time::{Duration, Instant},
};

use crate::sync::BatchOperationOutcome;
use crate::sync::range_sync::BatchProcessingResult;
use lighthouse_network::{PeerId, rpc::methods::DataColumnsByRangeRequest, service::api_types::Id};
use tracing::info;
use types::{ColumnIndex, DataColumnSidecarList, Epoch, EthSpec, Slot};

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: usize = 10;

#[derive(Debug)]
pub struct WrongState(pub(crate) String);

#[derive(Debug)]
pub struct Attempt {
    /// The peer that made the attempt.
    pub peer_id: PeerId,
    /// The hash of the blocks of the attempt.
    pub hash: u64,
}

impl Attempt {
    fn new<E: EthSpec>(peer_id: PeerId, data_columns: &DataColumnSidecarList<E>) -> Self {
        let mut hasher = DefaultHasher::new();
        data_columns.hash(&mut hasher);
        let hash = hasher.finish();
        Attempt { peer_id, hash }
    }
}

#[derive(Debug)]
/// A segment of a chain.
pub struct CustodyBatchInfo<E: EthSpec> {
    /// Start slot of the batch.
    start_slot: Slot,
    /// End slot of the batch.
    end_slot: Slot,
    /// Columns to fetch
    columns: HashSet<ColumnIndex>,
    /// The `Attempts` that have been made and failed to send us this batch.
    failed_processing_attempts: Vec<Attempt>,
    /// Number of processing attempts that have failed but we do not count.
    non_faulty_processing_attempts: u8,
    /// The number of download retries this batch has undergone due to a failed request.
    failed_download_attempts: Vec<Option<PeerId>>,
    /// State of the batch.
    state: CustodyBatchState<E>,
}

impl<E: EthSpec> std::fmt::Display for CustodyBatchInfo<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, End Slot: {}, State: {:?}",
            self.start_slot, self.end_slot, self.state
        )
    }
}

impl<E: EthSpec> CustodyBatchInfo<E> {
    pub fn new(start_epoch: &Epoch, num_of_epochs: u64, columns: HashSet<ColumnIndex>) -> Self {
        let start_slot = start_epoch.start_slot(E::slots_per_epoch());
        let end_slot = start_slot + num_of_epochs * E::slots_per_epoch();
        Self {
            start_slot,
            end_slot,
            columns,
            failed_processing_attempts: Vec::new(),
            failed_download_attempts: Vec::new(),
            non_faulty_processing_attempts: 0,
            state: CustodyBatchState::AwaitingDownload,
        }
    }

    pub fn start_downloading(&mut self, request_id: Id) -> Result<(), WrongState> {
        match self.state.poison() {
            CustodyBatchState::AwaitingDownload => {
                self.state = CustodyBatchState::Downloading(request_id);
                Ok(())
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Starting download for batch in wrong state {:?}",
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
        data_columns: DataColumnSidecarList<E>,
        peer: PeerId,
    ) -> Result<usize /* Received blocks */, WrongState> {
        match self.state.poison() {
            CustodyBatchState::Downloading(_) => {
                let received = data_columns.len();
                self.state =
                    CustodyBatchState::AwaitingProcessing(peer, data_columns, Instant::now());
                Ok(received)
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
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
            CustodyBatchState::Downloading(_) => {
                // register the attempt and check if the batch can be tried again
                self.failed_download_attempts.push(peer);

                self.state = if self.failed_download_attempts.len() >= MAX_BATCH_PROCESSING_ATTEMPTS
                {
                    CustodyBatchState::Failed
                } else {
                    // drop the columns
                    CustodyBatchState::AwaitingDownload
                };
                Ok(self.outcome())
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Download failed for batch in wrong state {:?}",
                    self.state
                )))
            }
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

    /// Returns a DataColumnsByRange request associated with the batch.
    pub fn to_data_columns_by_range_request(&self) -> DataColumnsByRangeRequest {
        DataColumnsByRangeRequest {
            start_slot: self.start_slot.into(),
            count: self.end_slot.sub(self.start_slot).into(),
            columns: self.columns.clone().into_iter().collect(),
        }
    }

    /// After different operations over a batch, this could be in a state that allows it to
    /// continue, or in failed state. When the batch has failed, we check if it did mainly due to
    /// processing failures. In this case the batch is considered failed and faulty.
    pub fn outcome(&self) -> BatchOperationOutcome {
        match self.state {
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
            CustodyBatchState::Failed => BatchOperationOutcome::Failed {
                blacklist: self.failed_processing_attempts.len()
                    > self.failed_download_attempts.len(),
            },
            _ => BatchOperationOutcome::Continue,
        }
    }

    pub fn processing_completed(
        &mut self,
        procesing_result: BatchProcessingResult,
    ) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            CustodyBatchState::Processing(attempt) => {
                self.state = match procesing_result {
                    BatchProcessingResult::Success => {
                        CustodyBatchState::AwaitingValidation(attempt)
                    }
                    BatchProcessingResult::FaultyFailure => {
                        // register the failed attempt
                        self.failed_processing_attempts.push(attempt);

                        // check if the batch can be downloaded again
                        if self.failed_processing_attempts.len() >= MAX_BATCH_PROCESSING_ATTEMPTS {
                            CustodyBatchState::Failed
                        } else {
                            CustodyBatchState::AwaitingDownload
                        }
                    }
                    BatchProcessingResult::NonFaultyFailure => {
                        self.non_faulty_processing_attempts =
                            self.non_faulty_processing_attempts.saturating_add(1);
                        CustodyBatchState::AwaitingDownload
                    }
                };
                Ok(self.outcome())
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Procesing completed for batch in wrong state: {:?}",
                    self.state
                )))
            }
        }
    }

    /// Returns the peer that is currently responsible for progressing the state of the batch.
    pub fn processing_peer(&self) -> Option<&PeerId> {
        match &self.state {
            CustodyBatchState::AwaitingDownload
            | CustodyBatchState::Failed
            | CustodyBatchState::Downloading(..) => None,
            CustodyBatchState::AwaitingProcessing(peer_id, _, _)
            | CustodyBatchState::Processing(Attempt { peer_id, .. })
            | CustodyBatchState::AwaitingValidation(Attempt { peer_id, .. }) => Some(peer_id),
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
        }
    }

    pub fn state(&self) -> &CustodyBatchState<E> {
        &self.state
    }

    pub fn attempts(&self) -> &[Attempt] {
        &self.failed_processing_attempts
    }

    pub fn start_processing(&mut self) -> Result<(DataColumnSidecarList<E>, Duration), WrongState> {
        match self.state.poison() {
            CustodyBatchState::AwaitingProcessing(peer, data_columns, start_instant) => {
                self.state = CustodyBatchState::Processing(Attempt::new::<E>(peer, &data_columns));
                Ok((data_columns, start_instant.elapsed()))
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
            other => {
                self.state = other;
                Err(WrongState(format!(
                    "Starting processing batch in wrong state {:?}",
                    self.state
                )))
            }
        }
    }

    /// Verifies if an incoming column belongs to this batch.
    pub fn is_expecting_data_column(&self, request_id: &Id) -> bool {
        if let CustodyBatchState::Downloading(expected_id) = &self.state {
            return expected_id == request_id;
        }
        false
    }

    #[must_use = "Batch may have failed"]
    pub fn validation_failed(&mut self) -> Result<BatchOperationOutcome, WrongState> {
        match self.state.poison() {
            CustodyBatchState::AwaitingValidation(attempt) => {
                self.failed_processing_attempts.push(attempt);

                // check if the batch can be downloaded again
                self.state =
                    if self.failed_processing_attempts.len() >= MAX_BATCH_PROCESSING_ATTEMPTS {
                        CustodyBatchState::Failed
                    } else {
                        CustodyBatchState::AwaitingDownload
                    };
                Ok(self.outcome())
            }
            CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
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

#[derive(Debug)]
/// Current state of a custody batch
pub enum CustodyBatchState<E: EthSpec> {
    /// The batch has failed either downloading or processing, but can be requested again.
    AwaitingDownload,
    /// The batch is being downloaded.
    Downloading(Id),
    /// The batch has been completely downloaded and is ready for processing.
    AwaitingProcessing(PeerId, DataColumnSidecarList<E>, Instant),
    /// The batch is being processed.
    Processing(Attempt),
    /// The batch was successfully processed and is waiting to be validated.
    AwaitingValidation(Attempt),
    /// Intermediate state for inner state handling.
    Poisoned,
    /// The batch has maxed out the allowed attempts for either downloading or processing. It
    /// cannot be recovered.
    Failed,
}

impl<E: EthSpec> CustodyBatchState<E> {
    /// Helper function for poisoning a state.
    pub fn poison(&mut self) -> CustodyBatchState<E> {
        std::mem::replace(self, CustodyBatchState::<E>::Poisoned)
    }
}
