use self::request::ActiveColumnSampleRequest;
use super::network_context::{RpcResponseError, SyncNetworkContext};
use crate::metrics;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::{PeerAction, PeerId};
use rand::{seq::SliceRandom, thread_rng};
use slog::{debug, error, warn};
use std::{
    collections::hash_map::Entry, collections::HashMap, marker::PhantomData, sync::Arc,
    time::Duration,
};
use types::{data_column_sidecar::ColumnIndex, ChainSpec, DataColumnSidecar, Hash256, Slot};

pub type SamplingResult = Result<(), SamplingError>;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SamplingId {
    pub id: SamplingRequester,
    pub column_index: ColumnIndex,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum SamplingRequester {
    ImportedBlock(Hash256),
}

type DataColumnSidecarVec<E> = Vec<Arc<DataColumnSidecar<E>>>;

pub struct Sampling<T: BeaconChainTypes> {
    // TODO(das): stalled sampling request are never cleaned up
    requests: HashMap<SamplingRequester, ActiveSamplingRequest<T>>,
    sampling_config: SamplingConfig,
    log: slog::Logger,
}

impl<T: BeaconChainTypes> Sampling<T> {
    pub fn new(sampling_config: SamplingConfig, log: slog::Logger) -> Self {
        Self {
            requests: <_>::default(),
            sampling_config,
            log,
        }
    }

    #[cfg(test)]
    pub fn active_sampling_requests(&self) -> Vec<Hash256> {
        self.requests.values().map(|r| r.block_root).collect()
    }

    /// Create a new sampling request for a known block
    ///
    /// ### Returns
    ///
    /// - `Some`: Request completed, won't make more progress. Expect requester to act on the result.
    /// - `None`: Request still active, requester should do no action
    pub fn on_new_sample_request(
        &mut self,
        block_root: Hash256,
        block_slot: Slot,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let id = SamplingRequester::ImportedBlock(block_root);

        let request = match self.requests.entry(id) {
            Entry::Vacant(e) => e.insert(ActiveSamplingRequest::new(
                block_root,
                block_slot,
                id,
                &self.sampling_config,
                self.log.clone(),
                &cx.chain.spec,
            )),
            Entry::Occupied(_) => {
                // Sampling is triggered from multiple sources, duplicate sampling requests are
                // likely (gossip block + gossip data column)
                // TODO(das): Should track failed sampling request for some time? Otherwise there's
                // a risk of a loop with multiple triggers creating the request, then failing,
                // and repeat.
                debug!(self.log, "Ignoring duplicate sampling request"; "id" => ?id);
                return None;
            }
        };

        debug!(self.log, "Created new sample request"; "id" => ?id);

        // TOOD(das): If a node has very little peers, continue_sampling() will attempt to find enough
        // to sample here, immediately failing the sampling request. There should be some grace
        // period to allow the peer manager to find custody peers.
        let result = request.continue_sampling(cx);
        self.handle_sampling_result(result, &id)
    }

    /// Insert a downloaded column into an active sampling request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Some`: Request completed, won't make more progress. Expect requester to act on the result.
    /// - `None`: Request still active, requester should do no action
    pub fn on_sample_downloaded(
        &mut self,
        id: SamplingId,
        peer_id: PeerId,
        resp: Result<(DataColumnSidecarVec<T::EthSpec>, Duration), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let Some(request) = self.requests.get_mut(&id.id) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Sample downloaded event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request.on_sample_downloaded(peer_id, id.column_index, resp, cx);
        self.handle_sampling_result(result, &id.id)
    }

    /// Insert a downloaded column into an active sampling request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Some`: Request completed, won't make more progress. Expect requester to act on the result.
    /// - `None`: Request still active, requester should do no action
    pub fn on_sample_verified(
        &mut self,
        id: SamplingId,
        result: Result<(), String>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let Some(request) = self.requests.get_mut(&id.id) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Sample verified event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request.on_sample_verified(id.column_index, result, cx);
        self.handle_sampling_result(result, &id.id)
    }

    /// Converts a result from the internal format of `ActiveSamplingRequest` (error first to use ?
    /// conveniently), to an Option first format to use an `if let Some() { act on result }` pattern
    /// in the sync manager.
    fn handle_sampling_result(
        &mut self,
        result: Result<Option<()>, SamplingError>,
        id: &SamplingRequester,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let result = result.transpose();
        if let Some(result) = result {
            debug!(self.log, "Sampling request completed, removing"; "id" => ?id, "result" => ?result);
            metrics::inc_counter_vec(
                &metrics::SAMPLING_REQUEST_RESULT,
                &[metrics::from_result(&result)],
            );
            self.requests.remove(id);
            Some((*id, result))
        } else {
            None
        }
    }
}

pub struct ActiveSamplingRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    block_slot: Slot,
    requester_id: SamplingRequester,
    column_requests: FnvHashMap<ColumnIndex, ActiveColumnSampleRequest>,
    column_shuffle: Vec<ColumnIndex>,
    required_successes: Vec<usize>,
    /// Logger for the `SyncNetworkContext`.
    pub log: slog::Logger,
    _phantom: PhantomData<T>,
}

#[derive(Debug)]
pub enum SamplingError {
    SendFailed(#[allow(dead_code)] &'static str),
    ProcessorUnavailable,
    TooManyFailures,
    BadState(#[allow(dead_code)] String),
    ColumnIndexOutOfBounds,
}

/// Required success index by current failures, with p_target=5.00E-06
/// Ref: https://colab.research.google.com/drive/18uUgT2i-m3CbzQ5TyP9XFKqTn1DImUJD#scrollTo=E82ITcgB5ATh
const REQUIRED_SUCCESSES: [usize; 11] = [16, 20, 23, 26, 29, 32, 34, 37, 39, 42, 44];

#[derive(Debug, Clone)]
pub enum SamplingConfig {
    Default,
    #[allow(dead_code)]
    Custom {
        required_successes: Vec<usize>,
    },
}

impl<T: BeaconChainTypes> ActiveSamplingRequest<T> {
    fn new(
        block_root: Hash256,
        block_slot: Slot,
        requester_id: SamplingRequester,
        sampling_config: &SamplingConfig,
        log: slog::Logger,
        spec: &ChainSpec,
    ) -> Self {
        // Select ahead of time the full list of to-sample columns
        let mut column_shuffle =
            (0..spec.number_of_columns as ColumnIndex).collect::<Vec<ColumnIndex>>();
        let mut rng = thread_rng();
        column_shuffle.shuffle(&mut rng);

        Self {
            block_root,
            block_slot,
            requester_id,
            column_requests: <_>::default(),
            column_shuffle,
            required_successes: match sampling_config {
                SamplingConfig::Default => REQUIRED_SUCCESSES.to_vec(),
                SamplingConfig::Custom { required_successes } => required_successes.clone(),
            },
            log,
            _phantom: PhantomData,
        }
    }

    /// Insert a downloaded column into an active sampling request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Err`: Sampling request has failed and will be dropped
    /// - `Ok(Some)`: Sampling request has successfully completed and will be dropped
    /// - `Ok(None)`: Sampling request still active
    pub(crate) fn on_sample_downloaded(
        &mut self,
        _peer_id: PeerId,
        column_index: ColumnIndex,
        resp: Result<(DataColumnSidecarVec<T::EthSpec>, Duration), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<()>, SamplingError> {
        // Select columns to sample
        // Create individual request per column
        // Progress requests
        // If request fails retry or expand search
        // If all good return
        let Some(request) = self.column_requests.get_mut(&column_index) else {
            warn!(
                self.log,
                "Received sampling response for unrequested column index"
            );
            return Ok(None);
        };

        match resp {
            Ok((mut data_columns, seen_timestamp)) => {
                debug!(self.log, "Sample download success"; "block_root" => %self.block_root, "column_index" => column_index, "count" => data_columns.len());
                metrics::inc_counter_vec(&metrics::SAMPLE_DOWNLOAD_RESULT, &[metrics::SUCCESS]);

                // No need to check data_columns has len > 1, as the SyncNetworkContext ensure that
                // only requested is returned (or none);
                if let Some(data_column) = data_columns.pop() {
                    // Peer has data column, send to verify
                    let Some(beacon_processor) = cx.beacon_processor_if_enabled() else {
                        // If processor is not available, error the entire sampling
                        debug!(self.log, "Dropping sampling"; "block" => %self.block_root, "reason" => "beacon processor unavailable");
                        return Err(SamplingError::ProcessorUnavailable);
                    };

                    debug!(self.log, "Sending data_column for verification"; "block" => ?self.block_root, "column_index" => column_index);
                    if let Err(e) = beacon_processor.send_rpc_validate_data_columns(
                        self.block_root,
                        vec![data_column],
                        seen_timestamp,
                        SamplingId {
                            id: self.requester_id,
                            column_index,
                        },
                    ) {
                        // TODO(das): Beacon processor is overloaded, what should we do?
                        error!(self.log, "Dropping sampling"; "block" => %self.block_root, "reason" => e.to_string());
                        return Err(SamplingError::SendFailed("beacon processor send failure"));
                    }
                } else {
                    // Peer does not have the requested data.
                    // TODO(das) what to do?
                    debug!(self.log, "Sampling peer claims to not have the data"; "block_root" => %self.block_root, "column_index" => column_index);
                    request.on_sampling_error()?;
                }
            }
            Err(err) => {
                debug!(self.log, "Sample download error"; "block_root" => %self.block_root, "column_index" => column_index, "error" => ?err);
                metrics::inc_counter_vec(&metrics::SAMPLE_DOWNLOAD_RESULT, &[metrics::FAILURE]);

                // Error downloading, maybe penalize peer and retry again.
                // TODO(das) with different peer or different peer?
                request.on_sampling_error()?;
            }
        };

        self.continue_sampling(cx)
    }

    /// Insert a column verification result into an active sampling request. Then make progress
    /// on the entire request.
    ///
    /// ### Returns
    ///
    /// - `Err`: Sampling request has failed and will be dropped
    /// - `Ok(Some)`: Sampling request has successfully completed and will be dropped
    /// - `Ok(None)`: Sampling request still active
    pub(crate) fn on_sample_verified(
        &mut self,
        column_index: ColumnIndex,
        result: Result<(), String>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<()>, SamplingError> {
        // Select columns to sample
        // Create individual request per column
        // Progress requests
        // If request fails retry or expand search
        // If all good return
        let Some(request) = self.column_requests.get_mut(&column_index) else {
            warn!(
                self.log,
                "Received sampling response for unrequested column index"
            );
            return Ok(None);
        };

        match result {
            Ok(_) => {
                debug!(self.log, "Sample verification success"; "block_root" => %self.block_root, "column_index" => column_index);
                metrics::inc_counter_vec(&metrics::SAMPLE_VERIFY_RESULT, &[metrics::SUCCESS]);

                // Valid, continue_sampling will maybe consider sampling succees
                request.on_sampling_success()?;
            }
            Err(err) => {
                debug!(self.log, "Sample verification failure"; "block_root" => %self.block_root, "column_index" => column_index, "reason" => ?err);
                metrics::inc_counter_vec(&metrics::SAMPLE_VERIFY_RESULT, &[metrics::FAILURE]);

                // TODO(das): Peer sent invalid data, penalize and try again from different peer
                // TODO(das): Count individual failures
                let peer_id = request.on_sampling_error()?;
                cx.report_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "invalid data column",
                );
            }
        }

        self.continue_sampling(cx)
    }

    pub(crate) fn continue_sampling(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<()>, SamplingError> {
        // First check if sampling is completed, by computing `required_successes`
        let mut successes = 0;
        let mut failures = 0;
        let mut ongoings = 0;

        for request in self.column_requests.values() {
            if request.is_completed() {
                successes += 1;
            }
            if request.is_failed() {
                failures += 1;
            }
            if request.is_ongoing() {
                ongoings += 1;
            }
        }

        // If there are too many failures, consider the sampling failed
        let Some(required_successes) = self.required_successes.get(failures) else {
            return Err(SamplingError::TooManyFailures);
        };

        // If there are enough successes, consider the sampling complete
        if successes >= *required_successes {
            return Ok(Some(()));
        }

        let mut sent_requests = 0;

        // First, attempt to progress sampling by requesting more columns, so that request failures
        // are accounted for below.
        for idx in 0..*required_successes {
            // Re-request columns. Note: out of bounds error should never happen, inputs are hardcoded
            let column_index = *self
                .column_shuffle
                .get(idx)
                .ok_or(SamplingError::ColumnIndexOutOfBounds)?;
            let request = self
                .column_requests
                .entry(column_index)
                .or_insert(ActiveColumnSampleRequest::new(column_index));

            if request.request(self.block_root, self.block_slot, self.requester_id, cx)? {
                sent_requests += 1
            }
        }

        // Make sure that sampling doesn't stall, by ensuring that this sampling request will
        // receive a new event of some type. If there are no ongoing requests, and no new
        // request was sent, loop to increase the required_successes until the sampling fails if
        // there are no peers.
        if ongoings == 0 && sent_requests == 0 {
            debug!(self.log, "Sampling request stalled"; "block_root" => %self.block_root);
        }

        Ok(None)
    }
}

mod request {
    use super::{SamplingError, SamplingId, SamplingRequester};
    use crate::sync::{
        manager::DataColumnsByRootRequester,
        network_context::{DataColumnsByRootSingleBlockRequest, SyncNetworkContext},
    };
    use beacon_chain::BeaconChainTypes;
    use lighthouse_network::PeerId;
    use std::collections::HashSet;
    use types::{data_column_sidecar::ColumnIndex, EthSpec, Hash256, Slot};

    pub(crate) struct ActiveColumnSampleRequest {
        column_index: ColumnIndex,
        status: Status,
        // TODO(das): Should downscore peers that claim to not have the sample?
        peers_dont_have: HashSet<PeerId>,
    }

    #[derive(Debug, Clone)]
    enum Status {
        NoPeers,
        NotStarted,
        Sampling(PeerId),
        Verified,
    }

    impl ActiveColumnSampleRequest {
        pub(crate) fn new(column_index: ColumnIndex) -> Self {
            Self {
                column_index,
                status: Status::NotStarted,
                peers_dont_have: <_>::default(),
            }
        }

        pub(crate) fn is_completed(&self) -> bool {
            match self.status {
                Status::NoPeers | Status::NotStarted | Status::Sampling(_) => false,
                Status::Verified => true,
            }
        }

        pub(crate) fn is_failed(&self) -> bool {
            match self.status {
                Status::NotStarted | Status::Sampling(_) | Status::Verified => false,
                Status::NoPeers => true,
            }
        }

        pub(crate) fn is_ongoing(&self) -> bool {
            match self.status {
                Status::NotStarted | Status::NoPeers | Status::Verified => false,
                Status::Sampling(_) => true,
            }
        }

        pub(crate) fn request<T: BeaconChainTypes>(
            &mut self,
            block_root: Hash256,
            block_slot: Slot,
            requester: SamplingRequester,
            cx: &mut SyncNetworkContext<T>,
        ) -> Result<bool, SamplingError> {
            match &self.status {
                Status::NoPeers | Status::NotStarted => {} // Ok to continue
                Status::Sampling(_) => return Ok(false),   // Already downloading
                Status::Verified => return Ok(false),      // Already completed
            }

            // TODO: When is a fork and only a subset of your peers know about a block, sampling should only
            // be queried on the peers on that fork. Should this case be handled? How to handle it?
            let mut peer_ids = cx.get_custodial_peers(
                block_slot.epoch(<T::EthSpec as EthSpec>::slots_per_epoch()),
                self.column_index,
            );

            peer_ids.retain(|peer_id| !self.peers_dont_have.contains(peer_id));

            // TODO(das) randomize custodial peer and avoid failing peers
            if let Some(peer_id) = peer_ids.first().cloned() {
                cx.data_column_lookup_request(
                    DataColumnsByRootRequester::Sampling(SamplingId {
                        id: requester,
                        column_index: self.column_index,
                    }),
                    peer_id,
                    DataColumnsByRootSingleBlockRequest {
                        block_root,
                        indices: vec![self.column_index],
                    },
                )
                .map_err(SamplingError::SendFailed)?;

                self.status = Status::Sampling(peer_id);
                Ok(true)
            } else {
                self.status = Status::NoPeers;
                Ok(false)
            }
        }

        pub(crate) fn on_sampling_error(&mut self) -> Result<PeerId, SamplingError> {
            match self.status.clone() {
                Status::Sampling(peer_id) => {
                    self.peers_dont_have.insert(peer_id);
                    self.status = Status::NotStarted;
                    Ok(peer_id)
                }
                other => Err(SamplingError::BadState(format!(
                    "bad state on_sampling_error expected Sampling got {other:?}"
                ))),
            }
        }

        pub(crate) fn on_sampling_success(&mut self) -> Result<(), SamplingError> {
            match &self.status {
                Status::Sampling(_) => {
                    self.status = Status::Verified;
                    Ok(())
                }
                other => Err(SamplingError::BadState(format!(
                    "bad state on_sampling_success expected Sampling got {other:?}"
                ))),
            }
        }
    }
}
