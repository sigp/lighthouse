use self::request::ActiveColumnSampleRequest;
#[cfg(test)]
pub(crate) use self::request::Status;
use super::network_context::{
    DataColumnsByRootSingleBlockRequest, RpcResponseError, SyncNetworkContext,
};
use crate::metrics;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::service::api_types::{
    DataColumnsByRootRequester, SamplingId, SamplingRequestId, SamplingRequester,
};
use lighthouse_network::{PeerAction, PeerId};
use rand::{seq::SliceRandom, thread_rng};
use slog::{debug, error, warn};
use std::{
    collections::hash_map::Entry, collections::HashMap, marker::PhantomData, sync::Arc,
    time::Duration,
};
use types::{data_column_sidecar::ColumnIndex, ChainSpec, DataColumnSidecar, Hash256};

pub type SamplingResult = Result<(), SamplingError>;

type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

pub struct Sampling<T: BeaconChainTypes> {
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

    #[cfg(test)]
    pub fn get_request_status(
        &self,
        block_root: Hash256,
        index: &ColumnIndex,
    ) -> Option<self::request::Status> {
        let requester = SamplingRequester::ImportedBlock(block_root);
        self.requests
            .get(&requester)
            .and_then(|req| req.get_request_status(index))
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
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let id = SamplingRequester::ImportedBlock(block_root);

        let request = match self.requests.entry(id) {
            Entry::Vacant(e) => e.insert(ActiveSamplingRequest::new(
                block_root,
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

        debug!(self.log,
            "Created new sample request";
            "id" => ?id,
            "column_selection" => ?request.column_selection()
        );

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
        resp: Result<(DataColumnSidecarList<T::EthSpec>, Duration), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<(SamplingRequester, SamplingResult)> {
        let Some(request) = self.requests.get_mut(&id.id) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Sample downloaded event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request.on_sample_downloaded(peer_id, id.sampling_request_id, resp, cx);
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

        let result = request.on_sample_verified(id.sampling_request_id, result, cx);
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
    requester_id: SamplingRequester,
    column_requests: FnvHashMap<ColumnIndex, ActiveColumnSampleRequest>,
    /// Mapping of column indexes for a sampling request.
    column_indexes_by_sampling_request: FnvHashMap<SamplingRequestId, Vec<ColumnIndex>>,
    /// Sequential ID for sampling requests.
    current_sampling_request_id: SamplingRequestId,
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
            requester_id,
            column_requests: <_>::default(),
            column_indexes_by_sampling_request: <_>::default(),
            current_sampling_request_id: SamplingRequestId(0),
            column_shuffle,
            required_successes: match sampling_config {
                SamplingConfig::Default => REQUIRED_SUCCESSES.to_vec(),
                SamplingConfig::Custom { required_successes } => required_successes.clone(),
            },
            log,
            _phantom: PhantomData,
        }
    }

    #[cfg(test)]
    pub fn get_request_status(&self, index: &ColumnIndex) -> Option<self::request::Status> {
        self.column_requests.get(index).map(|req| req.status())
    }

    /// Return the current ordered list of columns that this requests has to sample to succeed
    pub(crate) fn column_selection(&self) -> Vec<ColumnIndex> {
        self.column_shuffle
            .iter()
            .take(REQUIRED_SUCCESSES[0])
            .copied()
            .collect()
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
        sampling_request_id: SamplingRequestId,
        resp: Result<(DataColumnSidecarList<T::EthSpec>, Duration), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<()>, SamplingError> {
        // Select columns to sample
        // Create individual request per column
        // Progress requests
        // If request fails retry or expand search
        // If all good return
        let Some(column_indexes) = self
            .column_indexes_by_sampling_request
            .get(&sampling_request_id)
        else {
            error!(self.log,
                "Column indexes for the sampling request ID not found";
                "sampling_request_id" => ?sampling_request_id
            );
            return Ok(None);
        };

        match resp {
            Ok((mut resp_data_columns, seen_timestamp)) => {
                let resp_column_indexes = resp_data_columns
                    .iter()
                    .map(|r| r.index)
                    .collect::<Vec<_>>();
                debug!(self.log,
                    "Sample download success";
                    "block_root" => %self.block_root,
                    "column_indexes" => ?resp_column_indexes,
                    "count" => resp_data_columns.len()
                );
                metrics::inc_counter_vec(&metrics::SAMPLE_DOWNLOAD_RESULT, &[metrics::SUCCESS]);

                // Filter the data received in the response using the requested column indexes.
                let mut data_columns = vec![];
                for column_index in column_indexes {
                    let Some(request) = self.column_requests.get_mut(column_index) else {
                        warn!(self.log,
                            "Active column sample request not found";
                            "block_root" => %self.block_root,
                            "column_index" => column_index
                        );
                        continue;
                    };

                    let Some(data_pos) = resp_data_columns
                        .iter()
                        .position(|data| &data.index == column_index)
                    else {
                        // Peer does not have the requested data, mark peer as "dont have" and try
                        // again with a different peer.
                        debug!(self.log,
                            "Sampling peer claims to not have the data";
                            "block_root" => %self.block_root,
                            "column_index" => column_index
                        );
                        request.on_sampling_error()?;
                        continue;
                    };

                    data_columns.push(resp_data_columns.swap_remove(data_pos));
                }

                if !resp_data_columns.is_empty() {
                    let resp_column_indexes = resp_data_columns
                        .iter()
                        .map(|d| d.index)
                        .collect::<Vec<_>>();
                    debug!(self.log,
                        "Received data that was not requested";
                        "block_root" => %self.block_root,
                        "column_indexes" => ?resp_column_indexes
                    );
                }

                // Handle the downloaded data columns.
                if data_columns.is_empty() {
                    debug!(self.log, "Received empty response"; "block_root" => %self.block_root);
                    self.column_indexes_by_sampling_request
                        .remove(&sampling_request_id);
                } else {
                    // Overwrite `column_indexes` with the column indexes received in the response.
                    let column_indexes = data_columns.iter().map(|d| d.index).collect::<Vec<_>>();
                    self.column_indexes_by_sampling_request
                        .insert(sampling_request_id, column_indexes.clone());
                    // Peer has data column, send to verify
                    let Some(beacon_processor) = cx.beacon_processor_if_enabled() else {
                        // If processor is not available, error the entire sampling
                        debug!(self.log,
                            "Dropping sampling";
                            "block" => %self.block_root,
                            "reason" => "beacon processor unavailable"
                        );
                        return Err(SamplingError::ProcessorUnavailable);
                    };
                    debug!(self.log,
                        "Sending data_column for verification";
                        "block" => ?self.block_root,
                        "column_indexes" => ?column_indexes
                    );
                    if let Err(e) = beacon_processor.send_rpc_validate_data_columns(
                        self.block_root,
                        data_columns,
                        seen_timestamp,
                        SamplingId {
                            id: self.requester_id,
                            sampling_request_id,
                        },
                    ) {
                        // Beacon processor is overloaded, drop sampling attempt. Failing to sample
                        // is not a permanent state so we should recover once the node has capacity
                        // and receives a descendant block.
                        error!(self.log,
                            "Dropping sampling";
                            "block" => %self.block_root,
                            "reason" => e.to_string()
                        );
                        return Err(SamplingError::SendFailed("beacon processor send failure"));
                    }
                }
            }
            Err(err) => {
                debug!(self.log, "Sample download error";
                    "block_root" => %self.block_root,
                    "column_indexes" => ?column_indexes,
                    "error" => ?err
                );
                metrics::inc_counter_vec(&metrics::SAMPLE_DOWNLOAD_RESULT, &[metrics::FAILURE]);

                // Error downloading, malicious network errors are already penalized before
                // reaching this function. Mark the peer as failed and try again with another.
                for column_index in column_indexes {
                    let Some(request) = self.column_requests.get_mut(column_index) else {
                        warn!(self.log,
                            "Active column sample request not found";
                            "block_root" => %self.block_root,
                            "column_index" => column_index
                        );
                        continue;
                    };
                    request.on_sampling_error()?;
                }
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
        sampling_request_id: SamplingRequestId,
        result: Result<(), String>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<()>, SamplingError> {
        let Some(column_indexes) = self
            .column_indexes_by_sampling_request
            .get(&sampling_request_id)
        else {
            error!(self.log, "Column indexes for the sampling request ID not found"; "sampling_request_id" => ?sampling_request_id);
            return Ok(None);
        };

        match result {
            Ok(_) => {
                debug!(self.log, "Sample verification success"; "block_root" => %self.block_root, "column_indexes" => ?column_indexes);
                metrics::inc_counter_vec(&metrics::SAMPLE_VERIFY_RESULT, &[metrics::SUCCESS]);

                // Valid, continue_sampling will maybe consider sampling succees
                for column_index in column_indexes {
                    let Some(request) = self.column_requests.get_mut(column_index) else {
                        warn!(
                            self.log,
                            "Active column sample request not found"; "block_root" => %self.block_root, "column_index" => column_index
                        );
                        continue;
                    };
                    request.on_sampling_success()?;
                }
            }
            Err(err) => {
                debug!(self.log, "Sample verification failure"; "block_root" => %self.block_root, "column_indexes" => ?column_indexes, "reason" => ?err);
                metrics::inc_counter_vec(&metrics::SAMPLE_VERIFY_RESULT, &[metrics::FAILURE]);

                // Peer sent invalid data, penalize and try again from different peer
                // TODO(das): Count individual failures
                for column_index in column_indexes {
                    let Some(request) = self.column_requests.get_mut(column_index) else {
                        warn!(
                            self.log,
                            "Active column sample request not found"; "block_root" => %self.block_root, "column_index" => column_index
                        );
                        continue;
                    };
                    let peer_id = request.on_sampling_error()?;
                    cx.report_peer(
                        peer_id,
                        PeerAction::LowToleranceError,
                        "invalid data column",
                    );
                }
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

        // First, attempt to progress sampling by requesting more columns, so that request failures
        // are accounted for below.

        // Group the requested column indexes by the destination peer to batch sampling requests.
        let mut column_indexes_to_request = FnvHashMap::default();
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

            if request.is_ready_to_request() {
                if let Some(peer_id) = request.choose_peer(cx) {
                    let indexes = column_indexes_to_request.entry(peer_id).or_insert(vec![]);
                    indexes.push(column_index);
                }
            }
        }

        // Send requests.
        let mut sent_request = false;
        for (peer_id, column_indexes) in column_indexes_to_request {
            cx.data_column_lookup_request(
                DataColumnsByRootRequester::Sampling(SamplingId {
                    id: self.requester_id,
                    sampling_request_id: self.current_sampling_request_id,
                }),
                peer_id,
                DataColumnsByRootSingleBlockRequest {
                    block_root: self.block_root,
                    indices: column_indexes.clone(),
                },
                // false = We issue request to custodians who may or may not have received the
                // samples yet. We don't any signal (like an attestation or status messages that the
                // custodian has received data).
                false,
            )
            .map_err(SamplingError::SendFailed)?;
            self.column_indexes_by_sampling_request
                .insert(self.current_sampling_request_id, column_indexes.clone());
            self.current_sampling_request_id.0 += 1;
            sent_request = true;

            // Update request status.
            for column_index in column_indexes {
                let Some(request) = self.column_requests.get_mut(&column_index) else {
                    continue;
                };
                request.on_start_sampling(peer_id)?;
            }
        }

        // Make sure that sampling doesn't stall, by ensuring that this sampling request will
        // receive a new event of some type. If there are no ongoing requests, and no new
        // request was sent, loop to increase the required_successes until the sampling fails if
        // there are no peers.
        if ongoings == 0 && !sent_request {
            debug!(self.log, "Sampling request stalled"; "block_root" => %self.block_root);
        }

        Ok(None)
    }
}

mod request {
    use super::SamplingError;
    use crate::sync::network_context::SyncNetworkContext;
    use beacon_chain::BeaconChainTypes;
    use lighthouse_network::PeerId;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use std::collections::HashSet;
    use types::data_column_sidecar::ColumnIndex;

    pub(crate) struct ActiveColumnSampleRequest {
        column_index: ColumnIndex,
        status: Status,
        // TODO(das): Should downscore peers that claim to not have the sample?
        peers_dont_have: HashSet<PeerId>,
    }

    // Exposed only for testing assertions in lookup tests
    #[derive(Debug, Clone)]
    pub(crate) enum Status {
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

        pub(crate) fn is_ready_to_request(&self) -> bool {
            match self.status {
                Status::NoPeers | Status::NotStarted => true,
                Status::Sampling(_) | Status::Verified => false,
            }
        }

        #[cfg(test)]
        pub(crate) fn status(&self) -> Status {
            self.status.clone()
        }

        pub(crate) fn choose_peer<T: BeaconChainTypes>(
            &mut self,
            cx: &SyncNetworkContext<T>,
        ) -> Option<PeerId> {
            // TODO: When is a fork and only a subset of your peers know about a block, sampling should only
            // be queried on the peers on that fork. Should this case be handled? How to handle it?
            let mut peer_ids = cx.get_custodial_peers(self.column_index);

            peer_ids.retain(|peer_id| !self.peers_dont_have.contains(peer_id));

            if let Some(peer_id) = peer_ids.choose(&mut thread_rng()) {
                Some(*peer_id)
            } else {
                self.status = Status::NoPeers;
                None
            }
        }

        pub(crate) fn on_start_sampling(&mut self, peer_id: PeerId) -> Result<(), SamplingError> {
            match self.status.clone() {
                Status::NoPeers | Status::NotStarted => {
                    self.status = Status::Sampling(peer_id);
                    Ok(())
                }
                other => Err(SamplingError::BadState(format!(
                    "bad state on_start_sampling expected NoPeers|NotStarted got {other:?}. column_index:{}",
                    self.column_index
                ))),
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
                    "bad state on_sampling_error expected Sampling got {other:?}. column_index:{}",
                    self.column_index
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
                    "bad state on_sampling_success expected Sampling got {other:?}. column_index:{}",
                    self.column_index
                ))),
            }
        }
    }
}
