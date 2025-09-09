use crate::sync::network_context::{
    DataColumnsByRootRequestId, DataColumnsByRootSingleBlockRequest,
};
use beacon_chain::BeaconChainTypes;
use beacon_chain::validator_monitor::timestamp_now;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::{CustodyId, DataColumnsByRootRequester};
use lighthouse_tracing::SPAN_OUTGOING_CUSTODY_REQUEST;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use tracing::{Span, debug, debug_span, warn};
use types::{DataColumnSidecar, Hash256, data_column_sidecar::ColumnIndex};
use types::{DataColumnSidecarList, EthSpec};

use super::{LookupRequestResult, PeerGroup, RpcResponseResult, SyncNetworkContext};

const MAX_STALE_NO_PEERS_DURATION: Duration = Duration::from_secs(30);

pub struct ActiveCustodyRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    custody_id: CustodyId,
    /// List of column indices this request needs to download to complete successfully
    column_requests: FnvHashMap<ColumnIndex, ColumnRequest<T::EthSpec>>,
    /// Active requests for 1 or more columns each
    active_batch_columns_requests:
        FnvHashMap<DataColumnsByRootRequestId, ActiveBatchColumnsRequest>,
    peer_attempts: HashMap<PeerId, usize>,
    /// Set of peers that claim to have imported this block and their custody columns
    lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Span for tracing the lifetime of this request.
    span: Span,
    _phantom: PhantomData<T>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    SendFailed(&'static str),
    TooManyFailures,
    BadState(String),
    NoPeer(ColumnIndex),
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: DataColumnsByRootRequestId,
        req_id: DataColumnsByRootRequestId,
    },
}

struct ActiveBatchColumnsRequest {
    indices: Vec<ColumnIndex>,
    /// Span for tracing the lifetime of this request.
    span: Span,
}

pub type CustodyRequestResult<E> =
    Result<Option<(DataColumnSidecarList<E>, PeerGroup, Duration)>, Error>;

impl<T: BeaconChainTypes> ActiveCustodyRequest<T> {
    pub(crate) fn new(
        block_root: Hash256,
        custody_id: CustodyId,
        column_indices: &[ColumnIndex],
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
    ) -> Self {
        let span = debug_span!(
            parent: Span::current(),
            SPAN_OUTGOING_CUSTODY_REQUEST,
            %block_root,
        );
        Self {
            block_root,
            custody_id,
            column_requests: HashMap::from_iter(
                column_indices
                    .iter()
                    .map(|index| (*index, ColumnRequest::new())),
            ),
            active_batch_columns_requests: <_>::default(),
            peer_attempts: HashMap::new(),
            lookup_peers,
            span,
            _phantom: PhantomData,
        }
    }

    /// Insert a downloaded column into an active custody request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Err`: Custody request has failed and will be dropped
    /// - `Ok(Some)`: Custody request has successfully completed and will be dropped
    /// - `Ok(None)`: Custody request still active
    pub(crate) fn on_data_column_downloaded(
        &mut self,
        peer_id: PeerId,
        req_id: DataColumnsByRootRequestId,
        resp: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        let Some(batch_request) = self.active_batch_columns_requests.get_mut(&req_id) else {
            warn!(
                block_root = ?self.block_root,
                %req_id,
                "Received custody column response for unrequested index"
            );
            return Ok(None);
        };

        let _guard = batch_request.span.clone().entered();

        match resp {
            Ok((data_columns, seen_timestamp)) => {
                debug!(
                    block_root = ?self.block_root,
                    %req_id,
                    %peer_id,
                    count = data_columns.len(),
                    "Custody column download success"
                );

                // Map columns by index as an optimization to not loop the returned list on each
                // requested index. The worse case is 128 loops over a 128 item vec + mutation to
                // drop the consumed columns.
                let mut data_columns = HashMap::<ColumnIndex, _>::from_iter(
                    data_columns.into_iter().map(|d| (d.index, d)),
                );
                // Accumulate columns that the peer does not have to issue a single log per request
                let mut missing_column_indexes = vec![];

                for column_index in &batch_request.indices {
                    let column_request = self
                        .column_requests
                        .get_mut(column_index)
                        .ok_or(Error::BadState("unknown column_index".to_owned()))?;

                    if let Some(data_column) = data_columns.remove(column_index) {
                        column_request.on_download_success(
                            req_id,
                            peer_id,
                            data_column,
                            seen_timestamp,
                        )?;
                    } else {
                        // Peer does not have the requested data.
                        // TODO(das) do not consider this case a success. We know for sure the block has
                        // data. However we allow the peer to return empty as we can't attribute fault.
                        // TODO(das): Should track which columns are missing and eventually give up
                        // TODO(das): If the peer is in the lookup peer set it claims to have imported
                        // the block AND its custody columns. So in this case we can downscore
                        column_request.on_download_error(req_id)?;
                        missing_column_indexes.push(column_index);
                    }
                }

                // Note: no need to check data_columns is empty, SyncNetworkContext ensures that
                // successful responses only contain requested data.

                if !missing_column_indexes.is_empty() {
                    // Note: Batch logging that columns are missing to not spam logger
                    debug!(
                        block_root = ?self.block_root,
                        %req_id,
                        %peer_id,
                        ?missing_column_indexes,
                        "Custody column peer claims to not have some data"
                    );
                }
            }
            Err(err) => {
                debug!(
                    block_root = ?self.block_root,
                    %req_id,
                   %peer_id,
                   error = ?err,
                    "Custody column download error"
                );

                // TODO(das): Should mark peer as failed and try from another peer
                for column_index in &batch_request.indices {
                    self.column_requests
                        .get_mut(column_index)
                        .ok_or(Error::BadState("unknown column_index".to_owned()))?
                        .on_download_error_and_mark_failure(req_id)?;
                }
            }
        };

        self.continue_requests(cx)
    }

    pub(crate) fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        let _guard = self.span.clone().entered();
        if self.column_requests.values().all(|r| r.is_downloaded()) {
            // All requests have completed successfully.
            let mut peers = HashMap::<PeerId, Vec<usize>>::new();
            let mut seen_timestamps = vec![];
            let columns = std::mem::take(&mut self.column_requests)
                .into_values()
                .map(|request| {
                    let (peer, data_column, seen_timestamp) = request.complete()?;
                    peers
                        .entry(peer)
                        .or_default()
                        .push(data_column.index as usize);
                    seen_timestamps.push(seen_timestamp);
                    Ok(data_column)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let peer_group = PeerGroup::from_set(peers);
            let max_seen_timestamp = seen_timestamps.into_iter().max().unwrap_or(timestamp_now());
            return Ok(Some((columns, peer_group, max_seen_timestamp)));
        }

        let active_request_count_by_peer = cx.active_request_count_by_peer();
        let mut columns_to_request_by_peer = HashMap::<PeerId, Vec<ColumnIndex>>::new();
        let lookup_peers = self.lookup_peers.read();
        // Create deterministic hasher per request to ensure consistent peer ordering within
        // this request (avoiding fragmentation) while varying selection across different requests
        let random_state = RandomState::new();

        for (column_index, request) in self.column_requests.iter() {
            if let Some(wait_duration) = request.is_awaiting_download() {
                // Note: an empty response is considered a successful response, so we may end up
                // retrying many more times than `MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS`.
                if request.download_failures > MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS {
                    return Err(Error::TooManyFailures);
                }

                let peer_to_request = self.select_column_peer(
                    cx,
                    &active_request_count_by_peer,
                    &lookup_peers,
                    *column_index,
                    &random_state,
                );

                if let Some(peer_id) = peer_to_request {
                    columns_to_request_by_peer
                        .entry(peer_id)
                        .or_default()
                        .push(*column_index);
                } else if wait_duration > MAX_STALE_NO_PEERS_DURATION {
                    // Allow to request to sit stale in `NotStarted` state for at most
                    // `MAX_STALE_NO_PEERS_DURATION`, else error and drop the request. Note that
                    // lookup will naturally retry when other peers send us attestations for
                    // descendants of this un-available lookup.
                    return Err(Error::NoPeer(*column_index));
                } else {
                    // Do not issue requests if there is no custody peer on this column
                }
            }
        }

        let peer_requests = columns_to_request_by_peer.len();
        if peer_requests > 0 {
            let columns_requested_count = columns_to_request_by_peer
                .values()
                .map(|v| v.len())
                .sum::<usize>();
            debug!(
                lookup_peers = lookup_peers.len(),
                "Requesting {} columns from {} peers", columns_requested_count, peer_requests,
            );
        } else {
            debug!(
                lookup_peers = lookup_peers.len(),
                "No column peers found for look up",
            );
        }

        for (peer_id, indices) in columns_to_request_by_peer.into_iter() {
            let request_result = cx
                .data_column_lookup_request(
                    DataColumnsByRootRequester::Custody(self.custody_id),
                    peer_id,
                    DataColumnsByRootSingleBlockRequest {
                        block_root: self.block_root,
                        indices: indices.clone(),
                    },
                    // If peer is in the lookup peer set, it claims to have imported the block and
                    // must have its columns in custody. In that case, set `true = enforce max_requests`
                    // and downscore if data_columns_by_root does not returned the expected custody
                    // columns. For the rest of peers, don't downscore if columns are missing.
                    lookup_peers.contains(&peer_id),
                )
                .map_err(Error::SendFailed)?;

            match request_result {
                LookupRequestResult::RequestSent(req_id) => {
                    *self.peer_attempts.entry(peer_id).or_insert(0) += 1;

                    let client = cx.network_globals().client(&peer_id).kind;
                    let batch_columns_req_span = debug_span!(
                        "batch_columns_req",
                        %peer_id,
                        %client,
                    );
                    let _guard = batch_columns_req_span.clone().entered();
                    for column_index in &indices {
                        let column_request = self
                            .column_requests
                            .get_mut(column_index)
                            // Should never happen: column_index is iterated from column_requests
                            .ok_or(Error::BadState("unknown column_index".to_owned()))?;

                        column_request.on_download_start(req_id)?;
                    }

                    self.active_batch_columns_requests.insert(
                        req_id,
                        ActiveBatchColumnsRequest {
                            indices,
                            span: batch_columns_req_span,
                        },
                    );
                }
                LookupRequestResult::NoRequestNeeded(_) => unreachable!(),
                LookupRequestResult::Pending(_) => unreachable!(),
            }
        }

        Ok(None)
    }

    fn select_column_peer(
        &self,
        cx: &mut SyncNetworkContext<T>,
        active_request_count_by_peer: &HashMap<PeerId, usize>,
        lookup_peers: &HashSet<PeerId>,
        column_index: ColumnIndex,
        random_state: &RandomState,
    ) -> Option<PeerId> {
        // We draw from the total set of peers, but prioritize those peers who we have
        // received an attestation or a block from (`lookup_peers`), as the `lookup_peers` may take
        // time to build up and we are likely to not find any column peers initially.
        let custodial_peers = cx.get_custodial_peers(column_index);
        let mut prioritized_peers = custodial_peers
            .iter()
            .filter(|peer| {
                // Exclude peers that we have already made too many attempts to.
                self.peer_attempts.get(peer).copied().unwrap_or(0) <= MAX_CUSTODY_PEER_ATTEMPTS
            })
            .map(|peer| {
                (
                    // Prioritize peers that claim to know have imported this block
                    if lookup_peers.contains(peer) { 0 } else { 1 },
                    // De-prioritize peers that we have already attempted to download from
                    self.peer_attempts.get(peer).copied().unwrap_or(0),
                    // Prefer peers with fewer requests to load balance across peers.
                    active_request_count_by_peer.get(peer).copied().unwrap_or(0),
                    // The hash ensures consistent peer ordering within this request
                    // to avoid fragmentation while varying selection across different requests.
                    random_state.hash_one(peer),
                    *peer,
                )
            })
            .collect::<Vec<_>>();
        prioritized_peers.sort_unstable();

        prioritized_peers
            .first()
            .map(|(_, _, _, _, peer_id)| *peer_id)
    }
}

/// TODO(das): this attempt count is nested into the existing lookup request count.
const MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS: usize = 3;

/// Max number of attempts to request custody columns from a single peer.
const MAX_CUSTODY_PEER_ATTEMPTS: usize = 3;

struct ColumnRequest<E: EthSpec> {
    status: Status<E>,
    download_failures: usize,
}

#[derive(Debug, Clone)]
enum Status<E: EthSpec> {
    NotStarted(Instant),
    Downloading(DataColumnsByRootRequestId),
    Downloaded(PeerId, Arc<DataColumnSidecar<E>>, Duration),
}

impl<E: EthSpec> ColumnRequest<E> {
    fn new() -> Self {
        Self {
            status: Status::NotStarted(Instant::now()),
            download_failures: 0,
        }
    }

    fn is_awaiting_download(&self) -> Option<Duration> {
        match self.status {
            Status::NotStarted(start_time) => Some(start_time.elapsed()),
            Status::Downloading { .. } | Status::Downloaded { .. } => None,
        }
    }

    fn is_downloaded(&self) -> bool {
        match self.status {
            Status::NotStarted { .. } | Status::Downloading { .. } => false,
            Status::Downloaded { .. } => true,
        }
    }

    fn on_download_start(&mut self, req_id: DataColumnsByRootRequestId) -> Result<(), Error> {
        match &self.status {
            Status::NotStarted { .. } => {
                self.status = Status::Downloading(req_id);
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_download_start expected NotStarted got {other:?}"
            ))),
        }
    }

    fn on_download_error(&mut self, req_id: DataColumnsByRootRequestId) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.status = Status::NotStarted(Instant::now());
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_download_error expected Downloading got {other:?}"
            ))),
        }
    }

    fn on_download_error_and_mark_failure(
        &mut self,
        req_id: DataColumnsByRootRequestId,
    ) -> Result<(), Error> {
        // TODO(das): Should track which peers don't have data
        self.download_failures += 1;
        self.on_download_error(req_id)
    }

    fn on_download_success(
        &mut self,
        req_id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        data_column: Arc<DataColumnSidecar<E>>,
        seen_timestamp: Duration,
    ) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.status = Status::Downloaded(peer_id, data_column, seen_timestamp);
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_download_success expected Downloading got {other:?}"
            ))),
        }
    }

    fn complete(self) -> Result<(PeerId, Arc<DataColumnSidecar<E>>, Duration), Error> {
        match self.status {
            Status::Downloaded(peer_id, data_column, seen_timestamp) => {
                Ok((peer_id, data_column, seen_timestamp))
            }
            other => Err(Error::BadState(format!(
                "bad state complete expected Downloaded got {other:?}"
            ))),
        }
    }
}
