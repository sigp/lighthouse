use crate::sync::network_context::{
    DataColumnsByRootRequestId, DataColumnsByRootSingleBlockRequest,
};

use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::service::api_types::{CustodyId, DataColumnsByRootRequester};
use lighthouse_network::PeerId;
use lru_cache::LRUTimeCache;
use rand::Rng;
use slog::{debug, warn};
use std::time::{Duration, Instant};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use types::EthSpec;
use types::{data_column_sidecar::ColumnIndex, DataColumnSidecar, Hash256};

use super::{LookupRequestResult, PeerGroup, RpcResponseResult, SyncNetworkContext};

const FAILED_PEERS_CACHE_EXPIRY_SECONDS: u64 = 5;
const MAX_STALE_NO_PEERS_DURATION: Duration = Duration::from_secs(30);

type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

pub struct ActiveCustodyRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    custody_id: CustodyId,
    /// List of column indices this request needs to download to complete successfully
    column_requests: FnvHashMap<ColumnIndex, ColumnRequest<T::EthSpec>>,
    /// Active requests for 1 or more columns each
    active_batch_columns_requests:
        FnvHashMap<DataColumnsByRootRequestId, ActiveBatchColumnsRequest>,
    /// Peers that have recently failed to successfully respond to a columns by root request.
    /// Having a LRUTimeCache allows this request to not have to track disconnecting peers.
    failed_peers: LRUTimeCache<PeerId>,
    /// Logger for the `SyncNetworkContext`.
    pub log: slog::Logger,
    _phantom: PhantomData<T>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    SendFailed(&'static str),
    TooManyFailures,
    BadState(String),
    NoPeers(ColumnIndex),
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: DataColumnsByRootRequestId,
        req_id: DataColumnsByRootRequestId,
    },
}

struct ActiveBatchColumnsRequest {
    peer_id: PeerId,
    indices: Vec<ColumnIndex>,
}

pub type CustodyRequestResult<E> = Result<Option<(DataColumnSidecarList<E>, PeerGroup)>, Error>;

impl<T: BeaconChainTypes> ActiveCustodyRequest<T> {
    pub(crate) fn new(
        block_root: Hash256,
        custody_id: CustodyId,
        column_indices: &[ColumnIndex],
        log: slog::Logger,
    ) -> Self {
        Self {
            block_root,
            custody_id,
            column_requests: HashMap::from_iter(
                column_indices
                    .iter()
                    .map(|index| (*index, ColumnRequest::new())),
            ),
            active_batch_columns_requests: <_>::default(),
            failed_peers: LRUTimeCache::new(Duration::from_secs(FAILED_PEERS_CACHE_EXPIRY_SECONDS)),
            log,
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
        // TODO(das): Should downscore peers for verify errors here

        let Some(batch_request) = self.active_batch_columns_requests.get_mut(&req_id) else {
            warn!(self.log,
                "Received custody column response for unrequested index";
                "id" => ?self.custody_id,
                "block_root" => ?self.block_root,
                "req_id" => %req_id,
            );
            return Ok(None);
        };

        match resp {
            Ok((data_columns, _seen_timestamp)) => {
                debug!(self.log,
                    "Custody column download success";
                    "id" => ?self.custody_id,
                    "block_root" => ?self.block_root,
                    "req_id" => %req_id,
                    "peer" => %peer_id,
                    "count" => data_columns.len()
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
                        column_request.on_download_success(req_id, peer_id, data_column)?;
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
                    debug!(self.log,
                        "Custody column peer claims to not have some data";
                        "id" => ?self.custody_id,
                        "block_root" => ?self.block_root,
                        "req_id" => %req_id,
                        "peer" => %peer_id,
                        // TODO(das): this property can become very noisy, being the full range 0..128
                        "missing_column_indexes" => ?missing_column_indexes
                    );

                    self.failed_peers.insert(peer_id);
                }
            }
            Err(err) => {
                debug!(self.log,
                    "Custody column download error";
                    "id" => ?self.custody_id,
                    "block_root" => ?self.block_root,
                    "req_id" => %req_id,
                    "peer" => %peer_id,
                    "error" => ?err
                );

                // TODO(das): Should mark peer as failed and try from another peer
                for column_index in &batch_request.indices {
                    self.column_requests
                        .get_mut(column_index)
                        .ok_or(Error::BadState("unknown column_index".to_owned()))?
                        .on_download_error_and_mark_failure(req_id)?;
                }

                self.failed_peers.insert(peer_id);
            }
        };

        self.continue_requests(cx)
    }

    pub(crate) fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        if self.column_requests.values().all(|r| r.is_downloaded()) {
            // All requests have completed successfully.
            let mut peers = HashMap::<PeerId, Vec<usize>>::new();
            let columns = std::mem::take(&mut self.column_requests)
                .into_values()
                .map(|request| {
                    let (peer, data_column) = request.complete()?;
                    peers
                        .entry(peer)
                        .or_default()
                        .push(data_column.index as usize);
                    Ok(data_column)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let peer_group = PeerGroup::from_set(peers);
            return Ok(Some((columns, peer_group)));
        }

        let mut columns_to_request_by_peer = HashMap::<PeerId, Vec<ColumnIndex>>::new();

        // Need to:
        // - track how many active requests a peer has for load balancing
        // - which peers have failures to attempt others
        // - which peer returned what to have PeerGroup attributability

        for (column_index, request) in self.column_requests.iter_mut() {
            if let Some(wait_duration) = request.is_awaiting_download() {
                if request.download_failures > MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS {
                    return Err(Error::TooManyFailures);
                }

                // TODO(das): When is a fork and only a subset of your peers know about a block, we should
                // only query the peers on that fork. Should this case be handled? How to handle it?
                let custodial_peers = cx.get_custodial_peers(*column_index);

                // TODO(das): cache this computation in a OneCell or similar to prevent having to
                // run it every loop
                let mut active_requests_by_peer = HashMap::<PeerId, usize>::new();
                for batch_request in self.active_batch_columns_requests.values() {
                    *active_requests_by_peer
                        .entry(batch_request.peer_id)
                        .or_default() += 1;
                }

                let mut priorized_peers = custodial_peers
                    .iter()
                    .map(|peer| {
                        (
                            // De-prioritize peers that have failed to successfully respond to
                            // requests recently
                            self.failed_peers.contains(peer),
                            // Prefer peers with less requests to load balance across peers
                            active_requests_by_peer.get(peer).copied().unwrap_or(0),
                            // Final random factor to give all peers a shot in each retry
                            rand::thread_rng().gen::<u32>(),
                            *peer,
                        )
                    })
                    .collect::<Vec<_>>();
                priorized_peers.sort_unstable();

                if let Some((_, _, _, peer_id)) = priorized_peers.first() {
                    columns_to_request_by_peer
                        .entry(*peer_id)
                        .or_default()
                        .push(*column_index);
                } else if wait_duration > MAX_STALE_NO_PEERS_DURATION {
                    // Allow to request to sit stale in `NotStarted` state for at most
                    // `MAX_STALE_NO_PEERS_DURATION`, else error and drop the request. Note that
                    // lookup will naturally retry when other peers send us attestations for
                    // descendants of this un-available lookup.
                    return Err(Error::NoPeers(*column_index));
                } else {
                    // Do not issue requests if there is no custody peer on this column
                }
            }
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
                    // true = enforce max_requests are returned data_columns_by_root. We only issue requests
                    // for blocks after we know the block has data, and only request peers after they claim to
                    // have imported the block+columns and claim to be custodians
                    true,
                )
                .map_err(Error::SendFailed)?;

            match request_result {
                LookupRequestResult::RequestSent(req_id) => {
                    for column_index in &indices {
                        let column_request = self
                            .column_requests
                            .get_mut(column_index)
                            .ok_or(Error::BadState("unknown column_index".to_owned()))?;

                        column_request.on_download_start(req_id)?;
                    }

                    self.active_batch_columns_requests
                        .insert(req_id, ActiveBatchColumnsRequest { indices, peer_id });
                }
                LookupRequestResult::NoRequestNeeded(_) => unreachable!(),
                LookupRequestResult::Pending(_) => unreachable!(),
            }
        }

        Ok(None)
    }
}

/// TODO(das): this attempt count is nested into the existing lookup request count.
const MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS: usize = 3;

struct ColumnRequest<E: EthSpec> {
    status: Status<E>,
    download_failures: usize,
}

#[derive(Debug, Clone)]
enum Status<E: EthSpec> {
    NotStarted(Instant),
    Downloading(DataColumnsByRootRequestId),
    Downloaded(PeerId, Arc<DataColumnSidecar<E>>),
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
    ) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.status = Status::Downloaded(peer_id, data_column);
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_download_success expected Downloading got {other:?}"
            ))),
        }
    }

    fn complete(self) -> Result<(PeerId, Arc<DataColumnSidecar<E>>), Error> {
        match self.status {
            Status::Downloaded(peer_id, data_column) => Ok((peer_id, data_column)),
            other => Err(Error::BadState(format!(
                "bad state complete expected Downloaded got {other:?}"
            ))),
        }
    }
}
