use crate::sync::manager::{DataColumnsByRootRequester, SingleLookupReqId};
use crate::sync::network_context::DataColumnsByRootSingleBlockRequest;

use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use slog::{debug, warn};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use types::EthSpec;
use types::{data_column_sidecar::ColumnIndex, DataColumnSidecar, Epoch, Hash256};

use super::{LookupRequestResult, PeerGroup, ReqId, RpcResponseResult, SyncNetworkContext};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyId {
    pub requester: CustodyRequester,
    pub req_id: ReqId,
}

/// Downstream components that perform custody by root requests.
/// Currently, it's only single block lookups, so not using an enum
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyRequester(pub SingleLookupReqId);

type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

pub struct ActiveCustodyRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    block_epoch: Epoch,
    custody_id: CustodyId,
    /// List of column indices this request needs to download to complete successfully
    column_requests: FnvHashMap<ColumnIndex, ColumnRequest<T::EthSpec>>,
    /// Active requests for 1 or more columns each
    active_batch_columns_requests: FnvHashMap<ReqId, ActiveBatchColumnsRequest>,
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
}

struct ActiveBatchColumnsRequest {
    indices: Vec<ColumnIndex>,
}

type CustodyRequestResult<E> = Result<Option<(Vec<CustodyDataColumn<E>>, PeerGroup)>, Error>;

impl<T: BeaconChainTypes> ActiveCustodyRequest<T> {
    pub(crate) fn new(
        block_root: Hash256,
        custody_id: CustodyId,
        column_indices: &[ColumnIndex],
        log: slog::Logger,
    ) -> Self {
        Self {
            block_root,
            // TODO(das): use actual epoch if there's rotation
            block_epoch: Epoch::new(0),
            custody_id,
            column_requests: HashMap::from_iter(
                column_indices
                    .iter()
                    .map(|index| (*index, ColumnRequest::new())),
            ),
            active_batch_columns_requests: <_>::default(),
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
    pub(crate) fn on_data_column_downloaded(
        &mut self,
        peer_id: PeerId,
        req_id: ReqId,
        resp: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        // TODO(das): Should downscore peers for verify errors here

        let Some(batch_request) = self.active_batch_columns_requests.get_mut(&req_id) else {
            warn!(self.log,
                "Received custody column response for unrequested index";
                "id" => ?self.custody_id,
                "block_root" => ?self.block_root,
                "req_id" => req_id,
            );
            return Ok(None);
        };

        match resp {
            Ok((data_columns, _seen_timestamp)) => {
                debug!(self.log,
                    "Custody column download success";
                    "id" => ?self.custody_id,
                    "block_root" => ?self.block_root,
                    "req_id" => req_id,
                    "count" => data_columns.len()
                );

                let mut data_columns = HashMap::<ColumnIndex, _>::from_iter(
                    data_columns.into_iter().map(|d| (d.index, d)),
                );
                let mut missing_column_indexes = vec![];

                for column_index in &batch_request.indices {
                    let column_request = self
                        .column_requests
                        .get_mut(column_index)
                        .ok_or(Error::BadState("unknown column_index".to_owned()))?;

                    if let Some(data_column) = data_columns.remove(column_index) {
                        // If on_download_success is successful, we are expecting a columns for this
                        // custody requirement.
                        column_request.on_download_success(
                            peer_id,
                            CustodyDataColumn::from_asserted_custody(data_column),
                        )?;
                    } else {
                        // TODO(das) do not consider this case a success. We know for sure the block has
                        // data. However we allow the peer to return empty as we can't attribute fault.
                        column_request.on_dont_have_data()?;
                        // TODO: Should track which columns are missing and eventually give up
                        missing_column_indexes.push(column_index);
                    }
                }

                // Note: no need to check data_columns is empty, SyncNetworkContext ensures that
                // successful responses only contain requested data.

                if !missing_column_indexes.is_empty() {
                    // Peer does not have the requested data.
                    // Note: Batch logging that columns are missing to not spam logger
                    // TODO(das) what to do?
                    // TODO(das): If the peer is in the lookup peer set it claims to have imported
                    // the block AND its custody columns. So in this case we can downscore
                    debug!(self.log,
                        "Custody column peer claims to not have some data";
                        "id" => ?self.custody_id,
                        "block_root" => ?self.block_root,
                        // TODO(das): this property can become very noisy, being the full range 0..128
                        "missing_column_indexes" => ?missing_column_indexes,
                        "req_id" => req_id,
                    );
                }
            }
            Err(err) => {
                debug!(self.log,
                    "Custody column download error";
                    "id" => ?self.custody_id,
                    "block_root" => ?self.block_root,
                    "req_id" => req_id,
                    "error" => ?err
                );

                // Error downloading, maybe penalize peer and retry again.
                // TODO(das) with different peer or different peer?
                for column_index in &batch_request.indices {
                    self.column_requests
                        .get_mut(column_index)
                        .ok_or(Error::BadState("unknown column_index".to_owned()))?
                        .on_download_error()?;
                }
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
                        .push(data_column.as_data_column().index as usize);
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
            if request.is_awaiting_download() {
                // TODO: When is a fork and only a subset of your peers know about a block, sampling should only
                // be queried on the peers on that fork. Should this case be handled? How to handle it?
                let peer_ids = cx.get_custodial_peers(self.block_epoch, *column_index);

                // TODO(das) randomize custodial peer and avoid failing peers
                let Some(peer_id) = peer_ids.first().cloned() else {
                    // Do not tolerate not having custody peers, hard error.
                    // TODO(das): we might implement some grace period. The request will pause for X
                    // seconds expecting the peer manager to find peers before failing the request.
                    return Err(Error::NoPeers(*column_index));
                };

                columns_to_request_by_peer
                    .entry(peer_id)
                    .or_default()
                    .push(*column_index);
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
                        .insert(req_id, ActiveBatchColumnsRequest { indices });
                }
                LookupRequestResult::NoRequestNeeded => unreachable!(),
                LookupRequestResult::Pending => unreachable!(),
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
    NotStarted,
    Downloading(ReqId),
    Downloaded(PeerId, CustodyDataColumn<E>),
}

impl<E: EthSpec> ColumnRequest<E> {
    fn new() -> Self {
        Self {
            status: Status::NotStarted,
            download_failures: 0,
        }
    }

    fn is_awaiting_download(&self) -> bool {
        match self.status {
            Status::NotStarted => true,
            Status::Downloading { .. } | Status::Downloaded { .. } => false,
        }
    }

    fn is_downloaded(&self) -> bool {
        match self.status {
            Status::NotStarted | Status::Downloading { .. } => false,
            Status::Downloaded { .. } => true,
        }
    }

    fn on_download_start(&mut self, req_id: ReqId) -> Result<(), Error> {
        match self.status.clone() {
            Status::NotStarted => {
                self.status = Status::Downloading(req_id);
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_download_start expected NotStarted got {other:?}"
            ))),
        }
    }

    fn on_download_error(&mut self) -> Result<(), Error> {
        match self.status.clone() {
            Status::Downloading(_) => {
                self.download_failures += 1;
                self.status = Status::NotStarted;
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_sampling_error expected Sampling got {other:?}"
            ))),
        }
    }

    fn on_dont_have_data(&mut self) -> Result<(), Error> {
        // TODO(das): Should track which peers don't have data
        self.on_download_error()
    }

    fn on_download_success(
        &mut self,
        peer_id: PeerId,
        data_column: CustodyDataColumn<E>,
    ) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(_) => {
                self.status = Status::Downloaded(peer_id, data_column);
                Ok(())
            }
            other => Err(Error::BadState(format!(
                "bad state on_sampling_success expected Sampling got {other:?}"
            ))),
        }
    }

    fn complete(self) -> Result<(PeerId, CustodyDataColumn<E>), Error> {
        match self.status {
            Status::Downloaded(peer_id, data_column) => Ok((peer_id, data_column)),
            other => Err(Error::BadState(format!(
                "bad state complete expected Downloaded got {other:?}"
            ))),
        }
    }
}
