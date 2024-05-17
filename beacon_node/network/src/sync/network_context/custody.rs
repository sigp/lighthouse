use crate::sync::manager::SingleLookupReqId;

use self::request::ActiveColumnSampleRequest;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use slog::{debug, warn};
use std::{marker::PhantomData, sync::Arc};
use types::{data_column_sidecar::ColumnIndex, DataColumnSidecar, Epoch, Hash256};

use super::{PeerGroup, RpcResponseResult, SyncNetworkContext};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyId {
    pub id: CustodyRequester,
    pub column_index: ColumnIndex,
}

/// Downstream components that perform custody by root requests.
/// Currently, it's only single block lookups, so not using an enum
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyRequester(pub SingleLookupReqId);

type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

pub struct ActiveCustodyRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    block_epoch: Epoch,
    requester_id: CustodyRequester,
    column_requests: FnvHashMap<ColumnIndex, ActiveColumnSampleRequest>,
    columns: Vec<CustodyDataColumn<T::EthSpec>>,
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

type CustodyRequestResult<E> = Result<Option<(Vec<CustodyDataColumn<E>>, PeerGroup)>, Error>;

impl<T: BeaconChainTypes> ActiveCustodyRequest<T> {
    pub(crate) fn new(
        block_root: Hash256,
        requester_id: CustodyRequester,
        column_indexes: Vec<ColumnIndex>,
        log: slog::Logger,
    ) -> Self {
        Self {
            block_root,
            // TODO(das): use actual epoch if there's rotation
            block_epoch: Epoch::new(0),
            requester_id,
            column_requests: column_indexes
                .into_iter()
                .map(|index| (index, ActiveColumnSampleRequest::new(index)))
                .collect(),
            columns: vec![],
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
        _peer_id: PeerId,
        column_index: ColumnIndex,
        resp: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        // TODO(das): Should downscore peers for verify errors here

        let Some(request) = self.column_requests.get_mut(&column_index) else {
            warn!(
                self.log,
                "Received sampling response for unrequested column index"
            );
            return Ok(None);
        };

        match resp {
            Ok((mut data_columns, _seen_timestamp)) => {
                debug!(self.log, "Sample download success"; "block_root" => %self.block_root, "column_index" => column_index, "count" => data_columns.len());

                // No need to check data_columns has len > 1, as the SyncNetworkContext ensure that
                // only requested is returned (or none);
                if let Some(data_column) = data_columns.pop() {
                    request.on_download_success()?;

                    // If on_download_success is successful, we are expecting a columna for this
                    // custody requirement.
                    self.columns
                        .push(CustodyDataColumn::from_asserted_custody(data_column));
                } else {
                    // Peer does not have the requested data.
                    // TODO(das) what to do?
                    // TODO(das): If the peer is in the lookup peer set it claims to have imported
                    // the block AND its custody columns. So in this case we can downscore
                    debug!(self.log, "Sampling peer claims to not have the data"; "block_root" => %self.block_root, "column_index" => column_index);
                    // TODO(das) tolerate this failure if you are not sure the block has data
                    request.on_download_success()?;
                }
            }
            Err(err) => {
                debug!(self.log, "Sample download error"; "block_root" => %self.block_root, "column_index" => column_index, "error" => ?err);

                // Error downloading, maybe penalize peer and retry again.
                // TODO(das) with different peer or different peer?
                request.on_download_error()?;
            }
        };

        self.continue_requests(cx)
    }

    pub(crate) fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyRequestResult<T::EthSpec> {
        // First check if sampling is completed, by computing `required_successes`
        let mut successes = 0;

        for request in self.column_requests.values() {
            if request.is_downloaded() {
                successes += 1;
            }
        }

        // All requests have completed successfully. We may not have all the expected columns if the
        // serving peers claim that this block has no data.
        if successes == self.column_requests.len() {
            let columns = std::mem::take(&mut self.columns);

            let peers = self
                .column_requests
                .values()
                .filter_map(|r| r.peer())
                .collect::<Vec<_>>();
            let peer_group = PeerGroup::from_set(peers);

            return Ok(Some((columns, peer_group)));
        }

        for (_, request) in self.column_requests.iter_mut() {
            request.request(self.block_root, self.block_epoch, self.requester_id, cx)?;
        }

        Ok(None)
    }
}

mod request {
    use super::{CustodyId, CustodyRequester, Error};
    use crate::sync::{
        manager::DataColumnsByRootRequester,
        network_context::{DataColumnsByRootSingleBlockRequest, SyncNetworkContext},
    };
    use beacon_chain::BeaconChainTypes;
    use lighthouse_network::PeerId;
    use types::{data_column_sidecar::ColumnIndex, Epoch, Hash256};

    /// TODO(das): this attempt count is nested into the existing lookup request count.
    const MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS: usize = 3;

    pub(crate) struct ActiveColumnSampleRequest {
        column_index: ColumnIndex,
        status: Status,
        download_failures: usize,
    }

    #[derive(Debug, Clone)]
    enum Status {
        NotStarted,
        Downloading(PeerId),
        Downloaded(PeerId),
    }

    impl ActiveColumnSampleRequest {
        pub(crate) fn new(column_index: ColumnIndex) -> Self {
            Self {
                column_index,
                status: Status::NotStarted,
                download_failures: 0,
            }
        }

        pub(crate) fn is_downloaded(&self) -> bool {
            match self.status {
                Status::NotStarted | Status::Downloading(_) => false,
                Status::Downloaded(_) => true,
            }
        }

        pub(crate) fn peer(&self) -> Option<PeerId> {
            match self.status {
                Status::NotStarted | Status::Downloading(_) => None,
                Status::Downloaded(peer) => Some(peer),
            }
        }

        pub(crate) fn request<T: BeaconChainTypes>(
            &mut self,
            block_root: Hash256,
            block_epoch: Epoch,
            requester: CustodyRequester,
            cx: &mut SyncNetworkContext<T>,
        ) -> Result<bool, Error> {
            match &self.status {
                Status::NotStarted => {}                    // Ok to continue
                Status::Downloading(_) => return Ok(false), // Already downloading
                Status::Downloaded(_) => return Ok(false),  // Already completed
            }

            if self.download_failures > MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS {
                return Err(Error::TooManyFailures);
            }

            // TODO: When is a fork and only a subset of your peers know about a block, sampling should only
            // be queried on the peers on that fork. Should this case be handled? How to handle it?
            let peer_ids = cx.get_custodial_peers(block_epoch, self.column_index);

            // TODO(das) randomize custodial peer and avoid failing peers
            let Some(peer_id) = peer_ids.first().cloned() else {
                // Do not tolerate not having custody peers, hard error.
                // TODO(das): we might implement some grace period. The request will pause for X
                // seconds expecting the peer manager to find peers before failing the request.
                return Err(Error::NoPeers(self.column_index));
            };

            cx.data_column_lookup_request(
                DataColumnsByRootRequester::Custody(CustodyId {
                    id: requester,
                    column_index: self.column_index,
                }),
                peer_id,
                DataColumnsByRootSingleBlockRequest {
                    block_root,
                    indices: vec![self.column_index],
                },
            )
            .map_err(Error::SendFailed)?;

            self.status = Status::Downloading(peer_id);
            Ok(true)
        }

        pub(crate) fn on_download_error(&mut self) -> Result<PeerId, Error> {
            match self.status.clone() {
                Status::Downloading(peer_id) => {
                    self.download_failures += 1;
                    self.status = Status::NotStarted;
                    Ok(peer_id)
                }
                other => Err(Error::BadState(format!(
                    "bad state on_sampling_error expected Sampling got {other:?}"
                ))),
            }
        }

        pub(crate) fn on_download_success(&mut self) -> Result<(), Error> {
            match &self.status {
                Status::Downloading(peer) => {
                    self.status = Status::Downloaded(*peer);
                    Ok(())
                }
                other => Err(Error::BadState(format!(
                    "bad state on_sampling_success expected Sampling got {other:?}"
                ))),
            }
        }
    }
}
