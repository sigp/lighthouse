use std::{sync::Arc, time::Duration};

use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use lighthouse_network::{
    rpc::RPCError,
    service::api_types::{
        CustodySyncDataColumnsByRangeRequestId, CustodySyncDataColumnsByRootRequestId,
        SyncRequestId,
    },
    types::{SyncState, BackFillState},
    NetworkGlobals, PeerId, SyncInfo,
};
use logging::crit;
use tokio::sync::mpsc;
use tracing::{debug, error, trace};
use types::{DataColumnSidecar, DataColumnSidecarList, EthSpec, ForkContext, Hash256, Slot};

use crate::{
    network_beacon_processor::NetworkBeaconProcessor,
    status::ToStatusMessage,
    sync::{
        backfill_sync::SyncStart,
        custody_sync::CustodySync,
        network_context::{RpcEvent, SyncNetworkContext},
        peer_sync_info::{remote_sync_type, PeerSyncType},
    },
    NetworkMessage,
};

#[derive(Debug)]
pub enum DataColumnProcessingResult {
    Ok(),
    Err(BeaconChainError),
    Ignored,
}

#[derive(Debug)]
/// A message that can be sent to the custody sync manager thread.
pub enum CustodySyncMessage<E: EthSpec> {
    /// A useful peer has been discovered.
    AddPeer(PeerId, SyncInfo),

    /// Peer manager has received a MetaData of a peer with a new or updated CGC value.
    UpdatedPeerCgc(PeerId),

    /// A data columns has been received from the RPC
    RpcDataColumn {
        sync_request_id: SyncRequestId,
        peer_id: PeerId,
        data_column: Option<Arc<DataColumnSidecar<E>>>,
        seen_timestamp: Duration,
    },

    /// A data column with an unknown parent has been received.
    UnknownParentDataColumn(PeerId, Arc<DataColumnSidecar<E>>),

    /// A peer has disconnected.
    Disconnect(PeerId),

    /// An RPC Error has occurred on a request.
    RpcError {
        peer_id: PeerId,
        sync_request_id: SyncRequestId,
        error: RPCError,
    },

    /// Block processed
    DataColumnProcessed { result: DataColumnProcessingResult },
}

/// The primary object for handling and driving custody sync. It maintains the
/// current state of the custody syncing process, the number of useful peers, downloaded columns and
/// controls the logic behind custody sync.
pub struct CustodySyncManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,

    /// A receiving channel sent by the custody sync processor thread.
    custody_sync_channel: mpsc::UnboundedReceiver<CustodySyncMessage<T::EthSpec>>,

    /// A receiving channel sent by external lighthouse services to indicate if cgc has changed.
    cgc_changed_channel: mpsc::UnboundedReceiver<()>,

    /// The object handling custody sync.
    custody_sync: CustodySync<T>,

    /// A network context to contact the network service.
    network: SyncNetworkContext<T>,
}

/// Spawns a new `CustodySyncManager` thread.
pub fn spawn<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    sync_recv: mpsc::UnboundedReceiver<CustodySyncMessage<T::EthSpec>>,
    cgc_recv: mpsc::UnboundedReceiver<()>,
    fork_context: Arc<ForkContext>,
) {
}

impl<T: BeaconChainTypes> CustodySyncManager<T> {
    pub(crate) fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        sync_recv: mpsc::UnboundedReceiver<CustodySyncMessage<T::EthSpec>>,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        todo!()
    }

    /// The main driving future for the custody sync manager.
    async fn main(&mut self) {
        // process any inbound messages
        loop {
            tokio::select! {
                Some(sync_message) = self.custody_sync_channel.recv() => {
                    self.handle_message(sync_message);
                },
                Some(cgc_changed) = self.cgc_changed_channel.recv() => {
                    self.trigger_custody_backfill();
                }
            }
        }
    }

    pub(crate) fn handle_message(&mut self, sync_message: CustodySyncMessage<T::EthSpec>) {
        match sync_message {
            CustodySyncMessage::AddPeer(peer_id, info) => {
                self.add_peer(peer_id, info);
            }
            CustodySyncMessage::UpdatedPeerCgc(peer_id) => {
                debug!(
                    peer_id = ?peer_id,
                    "Received updated peer CGC message"
                );
                // TODO what needs to happen here
            }
            CustodySyncMessage::RpcDataColumn {
                sync_request_id,
                peer_id,
                data_column,
                seen_timestamp,
            } => {
                self.rpc_data_column_received(sync_request_id, peer_id, data_column, seen_timestamp)
            }
            CustodySyncMessage::UnknownParentDataColumn(peer_id, data_column) => todo!(),
            CustodySyncMessage::Disconnect(peer_id) => {{
                debug!(%peer_id, "Received disconnected message");
                self.peer_disconnect(&peer_id);
            }},
            CustodySyncMessage::RpcError {
                peer_id,
                sync_request_id,
                error,
            } => self.inject_error(peer_id, sync_request_id, error),
            CustodySyncMessage::DataColumnProcessed { result } => todo!(),
        }
    }

    pub(crate) fn trigger_custody_backfill(&mut self) {
        // TODO check if we can trigger custody backfill

        // Attempt to start/resume custody sync
        match self.custody_sync.start(&mut self.network) {
            Ok(SyncStart::Syncing {
                completed,
                remaining,
            }) => {
                let sync_state = SyncState::BackFillSyncing {
                    completed,
                    remaining,
                };

                // TODO update the managers view of syn state
            }
            Ok(SyncStart::NotSyncing) => {} // Ignore updating the state if the custody sync state didn't start.
            Err(e) => {
                error!(error = ?e, "Custody backfill sync failed to start");
            }
        };
    }

    #[cfg(test)]
    pub(crate) fn custody_sync_state(&self) -> BackFillState {
        self.custody_sync.state()
    }

    fn network_globals(&self) -> &NetworkGlobals<T::EthSpec> {
        self.network.network_globals()
    }

    /* Input Handling Functions */

    /// A peer has connected which has blocks that are unknown to us.
    ///
    /// This function handles the logic associated with the connection of a new peer.
    ///
    /// If the peer is within the `SLOT_IMPORT_TOLERANCE`, then it's head is sufficiently close to
    /// ours that we consider it fully sync'd with respect to our current chain.
    fn add_peer(&mut self, peer_id: PeerId, remote: SyncInfo) {
        // ensure the beacon chain still exists
        let status = self.chain.status_message();
        let local = SyncInfo {
            head_slot: *status.head_slot(),
            head_root: *status.head_root(),
            finalized_epoch: *status.finalized_epoch(),
            finalized_root: *status.finalized_root(),
            earliest_available_slot: status.earliest_available_slot().ok().cloned(),
        };

        let sync_type = remote_sync_type(&local, &remote, &self.chain);

        // update the state of the peer.
        self.update_peer_sync_state(&peer_id, &local, &remote, &sync_type);

        // Try to make progress on custody requests that are waiting for peers
        // for (id, result) in self.network.continue_custody_by_root_requests() {
        //     self.on_custody_by_root_result(id, result);
        // }
    }

    // TODO This should check if we can trigger custody sync
    fn is_backfill_complete(&mut self) -> bool {
        todo!()
    }

    /// Updates the syncing state of a peer.
    /// Return true if the peer is still connected and known to the peers DB
    fn update_peer_sync_state(
        &mut self,
        peer_id: &PeerId,
        local_sync_info: &SyncInfo,
        remote_sync_info: &SyncInfo,
        sync_type: &PeerSyncType,
    ) -> bool {
        // NOTE: here we are gracefully handling two race conditions: Receiving the status message
        // of a peer that is 1) disconnected 2) not in the PeerDB.

        let new_state = sync_type.as_sync_status(remote_sync_info);
        let rpr = new_state.as_str();
        // Drop the write lock
        let update_sync_status = self
            .network_globals()
            .peers
            .write()
            .update_sync_status(peer_id, new_state.clone());

        if let Some(was_updated) = update_sync_status {
            let is_connected = self.network_globals().peers.read().is_connected(peer_id);
            if was_updated {
                debug!(
                    %peer_id,
                    new_state = rpr,
                    our_head_slot = %local_sync_info.head_slot,
                    our_finalized_epoch = %local_sync_info.finalized_epoch,
                    their_head_slot = %remote_sync_info.head_slot,
                    their_finalized_epoch = %remote_sync_info.finalized_epoch,
                    is_connected,
                    "Peer transitioned sync state"
                );

                // A peer has transitioned its sync state. If the new state is "synced" we
                // inform the backfill sync that a new synced peer has joined us.
                if new_state.is_synced() {
                    // self.custody_sync.fully_synced_peer_joined();
                }
            }
            is_connected
        } else {
            error!(%peer_id, "Status'd peer is unknown");
            false
        }
    }

    fn rpc_data_column_received(
        &mut self,
        sync_request_id: SyncRequestId,
        peer_id: PeerId,
        data_column: Option<Arc<DataColumnSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
    ) {
        match sync_request_id {
            SyncRequestId::CustodySyncDataColumnsByRange(id) => self
                .on_data_columns_by_range_response(
                    id,
                    peer_id,
                    RpcEvent::from_chunk(data_column, seen_timestamp),
                ),
            _ => {
                crit!(%peer_id, "bad request id for data_column");
            }
        }
    }

    fn on_data_columns_by_root_response(
        &mut self,
        req_id: CustodySyncDataColumnsByRootRequestId,
        peer_id: PeerId,
        data_column: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) {
        // if let Some(resp) =
        //     self.network
        //         .on_data_columns_by_root_response(req_id, peer_id, data_column)
        // {
        //     match req_id.parent_request_id {
        //         DataColumnsByRootRequester::Sampling(id) => {
        //             if let Some((requester, result)) =
        //                 self.sampling
        //                     .on_sample_downloaded(id, peer_id, resp, &mut self.network)
        //             {
        //                 self.on_sampling_result(requester, result)
        //             }
        //         }
        //         DataColumnsByRootRequester::Custody(custody_id) => {
        //             if let Some(result) = self
        //                 .network
        //                 .on_custody_by_root_response(custody_id, req_id, peer_id, resp)
        //             {
        //                 self.on_custody_by_root_result(custody_id, result);
        //             }
        //         }
        //     }
        // }
    }

    fn on_data_columns_by_range_response(
        &mut self,
        id: CustodySyncDataColumnsByRangeRequestId,
        peer_id: PeerId,
        data_column: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) {
        if let Some(data_columns) = self
            .network
            .on_custody_sync_data_columns_by_range_response(id, peer_id, data_column)
        {
            match data_columns {
                Ok(data_columns) => todo!(),
                Err(_) => todo!(),
            }
           
        }
    }

    /// Handles a peer disconnect.
    ///
    /// It is important that a peer disconnect retries all the batches/lookups as
    /// there is no way to guarantee that libp2p always emits a error along with
    /// the disconnect.
    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        // Inject a Disconnected error on all requests associated with the disconnected peer
        // to retry all batches/lookups
        for sync_request_id in self.network.peer_disconnected(peer_id) {
            self.inject_error(*peer_id, sync_request_id, RPCError::Disconnected);
        }

        // Remove peer from all data structures
        let _ = self.custody_sync.peer_disconnected(peer_id);

        // Regardless of the outcome, we update the sync status.
        self.update_sync_state();
    }

    /// Updates the global custody sync state, logging any changes.
    fn update_sync_state(&mut self) {
        let new_state: BackFillState = match self.custody_sync.state() {
            BackFillState::Paused => todo!(),
            BackFillState::Syncing => todo!(),
            BackFillState::Completed => todo!(),
            BackFillState::Failed => todo!(),
        };
    }

    /// Handles RPC errors related to requests that were emitted from the sync manager.
    fn inject_error(&mut self, peer_id: PeerId, sync_request_id: SyncRequestId, error: RPCError) {
        trace!("Sync manager received a failed RPC");
        match sync_request_id {
            SyncRequestId::CustodySyncDataColumnsByRange(req_id) => {
                self.on_data_columns_by_range_response(req_id, peer_id, RpcEvent::RPCError(error))
            },
            _ => {
                todo!()
            }
        }
    }
}
