use crate::{
    service::NetworkMessage,
    sync::{manager::BlockProcessType, SyncMessage},
};
use beacon_chain::BeaconChain;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock, NotifyExecutionLayer};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, AsyncFn, DuplicateCache,
    WorkEvent as BeaconWorkEvent,
};
use lighthouse_network::{types::ChainSegmentProcessId, NetworkGlobals, PeerId};
use slog::Logger;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, error::TrySendError};
use types::*;

mod worker;

#[derive(Debug)]
pub enum Error {
    ShuttingDown,
    TrySendError(String),
}

impl<T: Debug> From<TrySendError<T>> for Error {
    fn from(e: TrySendError<T>) -> Self {
        Error::TrySendError(format!("{}", e))
    }
}

/// Defines if and where we will store the SSZ files of invalid blocks.
#[derive(Clone)]
pub enum InvalidBlockStorage {
    Enabled(PathBuf),
    Disabled,
}

/// Provides an interface to a `BeaconProcessor` running in some other thread.
/// The wider `networking` crate should use this struct to interface with the
/// beacon processor.
pub struct NetworkBeaconProcessor<T: BeaconChainTypes> {
    pub beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    pub duplicate_cache: DuplicateCache,
    pub chain: Arc<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub reprocess_tx: mpsc::Sender<ReprocessQueueMessage>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub invalid_block_storage: InvalidBlockStorage,
    pub log: Logger,
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /// Returns an async closure which processes a chain of beacon blocks.
    pub fn process_fn_process_chain_segment(
        self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> AsyncFn {
        let process_fn = async move {
            let notify_execution_layer = if self
                .network_globals
                .sync_state
                .read()
                .is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            self.process_chain_segment(sync_type, downloaded_blocks, notify_execution_layer)
                .await;
        };
        Box::pin(process_fn)
    }

    /// Returns an async closure which processes a beacon block which has
    /// already been verified via gossip.
    ///
    /// TODO(paul): delete me.
    pub fn process_fn_gossip_verified_block(
        self: Arc<Self>,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
        seen_timestamp: Duration,
    ) -> AsyncFn {
        let process_fn = async move {
            let reprocess_tx = self.reprocess_tx.clone();
            let invalid_block_storage = self.invalid_block_storage.clone();
            self.process_gossip_verified_block(
                peer_id,
                verified_block,
                reprocess_tx,
                invalid_block_storage,
                seen_timestamp,
            )
            .await;
        };
        Box::pin(process_fn)
    }
}
