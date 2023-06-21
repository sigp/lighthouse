use crate::{
    service::NetworkMessage,
    sync::{manager::BlockProcessType, SyncMessage},
};
use beacon_chain::BeaconChainTypes;
use beacon_chain::{BeaconChain, NotifyExecutionLayer};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, AsyncFn, DuplicateCache, Work as BeaconWork,
    WorkEvent as BeaconWorkEvent,
};
use lighthouse_network::{types::ChainSegmentProcessId, NetworkGlobals};
use slog::Logger;
use std::fmt::Debug;
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
    pub log: Logger,
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    pub fn work_builder<'a>(&'a self) -> WorkBuilder<'a, T> {
        WorkBuilder {
            network_processor: self,
        }
    }
}

/// A builder-type struct used to create `BeaconWorkEvents` send them to the
/// `BeaconProcessor` for execution.
pub struct WorkBuilder<'a, T: BeaconChainTypes> {
    network_processor: &'a NetworkBeaconProcessor<T>,
}

/// A wrapper around a work event and a channel to the `BeaconProcessor`,
/// providing convenience methods.
pub struct WorkEvent<'a, T: BeaconChainTypes> {
    network_processor: &'a NetworkBeaconProcessor<T>,
    beacon_work_event: BeaconWorkEvent<T::EthSpec>,
}

impl<'a, T: BeaconChainTypes> WorkEvent<'a, T> {
    fn new(
        network_processor: &'a NetworkBeaconProcessor<T>,
        beacon_work_event: BeaconWorkEvent<T::EthSpec>,
    ) -> Self {
        Self {
            network_processor,
            beacon_work_event,
        }
    }

    pub fn send_to_beacon_processor(self) -> Result<(), Error> {
        self.network_processor
            .beacon_processor_send
            .try_send(self.beacon_work_event)
            .map_err(Into::into)
    }
}

impl<'a, T: BeaconChainTypes> WorkBuilder<'a, T> {
    pub fn new(network_processor: &'a NetworkBeaconProcessor<T>) -> Self {
        Self { network_processor }
    }

    pub fn process_chain_segment(
        self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> WorkEvent<'a, T> {
        let network_processor = self.network_processor.clone();
        let process_fn = async move {
            let notify_execution_layer = if network_processor
                .network_globals
                .sync_state
                .read()
                .is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            network_processor
                .process_chain_segment(sync_type, downloaded_blocks, notify_execution_layer)
                .await;
        };

        let beacon_work_event = BeaconWorkEvent {
            drop_during_sync: false,
            work: BeaconWork::ChainSegment {
                process_id: sync_type,
                process_fn: Box::pin(process_fn),
            },
        };

        WorkEvent::new(self.network_processor, beacon_work_event)
    }

    pub fn rpc_beacon_block(
        self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> WorkEvent<'a, T> {
        let network_processor = self.network_processor.clone();
        let process_fn = async move {
            let reprocess_tx = network_processor.reprocess_tx.clone();
            let duplicate_cache = network_processor.duplicate_cache.clone();
            let should_process = true;
            network_processor
                .process_rpc_block(
                    block_root,
                    block,
                    seen_timestamp,
                    process_type,
                    reprocess_tx,
                    duplicate_cache,
                    should_process,
                )
                .await;
        };

        let beacon_work_event = BeaconWorkEvent {
            drop_during_sync: false,
            work: BeaconWork::RpcBlock {
                should_process: true,
                process_fn: Box::pin(process_fn),
            },
        };

        WorkEvent::new(self.network_processor, beacon_work_event)
    }
}

/// Returns an async closure which processes a beacon block recieved via RPC.
pub fn rpc_beacon_block_process_fn<T: BeaconChainTypes>(
    network_processor: Arc<NetworkBeaconProcessor<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    seen_timestamp: Duration,
    process_type: BlockProcessType,
) -> AsyncFn {
    let process_fn = async move {
        let reprocess_tx = network_processor.reprocess_tx.clone();
        let duplicate_cache = network_processor.duplicate_cache.clone();
        let should_process = true;
        network_processor
            .process_rpc_block(
                block_root,
                block,
                seen_timestamp,
                process_type,
                reprocess_tx,
                duplicate_cache,
                should_process,
            )
            .await;
    };
    Box::pin(process_fn)
}
