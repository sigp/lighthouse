use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::BeaconChainTypes;
use beacon_chain::{BeaconChain, NotifyExecutionLayer};
use beacon_processor::{Work as BeaconWork, WorkEvent as BeaconWorkEvent};
use lighthouse_network::{types::ChainSegmentProcessId, NetworkGlobals};
use slog::Logger;
use std::fmt::Debug;
use std::sync::{Arc, Weak};
use tokio::sync::mpsc::{self, error::TrySendError};
use types::*;
use worker::Worker;

mod worker;

#[derive(Debug)]
pub enum Error {
    ShuttingDown,
    TrySendError(String),
}

impl<T: Debug> From<TrySendError<T>> for Error {
    fn from(self) -> Error {
        Error::TrySendError(format!("{}", self))
    }
}

/// Provides an interface to a `BeaconProcessor` running in some other thread.
pub struct NetworkBeaconProcessor<T: BeaconChainTypes> {
    pub beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    pub chain: Weak<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub log: Logger,
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    fn worker(&self) -> Result<Worker<T>, Error> {
        let chain = self.chain.upgrade().ok_or(Error::ShuttingDown)?;
        Ok(Worker {
            chain: self.chain.clone(),
            network_tx: self.network_tx.clone(),
            sync_tx: self.sync_tx.clone(),
            log: self.log.clone(),
        })
    }

    pub fn process_chain_segment(
        self: Arc<Self>,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<(), Error> {
        let worker = self.worker()?;
        let network_globals = self.network_globals.clone();
        let process_fn = async move {
            let notify_execution_layer = if network_globals.sync_state.read().is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            worker.process_chain_segment(sync_type, downloaded_blocks, notify_execution_layer)
        };
        self.beacon_processor_send
            .try_send(BeaconWorkEvent {
                drop_during_sync: false,
                work: BeaconWork::ChainSegment {
                    process_id: sync_type,
                    process_fn,
                },
            })
            .map_err(Into::into)
    }
}
