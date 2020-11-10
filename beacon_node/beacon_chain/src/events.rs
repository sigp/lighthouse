use bus::Bus;
use eth2::types::{EventTopic, SseBlock, SseFinalizedCheckpoint, SseState};
use parking_lot::Mutex;
use serde_derive::{Deserialize, Serialize};
use slog::{error, info, Logger};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Receiver, Sender};
use types::{
    Attestation, Epoch, EthSpec, Hash256, SignedBeaconBlock, SignedBeaconBlockHash,
    SignedVoluntaryExit, Slot,
};
pub use websocket_server::WebSocketSender;

//TODO: figure out what this should be. Or should he have different capacities for each?
const DEFAULT_CHANNEL_CAPACITY: usize = 10;

pub trait EventHandler<T: EthSpec>: Sized + Send + Sync {
    fn register(&self, kind: EventKind<T>) -> Result<(), String>;

    fn subscribe_attestation(&self) -> Receiver<EventKind<T>>;

    fn subscribe_block(&self) -> Receiver<EventKind<T>>;

    fn subscribe_finalized(&self) -> Receiver<EventKind<T>>;

    fn subscribe_state(&self) -> Receiver<EventKind<T>>;

    fn subscribe_exit(&self) -> Receiver<EventKind<T>>;
}

pub struct NullEventHandler<T: EthSpec>(PhantomData<T>);

pub struct ServerSentEventHandler<T: EthSpec> {
    attestation_tx: Sender<EventKind<T>>,
    block_tx: Sender<EventKind<T>>,
    finalized_tx: Sender<EventKind<T>>,
    state_tx: Sender<EventKind<T>>,
    exit_tx: Sender<EventKind<T>>,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ServerSentEventHandler<T> {
    pub fn new(log: Logger) -> Self {
        let (attestation_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (block_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (finalized_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (state_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (exit_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);

        Self {
            attestation_tx,
            block_tx,
            finalized_tx,
            state_tx,
            exit_tx,
            log,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec> EventHandler<T> for ServerSentEventHandler<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        // info!(self.log, "registering head event - slot: {} block: {} stat: {} epoch transition: {}", slot, block, state, epoch_transition);

        match kind {
            EventKind::Attestation(attestation) => self
                .attestation_tx
                .send(EventKind::Attestation(attestation))
                .map(|_| Ok(()))
                .map_err(|e| format!(""))?,
            EventKind::Block(block) => self
                .block_tx
                .send(EventKind::Block(block))
                .map(|_| Ok(()))
                .map_err(|e| format!(""))?,
            EventKind::FinalizedCheckpoint(checkpoint) => self
                .finalized_tx
                .send(EventKind::FinalizedCheckpoint(checkpoint))
                .map(|_| Ok(()))
                .map_err(|e| format!(""))?,
            EventKind::State(state) => self
                .state_tx
                .send(EventKind::State(state))
                .map(|_| Ok(()))
                .map_err(|e| format!(""))?,
            EventKind::VoluntaryExit(exit) => self
                .exit_tx
                .send(EventKind::VoluntaryExit(exit))
                .map(|_| Ok(()))
                .map_err(|e| format!(""))?,
        }
    }

    fn subscribe_attestation(&self) -> Receiver<EventKind<T>> {
        self.attestation_tx.subscribe()
    }

    fn subscribe_block(&self) -> Receiver<EventKind<T>> {
        self.block_tx.subscribe()
    }

    fn subscribe_finalized(&self) -> Receiver<EventKind<T>> {
        self.finalized_tx.subscribe()
    }

    fn subscribe_state(&self) -> Receiver<EventKind<T>> {
        self.state_tx.subscribe()
    }

    fn subscribe_exit(&self) -> Receiver<EventKind<T>> {
        self.exit_tx.subscribe()
    }
}

impl<T: EthSpec> EventHandler<T> for NullEventHandler<T> {
    fn register(&self, _kind: EventKind<T>) -> Result<(), String> {
        Ok(())
    }

    fn subscribe_attestation(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn subscribe_block(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn subscribe_finalized(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn subscribe_state(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn subscribe_exit(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }
}

impl<T: EthSpec> Default for NullEventHandler<T> {
    fn default() -> Self {
        NullEventHandler(PhantomData)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "T: EthSpec", rename_all = "snake_case")]
pub enum EventKind<T: EthSpec> {
    Attestation(Attestation<T>),
    Block(SseBlock),
    FinalizedCheckpoint(SseFinalizedCheckpoint),
    State(SseState),
    VoluntaryExit(SignedVoluntaryExit),
}
