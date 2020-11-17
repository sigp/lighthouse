use eth2::types::{SseBlock, SseFinalizedCheckpoint, SseHead};
use serde_derive::{Deserialize, Serialize};
use slog::{Logger, trace};
use std::marker::PhantomData;
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Receiver, Sender, SendError};
use types::{Attestation, EthSpec, SignedVoluntaryExit};

const DEFAULT_CHANNEL_CAPACITY: usize = 10;

pub trait EventHandler<T: EthSpec>: Sized + Send + Sync {
    fn register(&self, kind: EventKind<T>);

    fn subscribe_attestation(&self) -> Receiver<EventKind<T>>;

    fn subscribe_block(&self) -> Receiver<EventKind<T>>;

    fn subscribe_finalized(&self) -> Receiver<EventKind<T>>;

    fn subscribe_head(&self) -> Receiver<EventKind<T>>;

    fn subscribe_exit(&self) -> Receiver<EventKind<T>>;

    fn attestation_recv_count(&self) -> Receiver<EventKind<T>>;

    fn block_recv_count(&self) -> Receiver<EventKind<T>>;

    fn finalized_recv_count(&self) -> Receiver<EventKind<T>>;

    fn head_recv_count(&self) -> Receiver<EventKind<T>>;

    fn exit_recv_count(&self) -> Receiver<EventKind<T>>;

}

pub struct NullEventHandler<T: EthSpec>(PhantomData<T>);

pub struct ServerSentEventHandler<T: EthSpec> {
    attestation_tx: Sender<EventKind<T>>,
    block_tx: Sender<EventKind<T>>,
    finalized_tx: Sender<EventKind<T>>,
    head_tx: Sender<EventKind<T>>,
    exit_tx: Sender<EventKind<T>>,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ServerSentEventHandler<T> {
    pub fn new(log: Logger) -> Self {
        let (attestation_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (block_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (finalized_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (head_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let (exit_tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);

        Self {
            attestation_tx,
            block_tx,
            finalized_tx,
            head_tx,
            exit_tx,
            log,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec> EventHandler<T> for ServerSentEventHandler<T> {
    fn register(&self, kind: EventKind<T>) {
        let result = match kind {
            EventKind::Attestation(attestation) => self
                .attestation_tx
                .send(EventKind::Attestation(attestation))
                .map(|count| trace!(self.log, "Registering server-sent attestation event"; "receiver_count" => count)),
            EventKind::Block(block) => self.block_tx.send(EventKind::Block(block))
                .map(|count| trace!(self.log, "Registering server-sent block event"; "receiver_count" => count)),
            EventKind::FinalizedCheckpoint(checkpoint) => self.finalized_tx
                .send(EventKind::FinalizedCheckpoint(checkpoint))
                .map(|count| trace!(self.log, "Registering server-sent finalized checkpoint event"; "receiver_count" => count)),
            EventKind::Head(head) => self.head_tx.send(EventKind::Head(head))
                .map(|count| trace!(self.log, "Registering server-sent head event"; "receiver_count" => count)),
            EventKind::VoluntaryExit(exit) => self.exit_tx.send(EventKind::VoluntaryExit(exit))
                .map(|count| trace!(self.log, "Registering server-sent voluntary exit event"; "receiver_count" => count)),
        };
        if let Err(SendError(event)) = result {
            // an error here indicates there are no receivers subscribed
            trace!(self.log, "No receivers registered to listen for event: {:?}", event);
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

    fn subscribe_head(&self) -> Receiver<EventKind<T>> {
        self.head_tx.subscribe()
    }

    fn subscribe_exit(&self) -> Receiver<EventKind<T>> {
        self.exit_tx.subscribe()
    }

    fn receiver_count(&self, kind: &EventKind<T>) -> usize {
        match kind {
            EventKind::Attestation(_) => self.attestation_tx.receiver_count(),
            EventKind::Block(_) => self.block_tx.receiver_count(),
            EventKind::FinalizedCheckpoint(_) => self.finalized_tx.receiver_count(),
            EventKind::Head(_) => self.head_tx.receiver_count(),
            EventKind::VoluntaryExit(_) => self.exit_tx.receiver_count(),
        }
    }

}

impl<T: EthSpec> EventHandler<T> for NullEventHandler<T> {
    fn register(&self, _kind: EventKind<T>) {
        // intentional no-op
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

    fn subscribe_head(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn subscribe_exit(&self) -> Receiver<EventKind<T>> {
        let (_, rx) = broadcast::channel(1);
        rx
    }

    fn receiver_count(&self, _kind: &EventKind<T>) -> usize {
        0
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
    Head(SseHead),
    VoluntaryExit(SignedVoluntaryExit),
}
