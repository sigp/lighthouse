use bus::Bus;
use parking_lot::Mutex;
use serde_derive::{Deserialize, Serialize};
use slog::{info, error, Logger};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{Attestation, Epoch, EthSpec, Hash256, SignedBeaconBlock, SignedBeaconBlockHash, Slot, SignedVoluntaryExit};
pub use websocket_server::WebSocketSender;
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Sender, Receiver};

pub trait EventHandler<T: EthSpec>: Sized + Send + Sync {
    fn register(&self, kind: EventKind<T>) -> Result<(), String>;
    fn subscribe(&self) -> Receiver<EventKind<T>>;
}

pub struct NullEventHandler<T: EthSpec>(PhantomData<T>);

impl<T: EthSpec> EventHandler<T> for WebSocketSender<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        self.send_string(
            serde_json::to_string(&kind)
                .map_err(|e| format!("Unable to serialize event: {:?}", e))?,
        )
    }
    fn subscribe(&self) -> Receiver<EventKind<T>> {
        let (_, rx ) = broadcast::channel(2);
        rx
    }
}

pub struct ServerSentEventHandler<T: EthSpec> {
    // Bus<> is itself Sync + Send.  We use Mutex<> here only because of the surrounding code does
    // not enforce mutability statically (i.e. relies on interior mutability).
    head_changed_queue: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
    head_tx: Sender<EventKind<T>>,
    head_rx: Receiver<EventKind<T>>,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ServerSentEventHandler<T> {
    pub fn new(log: Logger) -> Self {
        let (head_tx, mut head_rx) = broadcast::channel(2);


        let bus = Bus::new(T::slots_per_epoch() as usize);
        let mutex = Mutex::new(bus);
        let arc = Arc::new(mutex);
        Self {
            head_changed_queue: arc.clone(),
            head_tx,
            head_rx,
            log,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec> EventHandler<T> for ServerSentEventHandler<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        match kind {
            EventKind::Head {
                slot,
                block,
                state,
                epoch_transition,
            } => {
                info!(self.log, "registering head event - slot: {} block: {} stat: {} epoch transition: {}", slot, block, state, epoch_transition);
                self.head_tx.send(EventKind::Head {
                    slot,
                    block,
                    state,
                    epoch_transition,
                    //TODO: clean up
                }).map_err(|e|format!("Could not send head change event to queue."))?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn subscribe(&self) -> Receiver<EventKind<T>>{
        info!(self.log, "subscribing to head topic");
        self.head_tx.subscribe()
    }
}

// An event handler that pushes events to both the websockets handler and the SSE handler.
// Named after the unix `tee` command.  Meant as a temporary solution before ditching WebSockets
// completely once SSE functions well enough.
pub struct TeeEventHandler<E: EthSpec> {
    websockets_handler: WebSocketSender<E>,
    sse_handler: ServerSentEventHandler<E>,
}

impl<E: EthSpec> TeeEventHandler<E> {
    #[allow(clippy::type_complexity)]
    pub fn new(
        log: Logger,
        websockets_handler: WebSocketSender<E>,
    ) -> Self {
        let sse_handler = ServerSentEventHandler::new(log);
        Self {
            websockets_handler,
            sse_handler,
        }
    }
}

impl<E: EthSpec> EventHandler<E> for TeeEventHandler<E> {
    fn register(&self, kind: EventKind<E>) -> Result<(), String> {
        self.websockets_handler.register(kind.clone())?;
        self.sse_handler.register(kind)?;
        Ok(())
    }
    fn subscribe(&self) -> Receiver<EventKind<E>>{
        self.sse_handler.subscribe()
    }
}

impl<T: EthSpec> EventHandler<T> for NullEventHandler<T> {
    fn register(&self, _kind: EventKind<T>) -> Result<(), String> {
        Ok(())
    }
    fn subscribe(&self) -> Receiver<EventKind<T>> {
        let (_, rx ) = broadcast::channel(2);
        rx
    }
}

impl<T: EthSpec> Default for NullEventHandler<T> {
    fn default() -> Self {
        NullEventHandler(PhantomData)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(
    bound = "T: EthSpec",
    rename_all = "snake_case",
    tag = "event",
    content = "data"
)]
pub enum EventKind<T: EthSpec> {
    Attestation(Box<Attestation<T>>),
    Block{
        slot: Slot,
        block: Hash256,
    },
    ChainReorg{
        slot: Slot,
        //quoted
        depth: u64,
        old_head_block: Hash256,
        new_head_block: Hash256,
        old_head_state: Hash256,
        new_head_state: Hash256,
        epoch: Epoch,
    },
    FinalizedCheckpoint{
        block: Hash256,
        state: Hash256,
        epoch: Epoch,
    },
    Head{
        slot: Slot,
        block: Hash256,
        state: Hash256,
        epoch_transition: bool,
    },
    VoluntaryExit(Box<SignedVoluntaryExit>),


    BeaconHeadChanged {
        reorg: bool,
        current_head_beacon_block_root: Hash256,
        previous_head_beacon_block_root: Hash256,
    },
    BeaconFinalization {
        epoch: Epoch,
        root: Hash256,
    },
    BeaconBlockImported {
        block_root: Hash256,
        block: Box<SignedBeaconBlock<T>>,
    },
    BeaconBlockRejected {
        reason: String,
        block: Box<SignedBeaconBlock<T>>,
    },
    BeaconAttestationImported {
        attestation: Box<Attestation<T>>,
    },
    BeaconAttestationRejected {
        reason: String,
        attestation: Box<Attestation<T>>,
    },
}
