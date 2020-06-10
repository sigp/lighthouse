use bus::Bus;
use parking_lot::Mutex;
use serde_derive::{Deserialize, Serialize};
use slog::{error, Logger};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{Attestation, Epoch, EthSpec, Hash256, SignedBeaconBlock, SignedBeaconBlockHash};
pub use websocket_server::WebSocketSender;

pub trait EventHandler<T: EthSpec>: Sized + Send + Sync {
    fn register(&self, kind: EventKind<T>) -> Result<(), String>;
}

pub struct NullEventHandler<T: EthSpec>(PhantomData<T>);

impl<T: EthSpec> EventHandler<T> for WebSocketSender<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        self.send_string(
            serde_json::to_string(&kind)
                .map_err(|e| format!("Unable to serialize event: {:?}", e))?,
        )
    }
}

pub struct ServerSentEvents<T: EthSpec> {
    // Bus<> is itself Sync + Send.  We use Mutex<> here only because of the surrounding code does
    // not enforce mutability statically (i.e. relies on interior mutability).
    head_changed_queue: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ServerSentEvents<T> {
    pub fn new(log: Logger) -> (Self, Arc<Mutex<Bus<SignedBeaconBlockHash>>>) {
        let bus = Bus::new(T::slots_per_epoch() as usize);
        let mutex = Mutex::new(bus);
        let arc = Arc::new(mutex);
        let this = Self {
            head_changed_queue: arc.clone(),
            log: log,
            _phantom: PhantomData,
        };
        (this, arc)
    }
}

impl<T: EthSpec> EventHandler<T> for ServerSentEvents<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        match kind {
            EventKind::BeaconHeadChanged {
                current_head_beacon_block_root,
                ..
            } => {
                let mut guard = self.head_changed_queue.lock();
                if let Err(_) = guard.try_broadcast(current_head_beacon_block_root.into()) {
                    error!(
                        self.log,
                        "Head change streaming queue full";
                        "dropped_change" => format!("{}", current_head_beacon_block_root),
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// An event handler that pushes events to both the websockets handler and the SSE handler.
// Named after the unix `tee` command.  Meant as a temporary solution before ditching WebSockets
// completely once SSE functions well enough.
pub struct TeeEventHandler<E: EthSpec> {
    websockets_handler: WebSocketSender<E>,
    sse_handler: ServerSentEvents<E>,
}

impl<E: EthSpec> TeeEventHandler<E> {
    pub fn new(
        log: Logger,
        websockets_handler: WebSocketSender<E>,
    ) -> Result<(Self, Arc<Mutex<Bus<SignedBeaconBlockHash>>>), String> {
        let (sse_handler, bus) = ServerSentEvents::new(log);
        let result = Self {
            websockets_handler: websockets_handler,
            sse_handler: sse_handler,
        };
        Ok((result, bus))
    }
}

impl<E: EthSpec> EventHandler<E> for TeeEventHandler<E> {
    fn register(&self, kind: EventKind<E>) -> Result<(), String> {
        self.websockets_handler.register(kind.clone())?;
        self.sse_handler.register(kind)?;
        Ok(())
    }
}

impl<T: EthSpec> EventHandler<T> for NullEventHandler<T> {
    fn register(&self, _kind: EventKind<T>) -> Result<(), String> {
        Ok(())
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
