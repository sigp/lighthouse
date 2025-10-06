use crate::NetworkMessage;
use crate::sync::SyncMessage;
use crate::sync::manager::SyncManager;
use crate::sync::range_sync::RangeSyncType;
use beacon_chain::builder::Witness;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_processor::WorkEvent;
use lighthouse_network::NetworkGlobals;
use rand_chacha::ChaCha20Rng;
use slot_clock::ManualSlotClock;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Once};
use store::MemoryStore;
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use types::{ChainSpec, ForkName, MinimalEthSpec as E};

mod lookups;
mod range;

type T = Witness<ManualSlotClock, E, MemoryStore<E>, MemoryStore<E>>;

/// This test utility enables integration testing of Lighthouse sync components.
///
/// It covers the following:
/// 1. Sending `SyncMessage` to `SyncManager` to trigger `RangeSync`, `BackFillSync` and `BlockLookups` behaviours.
/// 2. Making assertions on `WorkEvent`s received from sync
/// 3. Making assertion on `NetworkMessage` received from sync (Outgoing RPC requests).
///
/// The test utility covers testing the interactions from and to `SyncManager`. In diagram form:
///                      +-----------------+
///                      | BeaconProcessor |
///                      +---------+-------+
///                             ^  |
///                             |  |
///                   WorkEvent |  | SyncMsg
///                             |  | (Result)
///                             |  v
/// +--------+            +-----+-----------+             +----------------+
/// | Router +----------->|  SyncManager    +------------>| NetworkService |
/// +--------+  SyncMsg   +-----------------+ NetworkMsg  +----------------+
///           (RPC resp)  |  - RangeSync    |  (RPC req)
///                       +-----------------+
///                       |  - BackFillSync |
///                       +-----------------+
///                       |  - BlockLookups |
///                       +-----------------+
struct TestRig {
    /// Receiver for `BeaconProcessor` events (e.g. block processing results).
    beacon_processor_rx: mpsc::Receiver<WorkEvent<E>>,
    beacon_processor_rx_queue: Vec<WorkEvent<E>>,
    /// Receiver for `NetworkMessage` (e.g. outgoing RPC requests from sync)
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Stores all `NetworkMessage`s received from `network_recv`. (e.g. outgoing RPC requests)
    network_rx_queue: Vec<NetworkMessage<E>>,
    /// Receiver for `SyncMessage` from the network
    sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
    /// To send `SyncMessage`. For sending RPC responses or block processing results to sync.
    sync_manager: SyncManager<T>,
    /// To manipulate sync state and peer connection status
    network_globals: Arc<NetworkGlobals<E>>,
    /// Beacon chain harness
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    /// `rng` for generating test blocks and blobs.
    rng_08: rand_chacha_03::ChaCha20Rng,
    rng: ChaCha20Rng,
    fork_name: ForkName,
    spec: Arc<ChainSpec>,
}

// Environment variable to read if `fork_from_env` feature is enabled.
pub const FORK_NAME_ENV_VAR: &str = "FORK_NAME";
// Environment variable specifying the log output directory in CI.
pub const CI_LOGGER_DIR_ENV_VAR: &str = "CI_LOGGER_DIR";

static INIT_TRACING: Once = Once::new();

pub fn init_tracing() {
    INIT_TRACING.call_once(|| {
        if std::env::var(CI_LOGGER_DIR_ENV_VAR).is_ok() {
            // Enable logging to log files for each test and each fork.
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(CILogWriter),
                )
                .init();
        }
    });
}

// CILogWriter writes logs to separate files for each test and each fork.
struct CILogWriter;

impl<'a> MakeWriter<'a> for CILogWriter {
    type Writer = Box<dyn Write + Send>;

    // fmt::Layer calls this method each time an event is recorded.
    fn make_writer(&'a self) -> Self::Writer {
        let log_dir = std::env::var(CI_LOGGER_DIR_ENV_VAR).unwrap();
        let fork_name = std::env::var(FORK_NAME_ENV_VAR)
            .map(|s| format!("{s}_"))
            .unwrap_or_default();

        // The current test name can be got via the thread name.
        let test_name = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .replace(|c: char| !c.is_alphanumeric(), "_");

        let file_path = format!("{log_dir}/{fork_name}{test_name}.log");
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&file_path)
            .expect("failed to open a log file");

        Box::new(file)
    }
}
