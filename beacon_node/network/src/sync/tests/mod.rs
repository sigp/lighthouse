use crate::sync::manager::SyncManager;
use crate::sync::range_sync::RangeSyncType;
use crate::sync::SyncMessage;
use crate::NetworkMessage;
use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_processor::WorkEvent;
use lighthouse_network::NetworkGlobals;
use slog::Logger;
use slot_clock::ManualSlotClock;
use std::sync::Arc;
use store::MemoryStore;
use tokio::sync::mpsc;
use types::{test_utils::XorShiftRng, ForkName, MinimalEthSpec as E};

mod lookups;
mod range;

type T = Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

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
    rng: XorShiftRng,
    fork_name: ForkName,
    log: Logger,
}
