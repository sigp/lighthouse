use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};

use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::BeaconChainHarness;
use beacon_processor::WorkEvent;
use lighthouse_network::peer_manager::peerdb::NewConnectionState;
use lighthouse_network::types::SyncState;
use lighthouse_network::{NetworkGlobals, PeerId};
use slot_clock::{ManualSlotClock, SlotClock, TestingSlotClock};
use store::MemoryStore;
use types::{MinimalEthSpec as E, Slot};

use crate::sync::SyncMessage;
use crate::{sync, NetworkMessage};

type T = Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

/// This test utility enables integration testing of Lighthouse sync components.
///
/// It covers the following:
/// 1. Sending `SyncMessage` to `SyncManager` to trigger `RangeSync`, `BackFillSync` and `BlockLookups` behaviours.
/// 2. Making assertions on `WorkEvent`s received from sync
/// 3. Making assertion on `NetworkMessage` received from sync.
pub struct SyncTester {
    harness: BeaconChainHarness<T>,
    network_globals: Arc<NetworkGlobals<E>>,
    sync_send: UnboundedSender<SyncMessage<E>>,
    network_recv: UnboundedReceiver<NetworkMessage<E>>,
    received_network_messages: Vec<NetworkMessage<E>>,
    beacon_processor_recv: Receiver<WorkEvent<E>>,
    received_beacon_processor_events: Vec<WorkEvent<E>>,
}

pub enum SyncTestType {
    RangeSync,
    BackFillSync,
    BlockLookups,
}

impl SyncTester {
    pub fn new(test_type: SyncTestType) -> Self {
        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<T>::builder(E)
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(0),
                Duration::from_secs(12),
            ))
            .build();

        let runtime = &harness.runtime;
        let log = &runtime.log;
        let chain = harness.chain.clone();
        let network_globals = Arc::new(NetworkGlobals::new_test_globals(Vec::new(), &log));

        let (sync_send, network_recv, beacon_processor_recv) =
            sync::manager::testing::spawn_for_testing(
                chain,
                network_globals.clone(),
                test_type,
                runtime.task_executor.clone(),
                log.clone(),
            );

        Self {
            harness,
            network_globals,
            sync_send,
            network_recv,
            received_network_messages: vec![],
            beacon_processor_recv,
            received_beacon_processor_events: vec![],
        }
    }

    /// Updates the syncing state of the node.
    pub fn set_node_sync_state(&mut self, sync_state: SyncState) -> &mut Self {
        self.network_globals.set_sync_state(sync_state);
        self
    }

    /// Sets the peer connection state. Add the peer to the `PeerDB` if it doesn't exist.
    pub fn set_peer_connected(
        &mut self,
        peer_id: &PeerId,
        new_state: NewConnectionState,
    ) -> &mut Self {
        self.network_globals
            .peers
            .write()
            .update_connection_state(peer_id, new_state);
        self
    }

    /// Sends a vec of `SyncMessage` to `SyncManager`, e.g. an RPC response or block processing
    /// result.
    pub fn send_sync_messages(&mut self, messages: Vec<SyncMessage<E>>) -> &mut Self {
        for msg in messages {
            self.sync_send
                .send(msg)
                .expect("SyncMessage to be sent to sync");
        }
        self
    }

    /// Alias of `self.send_sync_messages`. Sends an RPC response to `SyncManager`.
    pub fn send_rpc_response(&mut self, messages: Vec<SyncMessage<E>>) -> &mut Self {
        self.send_sync_messages(messages)
    }

    /// Checks the `network_recv` for a matching `NetworkMessage`. Useful for making assertions
    /// on events sent to the `NetworkService`, e.g. outgoing RPC requests.
    pub fn expect_rpc_request<F>(&mut self, match_fn: F) -> &mut Self
    where
        F: Fn(&NetworkMessage<E>) -> bool,
    {
        while let Ok(network_msg) = self.network_recv.try_recv() {
            self.received_network_messages.push(network_msg);
        }

        let match_found = self
            .received_network_messages
            .iter()
            .any(|network_msg| match_fn(network_msg));

        if !match_found {
            panic!("No matching network message or rpc request found");
        }

        self
    }

    /// Checks the `beacon_processor_recv` for a matching `WorkEvent`. Useful for making assertions
    /// on events sent to the `NetworkBeaconProcessor`, e.g. a chain segment sent for processing.
    pub fn expect_beacon_processor_send<F>(&mut self, match_fn: F) -> &mut Self
    where
        F: Fn(&WorkEvent<E>) -> bool,
    {
        while let Ok(work_event) = self.beacon_processor_recv.try_recv() {
            self.received_beacon_processor_events.push(work_event);
        }

        let match_found = self
            .received_beacon_processor_events
            .iter()
            .any(|work_event| match_fn(work_event));

        if !match_found {
            panic!("No matching work event found");
        }

        self
    }
}
