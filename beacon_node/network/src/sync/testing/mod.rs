use rand::SeedableRng;
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use beacon_chain::block_verification_types::AsBlock;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;

use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::{generate_rand_block_and_blobs, BeaconChainHarness, NumBlobs};
use beacon_processor::WorkEvent;
use lighthouse_network::discovery::CombinedKey;
use lighthouse_network::discv5::enr::Enr;
use lighthouse_network::peer_manager::peerdb::NewConnectionState;
use lighthouse_network::types::SyncState;
use lighthouse_network::{ConnectionDirection, Multiaddr, NetworkGlobals, PeerId};
use slot_clock::{ManualSlotClock, SlotClock, TestingSlotClock};
use store::MemoryStore;
use types::test_utils::XorShiftRng;
use types::{
    BlobSidecar, EthSpec, ForkName, FullPayload, Hash256, MinimalEthSpec as E, SignedBeaconBlock,
    Slot,
};

use crate::service::RequestId;
use crate::sync::SyncMessage;
use crate::{sync, NetworkMessage};

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
//                      | BeaconProcessor |
//                      +---------+-------+
//                             ^  |
//                             |  |
//                   WorkEvent |  | SyncMsg
//                             |  | (Result)
//                             |  v
// +--------+            +-----+-----------+             +----------------+
// | Router +----------->|  SyncManager    +------------>| NetworkService |
// +--------+  SyncMsg   +-----------------+ NetworkMsg  +----------------+
//           (RPC resp)  |  - RangeSync    |  (RPC req)
//                       +-----------------+
//                       |  - BackFillSync |
//                       +-----------------+
//                       |  - BlockLookups |
//                       +-----------------+
pub struct SyncTester {
    pub harness: BeaconChainHarness<T>,
    /// Used for storing test variables. It allows setting variables in one step and recall them in
    /// a later step, e.g. `request_id` for an RPC request.
    test_context: HashMap<String, Box<dyn Any>>,
    network_globals: Arc<NetworkGlobals<E>>,
    /// Sender for `SyncMessage`. For sending RPC responses or block processing results to sync.
    sync_send: UnboundedSender<SyncMessage<E>>,
    /// Receiver for `NetworkMessage` (e.g. outgoing RPC requests from sync)
    network_recv: UnboundedReceiver<NetworkMessage<E>>,
    /// Stores all `NetworkMessage`s received from `network_recv`. (e.g. outgoing RPC requests)
    received_network_messages: Vec<NetworkMessage<E>>,
    /// Receiver for `BeaconProcessor` events (e.g. block processing results).
    beacon_processor_recv: Receiver<WorkEvent<E>>,
    /// Stores all `WorkEvent`s received from `beacon_processor_recv`.
    received_beacon_processor_events: Vec<WorkEvent<E>>,
    /// `rng` for generating test blocks and blobs.
    rng: XorShiftRng,
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
            .spec(ForkName::Deneb.make_genesis_spec(E::default_spec()))
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
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

        let rng = XorShiftRng::from_seed([42; 16]);

        Self {
            harness,
            test_context: Default::default(),
            network_globals,
            sync_send,
            network_recv,
            received_network_messages: vec![],
            beacon_processor_recv,
            received_beacon_processor_events: vec![],
            rng,
        }
    }

    /// Create a chain of block and blobs and store in `self.test_context`.
    pub fn create_block_chain(
        &mut self,
        num_blocks: usize,
    ) -> (
        VecDeque<Arc<SignedBeaconBlock<E, FullPayload<E>>>>,
        VecDeque<Vec<Arc<BlobSidecar<E>>>>,
    ) {
        // TODO get fork name from env var?
        let fork_name = ForkName::Deneb;
        let (block, blobs) = self.rand_block_and_blobs(fork_name, NumBlobs::Random);
        let mut block = Arc::new(block);
        let mut blobs = blobs.into_iter().map(Arc::new).collect::<Vec<_>>();
        let mut block_chain = VecDeque::with_capacity(num_blocks);
        let mut blobs_chain = VecDeque::with_capacity(num_blocks);
        let num_parents = num_blocks - 1;
        for _ in 0..num_parents {
            // Set the current  block as the parent.
            let parent_root = block.canonical_root();
            let parent_block = block.clone();
            let parent_blobs = blobs.clone();
            block_chain.push_front(parent_block);
            blobs_chain.push_front(parent_blobs);

            // Create the next block.
            let (child_block, child_blobs) =
                self.block_with_parent_and_blobs(parent_root, fork_name, NumBlobs::Number(2));
            let mut child_block = Arc::new(child_block);
            let mut child_blobs = child_blobs.into_iter().map(Arc::new).collect::<Vec<_>>();

            // Update the new block to the current block.
            std::mem::swap(&mut child_block, &mut block);
            std::mem::swap(&mut child_blobs, &mut blobs);
        }

        block_chain.push_front(block);
        blobs_chain.push_front(blobs);
        (block_chain, blobs_chain)
    }

    /// Updates the syncing state of the node.
    pub fn set_node_sync_state(&mut self, sync_state: SyncState) -> &mut Self {
        self.network_globals.set_sync_state(sync_state);
        self
    }

    /// Sets the peer connection state. Add the peer to the `PeerDB` if it doesn't exist.
    pub fn add_connected_peer(&mut self, peer_id: &PeerId) -> &mut Self {
        self.network_globals
            .peers
            .write()
            .update_connection_state(peer_id, connected_connection_state());
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
    ///
    /// The matching `request_id` will be stored in the `self.test_context` map, keyed by the
    /// `key_for_req_id` parameter.
    pub async fn expect_rpc_request<F>(&mut self, key_for_req_id: &str, match_fn: F) -> &mut Self
    where
        F: Fn(&NetworkMessage<E>) -> bool,
    {
        // Retry needed here because we need to wait for sync to process messages.
        let result = with_retry(5, Duration::from_millis(10), || {
            while let Ok(network_msg) = self.network_recv.try_recv() {
                self.received_network_messages.push(network_msg);
            }

            let match_found = self
                .received_network_messages
                .iter()
                .find(|network_msg| match_fn(network_msg));

            match match_found {
                Some(NetworkMessage::SendRequest {
                    request_id: RequestId::Sync(request_id),
                    ..
                }) => Ok(request_id.clone()),
                _ => Err("No matching rpc request found"),
            }
        })
        .await;

        if let Ok(request_id) = result {
            self.test_context
                .insert(key_for_req_id.to_string(), Box::new(request_id));
        } else {
            panic!("{}", result.unwrap_err());
        }

        self
    }

    /// Checks the `beacon_processor_recv` for a matching `WorkEvent`. Useful for making assertions
    /// on events sent to the `NetworkBeaconProcessor`, e.g. a chain segment sent for processing.
    pub async fn expect_beacon_processor_send<F>(&mut self, match_fn: F) -> &mut Self
    where
        F: Fn(&WorkEvent<E>) -> bool,
    {
        let result = with_retry(5, Duration::from_millis(10), || {
            while let Ok(work_event) = self.beacon_processor_recv.try_recv() {
                self.received_beacon_processor_events.push(work_event);
            }

            let match_found = self
                .received_beacon_processor_events
                .iter()
                .any(|work_event| match_fn(work_event));

            if !match_found {
                return Err("No matching work event found");
            }

            Ok(())
        })
        .await;

        if result.is_err() {
            panic!("{}", result.unwrap_err());
        }

        self
    }

    /// Polls the `network_recv` for some time and make sure no `NetworkMessage::ReportPeer` is received.
    pub async fn expect_no_penalty(&mut self) -> &mut Self {
        // Retry needed here because we need to wait for sync to process messages.
        let max_retries = 5;
        let interval = Duration::from_millis(10);

        let mut try_count = 0;
        loop {
            while let Ok(msg) = self.network_recv.try_recv() {
                self.received_network_messages.push(msg);
            }

            let peer_penalty_found = self
                .received_network_messages
                .iter()
                .any(|msg| matches!(msg, NetworkMessage::ReportPeer { .. }));

            assert_eq!(peer_penalty_found, false);

            if try_count >= max_retries {
                break;
            }
            try_count += 1;
            sleep(interval).await
        }

        self
    }

    /// Get a test variable of type `T` stored in `self.text_context` from previous steps.
    pub fn get_from_context<T: 'static>(&self, key: &str) -> Option<&T> {
        self.test_context
            .get(key)
            .and_then(|val| val.downcast_ref::<T>())
    }

    fn rand_block_and_blobs(
        &mut self,
        fork_name: ForkName,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let rng = &mut self.rng;
        generate_rand_block_and_blobs::<E>(fork_name, num_blobs, rng)
    }

    fn block_with_parent_and_blobs(
        &mut self,
        parent_root: Hash256,
        fork_name: ForkName,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let (mut block, mut blobs) = self.rand_block_and_blobs(fork_name, num_blobs);
        *block.message_mut().parent_root_mut() = parent_root;
        blobs.iter_mut().for_each(|blob| {
            blob.signed_block_header = block.signed_block_header();
        });
        (block, blobs)
    }
}

/// Executes the function with a specified number of retries if the function returns an error.
/// Once it exceeds `max_retries` and still fails, the error is returned.
async fn with_retry<T, E, F>(max_retries: usize, interval: Duration, mut func: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: Debug,
{
    let mut retry_count = 0;
    loop {
        let result = func();
        if result.is_ok() || retry_count >= max_retries {
            break result;
        }
        retry_count += 1;
        sleep(interval).await
    }
}

fn connected_connection_state() -> NewConnectionState {
    let enr_key = CombinedKey::generate_secp256k1();
    let enr = Enr::builder().build(&enr_key).unwrap();
    NewConnectionState::Connected {
        enr: Some(enr),
        seen_address: Multiaddr::empty(),
        direction: ConnectionDirection::Outgoing,
    }
}
