use super::*;
use crate::status::ToStatusMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::range_sync::{BatchId, BlockStorage, RangeSyncType};
use crate::sync::{ChainId, SyncMessage};
use beacon_chain::parking_lot::RwLock;
use beacon_chain::test_utils::BlockStrategy;
use beacon_chain::EngineState;
use bls::FixedBytesExtended;
use lighthouse_network::rpc::{RequestType, StatusMessage};
use lighthouse_network::service::api_types::{AppRequestId, Id, SyncRequestId};
use lighthouse_network::{PeerId, SyncInfo};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use types::{EthSpec, Hash256, MinimalEthSpec as E, SignedBeaconBlock, Slot};

const D: Duration = Duration::new(0, 0);

#[derive(Debug)]
pub struct FakeStorage {
    known_blocks: RwLock<HashSet<Hash256>>,
    status: RwLock<StatusMessage>,
}

impl Default for FakeStorage {
    fn default() -> Self {
        FakeStorage {
            known_blocks: RwLock::new(HashSet::new()),
            status: RwLock::new(StatusMessage {
                fork_digest: [0; 4],
                finalized_root: Hash256::zero(),
                finalized_epoch: 0usize.into(),
                head_root: Hash256::zero(),
                head_slot: 0usize.into(),
            }),
        }
    }
}

impl FakeStorage {
    fn remember_block(&self, block_root: Hash256) {
        self.known_blocks.write().insert(block_root);
    }

    #[allow(dead_code)]
    fn forget_block(&self, block_root: &Hash256) {
        self.known_blocks.write().remove(block_root);
    }
}

impl BlockStorage for FakeStorage {
    fn is_block_known(&self, block_root: &store::Hash256) -> bool {
        self.known_blocks.read().contains(block_root)
    }
}

impl ToStatusMessage for FakeStorage {
    fn status_message(&self) -> StatusMessage {
        self.status.read().clone()
    }
}

type PeerTestInfo = (PeerId, SyncInfo /* Remote info */);

impl TestRig {
    /// Produce a head peer with an advanced head
    fn add_head_peer(&mut self) -> PeerTestInfo {
        let local_info = self.local_info();
        self.add_peer(SyncInfo {
            head_root: Hash256::random(),
            head_slot: local_info.head_slot + 1 + Slot::new(SLOT_IMPORT_TOLERANCE as u64),
            ..local_info
        })
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer(&mut self) -> PeerTestInfo {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + 2;
        self.add_peer(SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
        })
    }

    fn local_info(&self) -> SyncInfo {
        let StatusMessage {
            fork_digest: _,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
        } = self.harness.chain.status_message();
        SyncInfo {
            head_slot,
            head_root,
            finalized_epoch,
            finalized_root,
        }
    }

    fn add_peer(&mut self, remote_info: SyncInfo) -> PeerTestInfo {
        // Create valid peer known to network globals
        let peer_id = self.new_connected_peer();
        // Send peer to sync
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info.clone()));
        (peer_id, remote_info)
    }

    fn assert_state(&self, state: RangeSyncType) {
        assert_eq!(
            self.sync_manager
                .range_sync_state()
                .expect("State is ok")
                .expect("Range should be syncing")
                .0,
            state,
            "not expected range sync state"
        );
    }

    #[track_caller]
    fn expect_chain_segment(&mut self) {
        self.pop_received_processor_event(|ev| {
            (ev.work_type() == beacon_processor::WorkType::ChainSegment).then_some(())
        })
        .unwrap_or_else(|e| panic!("Expect ChainSegment work event"));
    }

    fn update_execution_engine_state(&mut self, state: EngineState) {
        self.log(&format!("execution engine state updated: {state:?}"));
        self.sync_manager.update_execution_engine_state(state);
    }

    fn send_blocks_by_range_response(
        &mut self,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<E>>>,
        range_blocks_req_id: Id,
    ) {
        self.log("send_blocks_by_range_response");
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::RangeBlockAndBlobs {
                id: range_blocks_req_id,
            },
            peer_id,
            beacon_block,
            seen_timestamp: D,
        });
    }

    fn send_empty_blocks_by_range_response(
        &mut self,
        _peer_id: PeerId,
        _chain_id: ChainId,
        _batch_id: BatchId,
        _req_id: Id,
    ) {
        // Send empty vector of blocks to range sync
        // todo!();
    }

    fn complete_range_block_and_blobs_response(&mut self, peer_id: PeerId, req_id: Id) {
        // For all active requests associated with a block or blob request ID send the stream
        // terminator without blocks
        self.send_blocks_by_range_response(peer_id, None, req_id);
    }

    fn find_blocks_by_range_request(&mut self, target_peer_id: &PeerId) -> (Id, Option<Id>) {
        let block_req_id = self
            .pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request: RequestType::BlocksByRange(_),
                    request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
                } if peer_id == target_peer_id => Some(*id),
                _ => None,
            })
            .expect("Should have a blocks by range request");

        let blob_req_id = if self.after_deneb() {
            Some(
                self.pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request: RequestType::BlobsByRange(_),
                        request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
                    } if peer_id == target_peer_id => Some(*id),
                    _ => None,
                })
                .expect("Should have a blobs by range request"),
            )
        } else {
            None
        };

        (block_req_id, blob_req_id)
    }

    fn find_and_complete_blocks_by_range_request(&mut self, target_peer_id: PeerId) {
        let (blocks_req_id, blobs_req_id) = self.find_blocks_by_range_request(&target_peer_id);

        // Complete the request with a single stream termination
        self.log(&format!(
            "Completing BlocksByRange request {blocks_req_id} with empty stream"
        ));
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::RangeBlockAndBlobs { id: blocks_req_id },
            peer_id: target_peer_id,
            beacon_block: None,
            seen_timestamp: D,
        });

        if let Some(blobs_req_id) = blobs_req_id {
            // Complete the request with a single stream termination
            self.log(&format!(
                "Completing BlobsByRange request {blobs_req_id} with empty stream"
            ));
            self.send_sync_message(SyncMessage::RpcBlob {
                request_id: SyncRequestId::RangeBlockAndBlobs { id: blobs_req_id },
                peer_id: target_peer_id,
                blob_sidecar: None,
                seen_timestamp: D,
            });
        }
    }

    fn create_remembered_block(&mut self) -> Hash256 {
        // Add block to chain storage such that `knows block` returns true
        // block_on(self.harness.extend_chain(
        //    1,
        //    BlockStrategy::OnCanonicalHead,
        //    AttestationStrategy::AllValidators,
        // ));

        let block_root = self
            .harness
            .chain
            .canonical_head
            .cached_head()
            .head_block_root();

        todo!();
    }

    fn remember_block(&mut self, block: Hash256) {
        todo!();
    }
}

#[test]
fn head_chain_removed_while_finalized_syncing() {
    // NOTE: this is a regression test.
    let mut rig = TestRig::test_setup();

    // Get a peer with an advanced head
    let (head_peer, _) = rig.add_head_peer();
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(&head_peer);

    // Now get a peer with an advanced finalized epoch.
    let (finalized_peer, _) = rig.add_finalized_peer();
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(&finalized_peer);

    // Fail the head chain by disconnecting the peer.
    rig.peer_disconnected(head_peer);
    rig.assert_state(RangeSyncType::Finalized);
}

#[ignore]
#[test]
fn state_update_while_purging() {
    // NOTE: this is a regression test.
    let mut rig = TestRig::test_setup();

    // TODO: Need to create blocks that can be inserted into the fork-choice and fit the "known
    // conditions" below.
    let known_block_root_1 = rig.create_remembered_block();
    let known_block_root_2 = rig.create_remembered_block();

    // Get a peer with an advanced head
    let (head_peer, head_info) = rig.add_head_peer();
    let head_peer_root = head_info.head_root;
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(&head_peer);

    // Now get a peer with an advanced finalized epoch.
    let (finalized_peer, remote_info) = rig.add_finalized_peer();
    let finalized_peer_root = remote_info.finalized_root;
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(&finalized_peer);

    // Now the chain knows both chains target roots.
    rig.remember_block(head_peer_root);
    rig.remember_block(finalized_peer_root);

    // Add an additional peer to the second chain to make range update it's status
    rig.add_finalized_peer();
}

#[test]
fn pause_and_resume_on_ee_offline() {
    let mut rig = TestRig::test_setup();

    // add some peers
    let (peer1, _) = rig.add_head_peer();
    // make the ee offline
    rig.update_execution_engine_state(EngineState::Offline);
    // send the response to the request
    rig.find_and_complete_blocks_by_range_request(peer1);
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let (peer2, _) = rig.add_finalized_peer();

    // send the response to the request
    rig.find_and_complete_blocks_by_range_request(peer2);
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();
    // make the beacon processor available again.
    // update_execution_engine_state implicitly calls resume
    // now resume range, we should have two processing requests in the beacon processor.
    rig.update_execution_engine_state(EngineState::Online);

    rig.expect_chain_segment();
    rig.expect_chain_segment();
}
