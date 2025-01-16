use super::*;
use crate::status::ToStatusMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::range_sync::RangeSyncType;
use crate::sync::SyncMessage;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_chain::{block_verification_types::RpcBlock, EngineState, NotifyExecutionLayer};
use lighthouse_network::rpc::{RequestType, StatusMessage};
use lighthouse_network::service::api_types::{AppRequestId, Id, SyncRequestId};
use lighthouse_network::{PeerId, SyncInfo};
use std::time::Duration;
use types::{
    BlobSidecarList, BlockImportSource, EthSpec, Hash256, MinimalEthSpec as E, SignedBeaconBlock,
    SignedBeaconBlockHash, Slot,
};

const D: Duration = Duration::new(0, 0);

impl TestRig {
    /// Produce a head peer with an advanced head
    fn add_head_peer(&mut self) -> PeerId {
        self.add_head_peer_with_root(Hash256::random())
    }

    /// Produce a head peer with an advanced head
    fn add_head_peer_with_root(&mut self, head_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        self.add_peer(SyncInfo {
            head_root,
            head_slot: local_info.head_slot + 1 + Slot::new(SLOT_IMPORT_TOLERANCE as u64),
            ..local_info
        })
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer(&mut self) -> PeerId {
        self.add_finalized_peer_with_root(Hash256::random())
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer_with_root(&mut self, finalized_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + 2;
        self.add_peer(SyncInfo {
            finalized_epoch,
            finalized_root,
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

    fn add_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        // Create valid peer known to network globals
        let peer_id = self.new_connected_peer();
        // Send peer to sync
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info.clone()));
        peer_id
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
        .unwrap_or_else(|e| panic!("Expect ChainSegment work event: {e:?}"));
    }

    fn update_execution_engine_state(&mut self, state: EngineState) {
        self.log(&format!("execution engine state updated: {state:?}"));
        self.sync_manager.update_execution_engine_state(state);
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

    async fn create_canonical_block(
        &mut self,
    ) -> (SignedBeaconBlock<E>, Option<BlobSidecarList<E>>) {
        self.harness.advance_slot();

        let block_root = self
            .harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        // TODO(das): this does not handle data columns yet
        let store = &self.harness.chain.store;
        let block = store.get_full_block(&block_root).unwrap().unwrap();
        let blobs = if block.fork_name_unchecked().deneb_enabled() {
            store.get_blobs(&block_root).unwrap().blobs()
        } else {
            None
        };
        (block, blobs)
    }

    async fn remember_block(
        &mut self,
        (block, blob_sidecars): (SignedBeaconBlock<E>, Option<BlobSidecarList<E>>),
    ) {
        // This code is kind of duplicated from Harness::process_block, but takes sidecars directly.
        let block_root = block.canonical_root();
        self.harness.set_current_slot(block.slot());
        let _: SignedBeaconBlockHash = self
            .harness
            .chain
            .process_block(
                block_root,
                RpcBlock::new(Some(block_root), block.into(), blob_sidecars).unwrap(),
                NotifyExecutionLayer::Yes,
                BlockImportSource::RangeSync,
                || Ok(()),
            )
            .await
            .unwrap()
            .try_into()
            .unwrap();
        self.harness.chain.recompute_head_at_current_slot().await;
    }
}

#[test]
fn head_chain_removed_while_finalized_syncing() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2821
    let mut rig = TestRig::test_setup();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer();
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(&head_peer);

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer();
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(&finalized_peer);

    // Fail the head chain by disconnecting the peer.
    rig.peer_disconnected(head_peer);
    rig.assert_state(RangeSyncType::Finalized);
}

#[tokio::test]
async fn state_update_while_purging() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2827
    let mut rig = TestRig::test_setup();

    // Create blocks on a separate harness
    let mut rig_2 = TestRig::test_setup();
    // Need to create blocks that can be inserted into the fork-choice and fit the "known
    // conditions" below.
    let head_peer_block = rig_2.create_canonical_block().await;
    let head_peer_root = head_peer_block.0.canonical_root();
    let finalized_peer_block = rig_2.create_canonical_block().await;
    let finalized_peer_root = finalized_peer_block.0.canonical_root();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer_with_root(head_peer_root);
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(&head_peer);

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer_with_root(finalized_peer_root);
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(&finalized_peer);

    // Now the chain knows both chains target roots.
    rig.remember_block(head_peer_block).await;
    rig.remember_block(finalized_peer_block).await;

    // Add an additional peer to the second chain to make range update it's status
    rig.add_finalized_peer();
}

#[test]
fn pause_and_resume_on_ee_offline() {
    let mut rig = TestRig::test_setup();

    // add some peers
    let peer1 = rig.add_head_peer();
    // make the ee offline
    rig.update_execution_engine_state(EngineState::Offline);
    // send the response to the request
    rig.find_and_complete_blocks_by_range_request(peer1);
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let peer2 = rig.add_finalized_peer();

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
