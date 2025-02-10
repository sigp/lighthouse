use super::*;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::status::ToStatusMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::network_context::RangeRequestId;
use crate::sync::range_sync::RangeSyncType;
use crate::sync::SyncMessage;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_chain::{block_verification_types::RpcBlock, EngineState, NotifyExecutionLayer};
use beacon_processor::WorkType;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, DataColumnsByRangeRequest, OldBlocksByRangeRequest,
    OldBlocksByRangeRequestV2,
};
use lighthouse_network::rpc::{RequestType, StatusMessage};
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    SyncRequestId,
};
use lighthouse_network::{PeerId, SyncInfo};
use std::time::Duration;
use types::{
    BlobSidecarList, BlockImportSource, Epoch, EthSpec, Hash256, MinimalEthSpec as E,
    SignedBeaconBlock, SignedBeaconBlockHash, Slot,
};

const D: Duration = Duration::new(0, 0);

pub(crate) enum DataSidecars<E: EthSpec> {
    Blobs(BlobSidecarList<E>),
    DataColumns(Vec<CustodyDataColumn<E>>),
}

enum ByRangeDataRequestIds {
    PreDeneb,
    PrePeerDAS(BlobsByRangeRequestId, PeerId),
    PostPeerDAS(Vec<(DataColumnsByRangeRequestId, PeerId)>),
}

/// Sync tests are usually written in the form:
/// - Do some action
/// - Expect a request to be sent
/// - Complete the above request
///
/// To make writting tests succint, the machinery in this testing rig automatically identifies
/// _which_ request to complete. Picking the right request is critical for tests to pass, so this
/// filter allows better expressivity on the criteria to identify the right request.
#[derive(Default, Debug, Clone)]
struct RequestFilter {
    peer: Option<PeerId>,
    epoch: Option<u64>,
}

impl RequestFilter {
    fn peer(mut self, peer: PeerId) -> Self {
        self.peer = Some(peer);
        self
    }

    fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(epoch);
        self
    }
}

fn filter() -> RequestFilter {
    RequestFilter::default()
}

impl TestRig {
    /// Produce a head peer with an advanced head
    fn add_head_peer(&mut self) -> PeerId {
        self.add_head_peer_with_root(Hash256::random())
    }

    /// Produce a head peer with an advanced head
    fn add_head_peer_with_root(&mut self, head_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        self.add_random_peer(SyncInfo {
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
        self.add_random_peer(SyncInfo {
            finalized_epoch,
            finalized_root,
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
        })
    }

    fn finalized_remote_info_advanced_by(&self, advanced_epochs: Epoch) -> SyncInfo {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + advanced_epochs;
        SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
        }
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

    fn add_random_peer_not_supernode(&mut self, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.new_connected_peer();
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_random_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        // Create valid peer known to network globals
        // TODO(fulu): Using supernode peers to ensure we have peer across all column
        // subnets for syncing. Should add tests connecting to full node peers.
        let peer_id = self.new_connected_supernode_peer();
        // Send peer to sync
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_random_peers(&mut self, remote_info: SyncInfo, count: usize) {
        for _ in 0..count {
            let peer = self.new_connected_peer();
            self.add_peer(peer, remote_info.clone());
        }
    }

    fn add_peer(&mut self, peer: PeerId, remote_info: SyncInfo) {
        self.send_sync_message(SyncMessage::AddPeer(peer, remote_info));
    }

    fn assert_state(&self, state: RangeSyncType) {
        assert_eq!(
            self.sync_manager
                .range_sync_state()
                .expect("State is ok")
                .expect("Range should be syncing, there are no chains")
                .0,
            state,
            "not expected range sync state"
        );
    }

    fn assert_no_chains_exist(&self) {
        if let Some(chain) = self.sync_manager.get_range_sync_chains().unwrap() {
            panic!("There still exists a chain {chain:?}");
        }
    }

    fn assert_no_failed_chains(&mut self) {
        assert_eq!(
            self.sync_manager.__range_failed_chains(),
            Vec::<Hash256>::new(),
            "Expected no failed chains"
        )
    }

    #[track_caller]
    fn expect_chain_segments(&mut self, count: usize) {
        for i in 0..count {
            self.pop_received_processor_event(|ev| {
                (ev.work_type() == beacon_processor::WorkType::ChainSegment).then_some(())
            })
            .unwrap_or_else(|e| panic!("Expect ChainSegment work event count {i}: {e:?}"));
        }
    }

    fn update_execution_engine_state(&mut self, state: EngineState) {
        self.log(&format!("execution engine state updated: {state:?}"));
        self.sync_manager.update_execution_engine_state(state);
    }

    fn find_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> ((BlocksByRangeRequestId, PeerId), ByRangeDataRequestIds) {
        let filter_f = |peer: PeerId, start_slot: u64| {
            if let Some(expected_epoch) = request_filter.epoch {
                let epoch = Slot::new(start_slot).epoch(E::slots_per_epoch()).as_u64();
                if epoch != expected_epoch {
                    return false;
                }
            }
            if let Some(expected_peer) = request_filter.peer {
                if peer != expected_peer {
                    return false;
                }
            }
            true
        };

        let block_req = self
            .pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request:
                        RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(
                            OldBlocksByRangeRequestV2 { start_slot, .. },
                        )),
                    request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            })
            .unwrap_or_else(|e| {
                panic!("Should have a BlocksByRange request, filter {request_filter:?}: {e:?}")
            });

        let by_range_data_requests = if self.after_fulu() {
            let mut data_columns_requests = vec![];
            while let Ok(data_columns_request) = self.pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request:
                        RequestType::DataColumnsByRange(DataColumnsByRangeRequest {
                            start_slot, ..
                        }),
                    request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            }) {
                data_columns_requests.push(data_columns_request);
            }
            if data_columns_requests.is_empty() {
                panic!("Found zero DataColumnsByRange requests, filter {request_filter:?}");
            }
            ByRangeDataRequestIds::PostPeerDAS(data_columns_requests)
        } else if self.after_deneb() {
            let (id, peer) = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request: RequestType::BlobsByRange(BlobsByRangeRequest { start_slot, .. }),
                        request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
                    } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                    _ => None,
                })
                .unwrap_or_else(|e| {
                    panic!("Should have a blobs by range request, filter {request_filter:?}: {e:?}")
                });
            ByRangeDataRequestIds::PrePeerDAS(id, peer)
        } else {
            ByRangeDataRequestIds::PreDeneb
        };

        (block_req, by_range_data_requests)
    }

    fn find_and_complete_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> RangeRequestId {
        let ((blocks_req_id, block_peer), by_range_data_request_ids) =
            self.find_blocks_by_range_request(request_filter);

        // Complete the request with a single stream termination
        self.log(&format!(
            "Completing BlocksByRange request {blocks_req_id:?} with empty stream"
        ));
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::BlocksByRange(blocks_req_id),
            peer_id: block_peer,
            beacon_block: None,
            seen_timestamp: D,
        });

        match by_range_data_request_ids {
            ByRangeDataRequestIds::PreDeneb => {}
            ByRangeDataRequestIds::PrePeerDAS(id, peer_id) => {
                // Complete the request with a single stream termination
                self.log(&format!(
                    "Completing BlobsByRange request {id:?} with empty stream"
                ));
                self.send_sync_message(SyncMessage::RpcBlob {
                    request_id: SyncRequestId::BlobsByRange(id),
                    peer_id,
                    blob_sidecar: None,
                    seen_timestamp: D,
                });
            }
            ByRangeDataRequestIds::PostPeerDAS(data_column_req_ids) => {
                // Complete the request with a single stream termination
                for (id, peer_id) in data_column_req_ids {
                    self.log(&format!(
                        "Completing DataColumnsByRange request {id:?} with empty stream"
                    ));
                    self.send_sync_message(SyncMessage::RpcDataColumn {
                        request_id: SyncRequestId::DataColumnsByRange(id),
                        peer_id,
                        data_column: None,
                        seen_timestamp: D,
                    });
                }
            }
        }

        blocks_req_id.parent_request_id.requester
    }

    fn find_and_complete_processing_chain_segment(&mut self, id: ChainSegmentProcessId) {
        self.pop_received_processor_event(|ev| {
            (ev.work_type() == WorkType::ChainSegment).then_some(())
        })
        .unwrap_or_else(|e| panic!("Expected chain segment work event: {e}"));

        self.log(&format!(
            "Completing ChainSegment processing work {id:?} with success"
        ));
        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: id,
            result: crate::sync::BatchProcessResult::Success {
                sent_blocks: 8,
                imported_blocks: 8,
            },
        });
    }

    fn complete_and_process_range_sync_until(
        &mut self,
        last_epoch: u64,
        request_filter: RequestFilter,
    ) {
        for epoch in 0..last_epoch {
            // Note: In this test we can't predict the block peer
            let id =
                self.find_and_complete_blocks_by_range_request(request_filter.clone().epoch(epoch));
            if let RangeRequestId::RangeSync { batch_id, .. } = id {
                assert_eq!(batch_id.as_u64(), epoch, "Unexpected batch_id");
            } else {
                panic!("unexpected RangeRequestId {id:?}");
            }

            let id = match id {
                RangeRequestId::RangeSync { chain_id, batch_id } => {
                    ChainSegmentProcessId::RangeBatchId(chain_id, batch_id)
                }
                RangeRequestId::BackfillSync { batch_id } => {
                    ChainSegmentProcessId::BackSyncBatchId(batch_id)
                }
            };

            self.find_and_complete_processing_chain_segment(id);
            if epoch < last_epoch - 1 {
                self.assert_state(RangeSyncType::Finalized);
            } else {
                self.assert_no_chains_exist();
                self.assert_no_failed_chains();
            }
        }
    }

    async fn create_canonical_block(&mut self) -> (SignedBeaconBlock<E>, Option<DataSidecars<E>>) {
        self.harness.advance_slot();

        let block_root = self
            .harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let store = &self.harness.chain.store;
        let block = store.get_full_block(&block_root).unwrap().unwrap();
        let fork = block.fork_name_unchecked();

        let data_sidecars = if fork.fulu_enabled() {
            store
                .get_data_columns(&block_root)
                .unwrap()
                .map(|columns| {
                    columns
                        .into_iter()
                        .map(CustodyDataColumn::from_asserted_custody)
                        .collect()
                })
                .map(DataSidecars::DataColumns)
        } else if fork.deneb_enabled() {
            store
                .get_blobs(&block_root)
                .unwrap()
                .blobs()
                .map(DataSidecars::Blobs)
        } else {
            None
        };

        (block, data_sidecars)
    }

    async fn remember_block(
        &mut self,
        (block, data_sidecars): (SignedBeaconBlock<E>, Option<DataSidecars<E>>),
    ) {
        // This code is kind of duplicated from Harness::process_block, but takes sidecars directly.
        let block_root = block.canonical_root();
        self.harness.set_current_slot(block.slot());
        let _: SignedBeaconBlockHash = self
            .harness
            .chain
            .process_block(
                block_root,
                build_rpc_block(block.into(), &data_sidecars, &self.spec),
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

fn build_rpc_block(
    block: Arc<SignedBeaconBlock<E>>,
    data_sidecars: &Option<DataSidecars<E>>,
    spec: &ChainSpec,
) -> RpcBlock<E> {
    match data_sidecars {
        Some(DataSidecars::Blobs(blobs)) => {
            RpcBlock::new(None, block, Some(blobs.clone())).unwrap()
        }
        Some(DataSidecars::DataColumns(columns)) => {
            RpcBlock::new_with_custody_columns(None, block, columns.clone(), spec).unwrap()
        }
        None => RpcBlock::new_without_blobs(None, block),
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
    let _ = rig.find_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer();
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(filter().peer(finalized_peer));

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
    let _ = rig.find_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer_with_root(finalized_peer_root);
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(filter().peer(finalized_peer));

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
    rig.find_and_complete_blocks_by_range_request(filter().peer(peer1).epoch(0));
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let _peer2 = rig.add_finalized_peer();

    // send the response to the request
    // Don't filter requests and the columns requests may be sent to peer1 or peer2
    // We need to filter by epoch, because the previous batch eagerly sent requests for the next
    // epoch for the other batch. So we can either filter by epoch of by sync type.
    rig.find_and_complete_blocks_by_range_request(filter().epoch(0));
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();
    // make the beacon processor available again.
    // update_execution_engine_state implicitly calls resume
    // now resume range, we should have two processing requests in the beacon processor.
    rig.update_execution_engine_state(EngineState::Online);

    // The head chain and finalized chain (2) should be in the processing queue
    rig.expect_chain_segments(2);
}

/// To attempt to finalize the peer's status finalized checkpoint we synced to its finalized epoch +
/// 2 epochs + 1 slot.
const EXTRA_SYNCED_EPOCHS: u64 = 2 + 1;

#[test]
fn finalized_sync_enough_global_custody_peers_few_chain_peers() {
    // Run for all forks
    let mut r = TestRig::test_setup();
    // This test creates enough global custody peers to satisfy column queries but only adds few
    // peers to the chain
    r.new_connected_peers_for_peerdas();

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Current priorization only sends batches to idle peers, so we need enough peers for each batch
    // TODO: Test this with a single peer in the chain, it should still work
    r.add_random_peers(
        remote_info,
        (advanced_epochs + EXTRA_SYNCED_EPOCHS) as usize,
    );
    r.assert_state(RangeSyncType::Finalized);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}

#[test]
fn finalized_sync_not_enough_custody_peers_on_start() {
    let mut r = TestRig::test_setup();
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Unikely that the single peer we added has enough columns for us. Tests are determinstic and
    // this error should never be hit
    r.add_random_peer_not_supernode(remote_info.clone());
    r.assert_state(RangeSyncType::Finalized);

    // Because we don't have enough peers on all columns we haven't sent any request.
    // NOTE: There's a small chance that this single peer happens to custody exactly the set we
    // expect, in that case the test will fail. Find a way to make the test deterministic.
    r.expect_empty_network();

    // Generate enough peers and supernodes to cover all custody columns
    r.new_connected_peers_for_peerdas();
    // Note: not necessary to add this peers to the chain, as we draw from the global pool
    // We still need to add enough peers to trigger batch downloads with idle peers. Same issue as
    // the test above.
    r.add_random_peers(
        remote_info,
        (advanced_epochs + EXTRA_SYNCED_EPOCHS - 1) as usize,
    );

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}
