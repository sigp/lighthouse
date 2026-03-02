use super::*;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::network_context::RangeRequestId;
use crate::sync::range_sync::RangeSyncType;
use beacon_chain::BeaconChain;
use beacon_chain::block_verification_types::AvailableBlockData;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy, test_spec};
use beacon_chain::{EngineState, NotifyExecutionLayer, block_verification_types::RpcBlock};
use beacon_processor::WorkType;
use lighthouse_network::rpc::RequestType;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, DataColumnsByRangeRequest, OldBlocksByRangeRequest,
    OldBlocksByRangeRequestV2, StatusMessageV2,
};
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    SyncRequestId,
};
use lighthouse_network::{PeerId, SyncInfo};
use std::collections::HashSet;
use std::time::Duration;
use types::{
    BlobSidecarList, BlockImportSource, DataColumnSubnetId, Epoch, EthSpec, Hash256,
    MinimalEthSpec as E, SignedBeaconBlock, SignedBeaconBlockHash, Slot,
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
        self.add_supernode_peer(SyncInfo {
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
        self.add_supernode_peer(SyncInfo {
            finalized_epoch,
            finalized_root,
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
            earliest_available_slot: Some(Slot::new(0)),
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
            earliest_available_slot: Some(Slot::new(0)),
        }
    }

    fn local_info(&self) -> SyncInfo {
        let StatusMessageV2 {
            fork_digest: _,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
            earliest_available_slot,
        } = self.harness.chain.status_message().status_v2();
        SyncInfo {
            head_slot,
            head_root,
            finalized_epoch,
            finalized_root,
            earliest_available_slot: Some(earliest_available_slot),
        }
    }

    fn add_fullnode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.new_connected_peer();
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_supernode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        // Create valid peer known to network globals
        // TODO(fulu): Using supernode peers to ensure we have peer across all column
        // subnets for syncing. Should add tests connecting to full node peers.
        let peer_id = self.new_connected_supernode_peer();
        // Send peer to sync
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_fullnode_peers(&mut self, remote_info: SyncInfo, peer_count: usize) {
        for _ in 0..peer_count {
            let peer = self.new_connected_peer();
            self.send_sync_message(SyncMessage::AddPeer(peer, remote_info.clone()));
        }
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
    fn assert_chain_segments(&mut self, count: usize) {
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
            if let Some(expected_peer) = request_filter.peer
                && peer != expected_peer
            {
                return false;
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
                    app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            })
            .unwrap_or_else(|e| {
                panic!("Should have a BlocksByRange request, filter {request_filter:?}: {e:?}")
            });

        let by_range_data_requests = if self.is_after_fulu() {
            let mut data_columns_requests = vec![];
            while let Ok(data_columns_request) = self.pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request:
                        RequestType::DataColumnsByRange(DataColumnsByRangeRequest {
                            start_slot, ..
                        }),
                    app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            }) {
                data_columns_requests.push(data_columns_request);
            }
            if data_columns_requests.is_empty() {
                panic!("Found zero DataColumnsByRange requests, filter {request_filter:?}");
            }
            ByRangeDataRequestIds::PostPeerDAS(data_columns_requests)
        } else if self.is_after_deneb() {
            let (id, peer) = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request: RequestType::BlobsByRange(BlobsByRangeRequest { start_slot, .. }),
                        app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
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
            sync_request_id: SyncRequestId::BlocksByRange(blocks_req_id),
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
                    sync_request_id: SyncRequestId::BlobsByRange(id),
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
                        sync_request_id: SyncRequestId::DataColumnsByRange(id),
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
                .get_data_columns(&block_root, fork)
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
                build_rpc_block(block.into(), &data_sidecars, self.harness.chain.clone()),
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
    chain: Arc<BeaconChain<T>>,
) -> RpcBlock<E> {
    match data_sidecars {
        Some(DataSidecars::Blobs(blobs)) => {
            let block_data = AvailableBlockData::new_with_blobs(blobs.clone());
            RpcBlock::new(
                block,
                Some(block_data),
                &chain.data_availability_checker,
                chain.spec.clone(),
            )
            .unwrap()
        }
        Some(DataSidecars::DataColumns(columns)) => {
            let block_data = AvailableBlockData::new_with_data_columns(
                columns
                    .iter()
                    .map(|c| c.as_data_column().clone())
                    .collect::<Vec<_>>(),
            );
            RpcBlock::new(
                block,
                Some(block_data),
                &chain.data_availability_checker,
                chain.spec.clone(),
            )
            .unwrap()
        }
        // Block has no data, expects zero columns
        None => RpcBlock::new(
            block,
            Some(AvailableBlockData::NoData),
            &chain.data_availability_checker,
            chain.spec.clone(),
        )
        .unwrap(),
    }
}

#[test]
fn head_chain_removed_while_finalized_syncing() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2821
    let mut rig = TestRig::default();

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
    let mut rig = TestRig::with_custody_type(NodeCustodyType::SemiSupernode);

    // Create blocks on a separate harness
    // SemiSupernode ensures enough columns are stored for sampling + custody RPC block validation
    let mut rig_2 = TestRig::with_custody_type(NodeCustodyType::SemiSupernode);
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
    let mut rig = TestRig::default();

    // add some peers
    let peer1 = rig.add_head_peer();
    // make the ee offline
    rig.update_execution_engine_state(EngineState::Offline);
    // send the response to the request
    rig.find_and_complete_blocks_by_range_request(filter().peer(peer1).epoch(0));
    // the beacon processor shouldn't have received any work
    rig.assert_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let _peer2 = rig.add_finalized_peer();

    // send the response to the request
    // Don't filter requests and the columns requests may be sent to peer1 or peer2
    // We need to filter by epoch, because the previous batch eagerly sent requests for the next
    // epoch for the other batch. So we can either filter by epoch of by sync type.
    rig.find_and_complete_blocks_by_range_request(filter().epoch(0));
    // the beacon processor shouldn't have received any work
    rig.assert_empty_processor();
    // make the beacon processor available again.
    // update_execution_engine_state implicitly calls resume
    // now resume range, we should have two processing requests in the beacon processor.
    rig.update_execution_engine_state(EngineState::Online);

    // The head chain and finalized chain (2) should be in the processing queue
    rig.assert_chain_segments(2);
}

/// To attempt to finalize the peer's status finalized checkpoint we synced to its finalized epoch +
/// 2 epochs + 1 slot.
const EXTRA_SYNCED_EPOCHS: u64 = 2 + 1;

#[test]
fn finalized_sync_enough_global_custody_peers_few_chain_peers() {
    // Run for all forks
    let mut r = TestRig::default();

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Generate enough peers and supernodes to cover all custody columns
    let peer_count = 100;
    r.add_fullnode_peers(remote_info.clone(), peer_count);
    r.add_supernode_peer(remote_info);
    r.assert_state(RangeSyncType::Finalized);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}

#[test]
fn finalized_sync_not_enough_custody_peers_on_start() {
    let mut r = TestRig::default();
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Unikely that the single peer we added has enough columns for us. Tests are deterministic and
    // this error should never be hit
    r.add_fullnode_peer(remote_info.clone());
    r.assert_state(RangeSyncType::Finalized);

    // Because we don't have enough peers on all columns we haven't sent any request.
    // NOTE: There's a small chance that this single peer happens to custody exactly the set we
    // expect, in that case the test will fail. Find a way to make the test deterministic.
    r.assert_empty_network();

    // Generate enough peers and supernodes to cover all custody columns
    let peer_count = 100;
    r.add_fullnode_peers(remote_info.clone(), peer_count);
    r.add_supernode_peer(remote_info);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}

/// This is a regression test for the following race condition scenario:
/// 1. A node is connected to 3 supernode peers: peer 1 is synced, & peer 2 and 3 are advanced.
/// 2. No metadata has been received yet (i.e. no custody info), so the node cannot start data
///    column range sync yet.
/// 3. Now peer 1 sends the CGC via metadata response, we now have one peer on all custody subnets,
///    BUT not on the finalized syncing chain.
/// 4. The node tries to `send_batch` but fails repeatedly with `NoPeers`, as there's no peer
///    that is able to serve columns for the advanced epochs. The chain is removed after 5 failed attempts.
/// 5. Now peer 2 & 3 send CGC updates, BUT because there's no syncing chain, nothing happens -
///    sync is stuck until finding new peers.
///
/// The expected behaivour in this scenario should be:
/// 4. not finding suitable peers, chain is kept and batch remains in AwaitingDownload
/// 5. finalized sync should resume as soon as CGC updates are received from peer 2 or 3.
#[test]
fn finalized_sync_not_enough_custody_peers_resume_after_peer_cgc_update() {
    // Only run post-PeerDAS
    if !test_spec::<E>().is_fulu_scheduled() {
        return;
    }
    let mut r = TestRig::default();

    // GIVEN: the node is connected to 3 supernode peers:

    // Peer 1 is synced (same finalized epoch)
    let peer_1 = r.new_connected_supernode_peer_no_metadata_custody_subnet();
    let remote_info = r.local_info().clone();
    r.send_sync_message(SyncMessage::AddPeer(peer_1, remote_info));

    // Peer 2 is advanced (local finalized epoch + 2)
    let advanced_epochs: u64 = 2;
    let peer_2 = r.new_connected_supernode_peer_no_metadata_custody_subnet();
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());
    r.send_sync_message(SyncMessage::AddPeer(peer_2, remote_info.clone()));
    // We expect a finalized chain to be created with peer 2, but no requests sent out yet due to missing custody info.
    r.assert_state(RangeSyncType::Finalized);
    r.assert_empty_network();

    // Peer 3 is connected and advanced
    let peer_3 = r.new_connected_supernode_peer_no_metadata_custody_subnet();
    r.send_sync_message(SyncMessage::AddPeer(peer_3, remote_info));
    // We are still in finalized sync state (now with peer 3 added)
    r.assert_state(RangeSyncType::Finalized);

    for (i, p) in [peer_1, peer_2, peer_3].iter().enumerate() {
        let peer_idx = i + 1;
        r.log(&format!("Peer {peer_idx}: {p:?}"));
    }

    // WHEN: peer 1 sends its CGC via metadata response
    let all_custody_subnets = (0..r.harness.spec.data_column_sidecar_subnet_count)
        .map(|i| i.into())
        .collect::<HashSet<_>>();
    r.send_peer_cgc_update_to_sync(&peer_1, all_custody_subnets.clone());

    // We still don't have any peers on the syncing chain with custody columns (peer 1 & 2)
    // The node won't send the batch and will remain in the finalized sync state (this was failing before!)
    r.assert_state(RangeSyncType::Finalized);

    // Now we receive peer 2 & 3's CGC updates, the node will resume syncing from these two peers
    r.send_peer_cgc_update_to_sync(&peer_2, all_custody_subnets.clone());
    r.send_peer_cgc_update_to_sync(&peer_3, all_custody_subnets);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}
