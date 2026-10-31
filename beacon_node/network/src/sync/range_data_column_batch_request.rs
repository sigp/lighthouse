use std::collections::{HashMap, HashSet};

use crate::sync::block_sidecar_coupling::{ByRangeRequest, CouplingError};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::DataColumnsByRangeRequestId;
use std::sync::Arc;
use tracing::debug;
use types::{ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256, Slot};

pub struct RangeDataColumnBatchRequest<T: BeaconChainTypes> {
    requests: HashMap<
        DataColumnsByRangeRequestId,
        ByRangeRequest<DataColumnsByRangeRequestId, DataColumnSidecarList<T::EthSpec>>,
    >,
    /// The column indices corresponding to the request
    column_peers: HashMap<DataColumnsByRangeRequestId, Vec<ColumnIndex>>,
    expected_custody_columns: HashSet<ColumnIndex>,
    attempt: usize,
    beacon_chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
}

impl<T: BeaconChainTypes> RangeDataColumnBatchRequest<T> {
    pub fn new(
        by_range_requests: Vec<(DataColumnsByRangeRequestId, Vec<ColumnIndex>)>,
        beacon_chain: Arc<BeaconChain<T>>,
        epoch: Epoch,
    ) -> Self {
        let requests = by_range_requests
            .clone()
            .into_iter()
            .map(|(req, _)| (req, ByRangeRequest::Active(req)))
            .collect::<HashMap<_, _>>();

        let column_peers = by_range_requests.clone().into_iter().collect();

        let expected_custody_columns = by_range_requests
            .into_iter()
            .flat_map(|(_, column_indices)| column_indices)
            .collect();

        Self {
            requests,
            column_peers,
            expected_custody_columns,
            beacon_chain,
            epoch,
            attempt: 0,
        }
    }

    pub fn add_custody_columns(
        &mut self,
        req_id: DataColumnsByRangeRequestId,
        columns: Vec<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Result<(), String> {
        let req = self
            .requests
            .get_mut(&req_id)
            .ok_or(format!("unknown data columns by range req_id {req_id}"))?;
        req.finish(req_id, columns)
    }

    pub fn responses(
        &mut self,
    ) -> Option<Result<DataColumnSidecarList<T::EthSpec>, CouplingError>> {
        let mut received_columns_for_slot: HashMap<Slot, DataColumnSidecarList<T::EthSpec>> =
            HashMap::new();
        let mut column_to_peer_id: HashMap<u64, PeerId> = HashMap::new();

        for req in self.requests.values() {
            let Some(columns) = req.to_finished() else {
                return None;
            };

            for column in columns {
                received_columns_for_slot
                    .entry(column.slot())
                    .or_default()
                    .push(column.clone());
            }
        }

        // Note: this assumes that only 1 peer is responsible for a column
        // with a batch.
        for (id, columns) in self.column_peers.iter() {
            for column in columns {
                column_to_peer_id.insert(*column, id.peer);
            }
        }

        // An "attempt" is complete here after we have received a response for all the
        // requests we made. i.e. `req.to_finished()` returns Some for all requests.
        self.attempt += 1;

        let resp = self.responses_with_custody_columns(
            received_columns_for_slot,
            column_to_peer_id,
            &self.expected_custody_columns,
        );

        if let Err(CouplingError::DataColumnPeerFailure {
            error: _,
            faulty_peers,
        }) = &resp
        {
            for (_, peer) in faulty_peers.iter() {
                // find the req id associated with the peer and
                // delete it from the entries as we are going to make
                // a separate attempt for those components.
                self.requests.retain(|&k, _| k.peer != *peer);
            }
        }
        Some(resp)
    }

    fn responses_with_custody_columns(
        &self,
        mut received_columns_for_slot: HashMap<Slot, DataColumnSidecarList<T::EthSpec>>,
        column_to_peer: HashMap<ColumnIndex, PeerId>,
        expected_custody_columns: &HashSet<ColumnIndex>,
    ) -> Result<DataColumnSidecarList<T::EthSpec>, CouplingError> {
        let mut naughty_peers = vec![];
        let mut result: DataColumnSidecarList<T::EthSpec> = vec![];

        // Iterate past the end of the epoch to find the child of its last block. Custody backfill
        // only requests epochs followed by a finalized block, so the child is at or before the
        // split block. Stopping before the split slot avoids cloning the head state.
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let epoch_end_slot = self.epoch.end_slot(slots_per_epoch);
        let split = self.beacon_chain.store.get_split_info();
        let forward_blocks_iter = self
            .beacon_chain
            .forwards_iter_block_roots_until(
                self.epoch.start_slot(slots_per_epoch),
                std::cmp::max(epoch_end_slot, split.slot.saturating_sub(1u64)),
            )
            .map_err(|_| {
                CouplingError::InternalError("Failed to fetch block root iterator".to_string())
            })?;

        let mut block_roots = vec![];
        let mut next_epoch_child_root = None;
        for block_iter_result in forward_blocks_iter {
            let (block_root, slot) = block_iter_result.map_err(|_| {
                CouplingError::InternalError("Failed to iterate block roots".to_string())
            })?;
            if slot <= epoch_end_slot {
                block_roots.push((block_root, slot));
            } else if block_roots
                .last()
                .is_some_and(|(last_root, _)| *last_root != block_root)
            {
                next_epoch_child_root = Some(block_root);
                break;
            }
        }
        // Otherwise the child is the split block, unless the last block is the split block.
        if next_epoch_child_root.is_none() && split.slot > epoch_end_slot {
            next_epoch_child_root = block_roots
                .last()
                .filter(|(last_root, _)| *last_root != split.block_root)
                .map(|_| split.block_root);
        }

        // Load each block once. Skipped slots repeat the previous block root.
        let mut blocks = HashMap::new();
        for block_root in block_roots
            .iter()
            .map(|(block_root, _)| *block_root)
            .chain(next_epoch_child_root)
        {
            if blocks.contains_key(&block_root) {
                continue;
            }
            let Some(block) = self
                .beacon_chain
                .get_blinded_block(&block_root)
                .ok()
                .flatten()
            else {
                // The block root we are fetching is from the forwards block root iterator. This doesn't seem like a possible scenario.
                return Err(CouplingError::InternalError(
                    "Block root from forwards block iterator not found in db".to_string(),
                ));
            };
            blocks.insert(block_root, block);
        }

        // The child of each block is the next distinct block root.
        let mut child_roots = vec![None; block_roots.len()];
        let mut later: Option<(Hash256, Option<Hash256>)> = None;
        for (child_root, (block_root, _)) in child_roots.iter_mut().zip(&block_roots).rev() {
            *child_root = match later {
                Some((later_root, later_child)) if later_root == *block_root => later_child,
                Some((later_root, _)) => Some(later_root),
                None => next_epoch_child_root,
            };
            later = Some((*block_root, *child_root));
        }

        for ((block_root, slot), child_root) in block_roots.into_iter().zip(child_roots) {
            let Some(block) = blocks.get(&block_root) else {
                return Err(CouplingError::InternalError(
                    "Block root from forwards block iterator not loaded".to_string(),
                ));
            };

            // A Gloas block's payload was revealed if its child's bid builds on it. Withheld
            // payloads have no columns on the network. Without a finalized child the status isn't
            // final (`None`), so no columns are expected. Custody backfill doesn't request such
            // epochs.
            let payload_revealed = match block.message().body().signed_execution_payload_bid() {
                Ok(bid) => child_root
                    .and_then(|child_root| blocks.get(&child_root))
                    .map(|child| child.is_parent_block_full(bid.message().block_hash())),
                // Prior to Gloas.
                Err(_) => Some(true),
            };
            let expects_columns = block.slot() == slot
                && block.num_expected_blobs() != 0
                && payload_revealed == Some(true);

            let Some(columns) = received_columns_for_slot.remove(&slot) else {
                // If at least one blob is expected for this slot but none have been served, penalize all peers
                // The slot check ensures we arent checking a skipped slot.
                if expects_columns {
                    for column in expected_custody_columns {
                        if let Some(naughty_peer) = column_to_peer.get(column) {
                            naughty_peers.push((*column, *naughty_peer));
                        }
                    }
                }
                continue;
            };

            // This is a skipped slot, skip to the next slot after we verify that peers
            // didn't serve us columns for a skipped slot
            if block.slot() != slot {
                // If we received columns for a skipped slot, punish the peer
                if !columns.is_empty() {
                    for column in expected_custody_columns {
                        if let Some(naughty_peer) = column_to_peer.get(column) {
                            naughty_peers.push((*column, *naughty_peer));
                        }
                    }
                }

                continue;
            }

            // Columns for a payload that finalized as EMPTY belong to an abandoned payload, which
            // finalization pruning deletes. A peer that hasn't pruned yet may still serve them, so
            // drop them without penalizing it.
            if payload_revealed == Some(false) {
                if !columns.is_empty() {
                    debug!(
                        %block_root,
                        %slot,
                        count = columns.len(),
                        "Dropping columns served for a withheld payload"
                    );
                }
                continue;
            }

            let column_block_roots = columns
                .iter()
                .map(|column| column.block_root())
                .unique()
                .collect::<Vec<_>>();

            let column_block_signatures = columns
                .iter()
                .filter_map(|column| match column.as_ref() {
                    DataColumnSidecar::Fulu(column) => {
                        Some(column.signed_block_header.signature.clone())
                    }
                    _ => None,
                })
                .unique()
                .collect::<Vec<_>>();

            let column_block_root = match column_block_roots.as_slice() {
                // We expect a single unique block root
                [column_block_root] => *column_block_root,
                // If there are no block roots, penalize all peers
                [] => {
                    for column in &columns {
                        if let Some(naughty_peer) = column_to_peer.get(column.index()) {
                            naughty_peers.push((*column.index(), *naughty_peer));
                        }
                    }
                    continue;
                }
                // If theres more than one unique block root penalize the peers serving the bad block roots.
                column_block_roots => {
                    for column in columns {
                        if column_block_roots.contains(&column.block_root())
                            && block_root != column.block_root()
                            && let Some(naughty_peer) = column_to_peer.get(column.index())
                        {
                            naughty_peers.push((*column.index(), *naughty_peer));
                        }
                    }
                    continue;
                }
            };

            let column_block_signature = match column_block_signatures.as_slice() {
                // We expect a single unique block signature
                [block_signature] => Some(block_signature),
                // Gloas columns do not contain a signed block header.
                [] if block.fork_name_unchecked().gloas_enabled() => None,
                // Fulu columns must contain a signed block header.
                [] => {
                    for column in &columns {
                        if let Some(naughty_peer) = column_to_peer.get(column.index()) {
                            naughty_peers.push((*column.index(), *naughty_peer));
                        }
                    }
                    continue;
                }
                // If theres more than one unique block signature, penalize the peers serving the
                // invalid block signatures. This check is only relevant for Fulu.
                column_block_signatures => {
                    for column in columns {
                        if let DataColumnSidecar::Fulu(column) = column.as_ref()
                            && column_block_signatures
                                .contains(&column.signed_block_header.signature)
                            && block.signature() != &column.signed_block_header.signature
                            && let Some(naughty_peer) = column_to_peer.get(&column.index)
                        {
                            naughty_peers.push((column.index, *naughty_peer));
                        }
                    }
                    continue;
                }
            };

            // if the block root doesn't match the columns block root, penalize the peers
            if block_root != column_block_root {
                for column in &columns {
                    if let Some(naughty_peer) = column_to_peer.get(column.index()) {
                        naughty_peers.push((*column.index(), *naughty_peer));
                    }
                }
            }

            // Fulu columns must match the block signature.
            if let Some(column_block_signature) = column_block_signature
                && block.signature() != column_block_signature
            {
                for column in &columns {
                    if let Some(naughty_peer) = column_to_peer.get(column.index()) {
                        naughty_peers.push((*column.index(), *naughty_peer));
                    }
                }
            }

            let received_columns = columns.iter().map(|c| *c.index()).collect::<HashSet<_>>();

            let missing_columns = expected_custody_columns
                .difference(&received_columns)
                .collect::<HashSet<_>>();

            // blobs are expected for this slot but there is at least one missing columns
            // penalize the peers responsible for those columns.
            if expects_columns && !missing_columns.is_empty() {
                for column in missing_columns {
                    if let Some(naughty_peer) = column_to_peer.get(column) {
                        naughty_peers.push((*column, *naughty_peer));
                    };
                }
            }

            result.extend(columns);
        }

        if !naughty_peers.is_empty() {
            return Err(CouplingError::DataColumnPeerFailure {
                error: "Bad or missing columns for some slots".to_string(),
                faulty_peers: naughty_peers,
            });
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::WhenSlotSkipped;
    use beacon_chain::custody_context::NodeCustodyType;
    use beacon_chain::test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    };
    use lighthouse_network::service::api_types::{
        CustodyBackFillBatchRequestId, CustodyBackfillBatchId, DataColumnsByRangeRequester,
    };
    use types::{ForkName, Spec};

    type E = Spec;

    #[tokio::test]
    async fn valid_gloas_batch_completes_without_peer_failure() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();
        let block_root = harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let epoch = Epoch::new(0);
        let data_columns = harness
            .chain
            .store
            .get_data_columns(&block_root, ForkName::Gloas)
            .expect("should read data columns")
            .expect("should store data columns");

        assert!(!data_columns.is_empty());
        assert!(
            data_columns
                .iter()
                .all(|column| matches!(column.as_ref(), DataColumnSidecar::Gloas(_)))
        );

        let requested_columns = data_columns
            .iter()
            .map(|column| *column.index())
            .unique()
            .collect::<Vec<_>>();
        let peer = PeerId::random();
        let request_id = DataColumnsByRangeRequestId {
            id: 0,
            parent_request_id: DataColumnsByRangeRequester::CustodyBackfillSync(
                CustodyBackFillBatchRequestId {
                    id: 0,
                    batch_id: CustodyBackfillBatchId { epoch, run_id: 0 },
                },
            ),
            peer,
        };
        let mut request = RangeDataColumnBatchRequest::new(
            vec![(request_id, requested_columns)],
            harness.chain.clone(),
            epoch,
        );
        request
            .add_custody_columns(request_id, data_columns.clone())
            .expect("should complete request");

        match request.responses() {
            Some(Ok(received_columns)) => assert_eq!(received_columns, data_columns),
            response => panic!("expected valid Gloas columns, got {response:?}"),
        }
    }

    #[tokio::test]
    async fn withheld_gloas_payload_does_not_penalize_peers() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();

        // Import the block but withhold its payload envelope.
        let slot = Slot::new(1);
        let (block_contents, envelope, _) = harness
            .make_block_with_envelope(harness.get_current_state(), slot)
            .await;
        assert!(envelope.is_some());
        let block_root = block_contents.0.canonical_root();
        assert_ne!(block_contents.0.num_expected_blobs(), 0);
        harness
            .process_block(slot, block_root, block_contents)
            .await
            .expect("should import block");

        // The child builds on the EMPTY parent, which marks the payload as withheld.
        harness.advance_slot();
        let child_slot = Slot::new(2);
        let (child_contents, _, _) = harness
            .make_block_with_envelope(harness.get_current_state(), child_slot)
            .await;
        let child_root = child_contents.0.canonical_root();
        harness
            .process_block(child_slot, child_root, child_contents)
            .await
            .expect("should import child block");
        let block = harness
            .chain
            .get_blinded_block(&block_root)
            .unwrap()
            .unwrap();
        let child = harness
            .chain
            .get_blinded_block(&child_root)
            .unwrap()
            .unwrap();
        let bid_hash = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .unwrap()
            .message()
            .block_hash();
        assert!(!child.is_parent_block_full(bid_hash));

        let epoch = Epoch::new(0);
        let peer = PeerId::random();
        let request_id = DataColumnsByRangeRequestId {
            id: 0,
            parent_request_id: DataColumnsByRangeRequester::CustodyBackfillSync(
                CustodyBackFillBatchRequestId {
                    id: 0,
                    batch_id: CustodyBackfillBatchId { epoch, run_id: 0 },
                },
            ),
            peer,
        };
        let mut request = RangeDataColumnBatchRequest::new(
            vec![(request_id, vec![0, 1, 2, 3])],
            harness.chain.clone(),
            epoch,
        );
        request
            .add_custody_columns(request_id, vec![])
            .expect("should complete request");

        match request.responses() {
            Some(Ok(received_columns)) => assert!(received_columns.is_empty()),
            response => panic!("expected no peer failure, got {response:?}"),
        }
    }

    #[tokio::test]
    async fn revealed_gloas_payload_with_missing_columns_penalizes_peers() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();
        // The child at slot 2 builds on the FULL parent, which marks the slot 1 payload as
        // revealed.
        let child_root = harness
            .extend_chain(
                2,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        let block_root = harness
            .chain
            .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
            .unwrap()
            .unwrap();
        let block = harness
            .chain
            .get_blinded_block(&block_root)
            .unwrap()
            .unwrap();
        let child = harness
            .chain
            .get_blinded_block(&child_root)
            .unwrap()
            .unwrap();
        let bid_hash = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .unwrap()
            .message()
            .block_hash();
        assert!(child.is_parent_block_full(bid_hash));

        let epoch = Epoch::new(0);
        let peer = PeerId::random();
        let request_id = DataColumnsByRangeRequestId {
            id: 0,
            parent_request_id: DataColumnsByRangeRequester::CustodyBackfillSync(
                CustodyBackFillBatchRequestId {
                    id: 0,
                    batch_id: CustodyBackfillBatchId { epoch, run_id: 0 },
                },
            ),
            peer,
        };
        let mut request = RangeDataColumnBatchRequest::new(
            vec![(request_id, vec![0, 1, 2, 3])],
            harness.chain.clone(),
            epoch,
        );
        request
            .add_custody_columns(request_id, vec![])
            .expect("should complete request");

        match request.responses() {
            Some(Err(CouplingError::DataColumnPeerFailure { faulty_peers, .. })) => {
                assert!(faulty_peers.iter().any(|(_, p)| *p == peer))
            }
            response => panic!("expected peer failure, got {response:?}"),
        }
    }

    fn custody_backfill_request(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        epoch: Epoch,
        columns: Vec<ColumnIndex>,
        peer: PeerId,
    ) -> (
        DataColumnsByRangeRequestId,
        RangeDataColumnBatchRequest<EphemeralHarnessType<E>>,
    ) {
        let request_id = DataColumnsByRangeRequestId {
            id: 0,
            parent_request_id: DataColumnsByRangeRequester::CustodyBackfillSync(
                CustodyBackFillBatchRequestId {
                    id: 0,
                    batch_id: CustodyBackfillBatchId { epoch, run_id: 0 },
                },
            ),
            peer,
        };
        let request = RangeDataColumnBatchRequest::new(
            vec![(request_id, columns)],
            harness.chain.clone(),
            epoch,
        );
        (request_id, request)
    }

    // A skipped slot between a withheld block and its child.
    #[tokio::test]
    async fn withheld_gloas_payload_with_skipped_slot_does_not_penalize_peers() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();

        // Import the slot 1 block but withhold its payload envelope.
        let slot = Slot::new(1);
        let (block_contents, _, _) = harness
            .make_block_with_envelope(harness.get_current_state(), slot)
            .await;
        let block_root = block_contents.0.canonical_root();
        harness
            .process_block(slot, block_root, block_contents)
            .await
            .expect("should import block");

        // Skip slot 2. The slot 3 child builds on the EMPTY parent.
        harness.advance_slot();
        harness.advance_slot();
        let child_slot = Slot::new(3);
        let (child_contents, _, _) = harness
            .make_block_with_envelope(harness.get_current_state(), child_slot)
            .await;
        let child_root = child_contents.0.canonical_root();
        harness
            .process_block(child_slot, child_root, child_contents)
            .await
            .expect("should import child block");
        assert_eq!(
            harness
                .chain
                .block_root_at_slot(Slot::new(2), WhenSlotSkipped::Prev)
                .unwrap(),
            Some(block_root)
        );

        let peer = PeerId::random();
        let (request_id, mut request) =
            custody_backfill_request(&harness, Epoch::new(0), vec![0, 1, 2, 3], peer);
        request
            .add_custody_columns(request_id, vec![])
            .expect("should complete request");

        // The slot 3 block has no child, so it owes no columns either.
        match request.responses() {
            Some(Ok(received_columns)) => assert!(received_columns.is_empty()),
            response => panic!("expected no peer failure, got {response:?}"),
        }
    }

    // The last block of a finalized epoch has its child in the next epoch.
    #[tokio::test]
    async fn revealed_gloas_payload_with_child_in_next_epoch_penalizes_peers() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        let slots_per_epoch = E::slots_per_epoch();

        // Blocks up to the second last slot of epoch 0, then skip into epoch 1.
        harness.advance_slot();
        let last_block_root = harness
            .extend_chain(
                slots_per_epoch as usize - 2,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        for _ in 0..3 {
            harness.advance_slot();
        }
        harness
            .extend_chain(
                slots_per_epoch as usize * 5,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let epoch = Epoch::new(0);
        let epoch_end_slot = epoch.end_slot(slots_per_epoch);
        assert!(harness.chain.store.get_split_slot() > epoch_end_slot);
        let last_block = harness
            .chain
            .get_blinded_block(&last_block_root)
            .unwrap()
            .unwrap();
        assert_eq!(last_block.slot(), epoch_end_slot - 1);
        assert_eq!(
            harness
                .chain
                .block_root_at_slot(epoch_end_slot + 1, WhenSlotSkipped::Prev)
                .unwrap(),
            Some(last_block_root)
        );

        // Serve every block's columns except the last block's.
        let mut columns = vec![];
        for slot in 1..epoch_end_slot.as_u64() - 1 {
            let block_root = harness
                .chain
                .block_root_at_slot(Slot::new(slot), WhenSlotSkipped::None)
                .unwrap()
                .unwrap();
            columns.extend(
                harness
                    .chain
                    .store
                    .get_data_columns(&block_root, ForkName::Gloas)
                    .unwrap()
                    .unwrap(),
            );
        }
        let requested_columns = columns
            .iter()
            .map(|column| *column.index())
            .unique()
            .collect::<Vec<_>>();

        let peer = PeerId::random();
        let (request_id, mut request) =
            custody_backfill_request(&harness, epoch, requested_columns, peer);
        request
            .add_custody_columns(request_id, columns)
            .expect("should complete request");

        match request.responses() {
            Some(Err(CouplingError::DataColumnPeerFailure { faulty_peers, .. })) => {
                assert!(faulty_peers.iter().any(|(_, p)| *p == peer))
            }
            response => panic!("expected peer failure, got {response:?}"),
        }
    }

    // A late reveal: the envelope and columns were imported, but the child builds on the EMPTY
    // parent. Columns a peer serves for it are dropped without a penalty.
    #[tokio::test]
    async fn late_revealed_gloas_payload_columns_are_dropped() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();

        let slot = Slot::new(1);
        let (block_contents, envelope, post_state) = harness
            .make_block_with_envelope(harness.get_current_state(), slot)
            .await;
        let envelope = envelope.expect("should produce an envelope");
        let block_root = block_contents.0.canonical_root();
        let block_state_root = block_contents.0.state_root();
        harness
            .process_block(slot, block_root, block_contents)
            .await
            .expect("should import block");

        // Build the child while the payload is still missing, so it builds on the EMPTY parent.
        harness.advance_slot();
        let child_slot = Slot::new(2);
        let (child_contents, _, _) = harness
            .make_block_with_envelope(post_state.clone(), child_slot)
            .await;
        let child_root = child_contents.0.canonical_root();

        // The envelope arrives late, then the child.
        harness
            .process_envelope(block_root, envelope, &post_state, block_state_root)
            .await;
        harness
            .process_block(child_slot, child_root, child_contents)
            .await
            .expect("should import child block");

        let data_columns = harness
            .chain
            .store
            .get_data_columns(&block_root, ForkName::Gloas)
            .expect("should read data columns")
            .expect("should store data columns");
        let block = harness
            .chain
            .get_blinded_block(&block_root)
            .unwrap()
            .unwrap();
        let child = harness
            .chain
            .get_blinded_block(&child_root)
            .unwrap()
            .unwrap();
        let bid_hash = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .unwrap()
            .message()
            .block_hash();
        assert!(!child.is_parent_block_full(bid_hash));

        let requested_columns = data_columns
            .iter()
            .map(|column| *column.index())
            .unique()
            .collect::<Vec<_>>();
        let peer = PeerId::random();
        let (request_id, mut request) =
            custody_backfill_request(&harness, Epoch::new(0), requested_columns, peer);
        request
            .add_custody_columns(request_id, data_columns)
            .expect("should complete request");

        match request.responses() {
            Some(Ok(received_columns)) => assert!(received_columns.is_empty()),
            response => panic!("expected no peer failure, got {response:?}"),
        }
    }
}
