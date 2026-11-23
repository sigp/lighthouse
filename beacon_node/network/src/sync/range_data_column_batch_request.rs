use std::collections::{HashMap, HashSet};

use crate::sync::block_sidecar_coupling::{ByRangeRequest, CouplingError};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::DataColumnsByRangeRequestId;
use std::sync::Arc;
use types::{ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Slot};

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

        let forward_blocks_iter = self
            .beacon_chain
            .forwards_iter_block_roots_until(
                self.epoch.start_slot(T::EthSpec::slots_per_epoch()),
                self.epoch.end_slot(T::EthSpec::slots_per_epoch()),
            )
            .map_err(|_| {
                CouplingError::InternalError("Failed to fetch block root iterator".to_string())
            })?;

        for block_iter_result in forward_blocks_iter {
            let (block_root, slot) = block_iter_result.map_err(|_| {
                CouplingError::InternalError("Failed to iterate block roots".to_string())
            })?;

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

            let Some(columns) = received_columns_for_slot.remove(&slot) else {
                // If at least one blob is expected for this slot but none have been served, penalize all peers
                // The slot check ensures we arent checking a skipped slot.
                if block.num_expected_blobs() != 0 && block.slot() == slot {
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
                for column in &columns {
                    if let Some(naughty_peer) = column_to_peer.get(column.index()) {
                        naughty_peers.push((*column.index(), *naughty_peer));
                    }
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
            if block.num_expected_blobs() != 0 && !missing_columns.is_empty() {
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
    use beacon_chain::custody_context::NodeCustodyType;
    use beacon_chain::test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    };
    use lighthouse_network::service::api_types::{
        CustodyBackFillBatchRequestId, CustodyBackfillBatchId, DataColumnsByRangeRequester,
    };
    use types::{ForkName, Spec};

    type E = Spec;

    fn gloas_supernode_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        harness.execution_block_generator().set_min_blob_count(1);
        harness
    }

    /// Adds a block at the next slot and returns the columns stored for it.
    async fn extend_with_columns(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) -> DataColumnSidecarList<E> {
        harness.advance_slot();
        let block_root = harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        harness
            .chain
            .store
            .get_data_columns(&block_root, ForkName::Gloas)
            .expect("should read data columns")
            .expect("should store data columns")
    }

    fn backfill_request_id(peer: PeerId, epoch: Epoch) -> DataColumnsByRangeRequestId {
        DataColumnsByRangeRequestId {
            id: 0,
            parent_request_id: DataColumnsByRangeRequester::CustodyBackfillSync(
                CustodyBackFillBatchRequestId {
                    id: 0,
                    batch_id: CustodyBackfillBatchId { epoch, run_id: 0 },
                },
            ),
            peer,
        }
    }

    #[tokio::test]
    async fn valid_gloas_batch_completes_without_peer_failure() {
        let harness = gloas_supernode_harness();
        let data_columns = extend_with_columns(&harness).await;
        let epoch = Epoch::new(0);

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
        let request_id = backfill_request_id(PeerId::random(), epoch);
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
    async fn skipped_slot_column_blames_only_the_serving_peer() {
        let harness = gloas_supernode_harness();
        let first_columns = extend_with_columns(&harness).await;
        // Skip a slot before the next block.
        harness.advance_slot();
        let second_columns = extend_with_columns(&harness).await;

        let skipped_slot = first_columns[0].slot() + 1;
        assert_eq!(second_columns[0].slot(), skipped_slot + 1);

        let honest_column = *first_columns[0].index();
        let faulty_column = *first_columns[1].index();
        let served = |index: ColumnIndex| {
            first_columns
                .iter()
                .chain(second_columns.iter())
                .filter(|column| *column.index() == index)
                .cloned()
                .collect::<Vec<_>>()
        };

        let epoch = Epoch::new(0);
        let honest_request_id = backfill_request_id(PeerId::random(), epoch);
        let faulty_request_id = backfill_request_id(PeerId::random(), epoch);

        let mut request = RangeDataColumnBatchRequest::new(
            vec![
                (honest_request_id, vec![honest_column]),
                (faulty_request_id, vec![faulty_column]),
            ],
            harness.chain.clone(),
            epoch,
        );

        // The honest peer serves only the column it was assigned.
        request
            .add_custody_columns(honest_request_id, served(honest_column))
            .expect("should complete honest request");

        // The faulty peer serves its own column plus one at the skipped slot. The wire validator
        // accepts that column: its slot is in range and its index was requested.
        let mut faulty_response = served(faulty_column);
        let skipped_slot_column = match faulty_response[0].as_ref() {
            DataColumnSidecar::Gloas(column) => {
                let mut column = column.clone();
                column.slot = skipped_slot;
                Arc::new(DataColumnSidecar::Gloas(column))
            }
            DataColumnSidecar::Fulu(_) => panic!("expected Gloas columns"),
        };
        faulty_response.push(skipped_slot_column);
        request
            .add_custody_columns(faulty_request_id, faulty_response)
            .expect("should complete faulty request");

        let faulty_peers = match request.responses() {
            Some(Err(CouplingError::DataColumnPeerFailure { faulty_peers, .. })) => faulty_peers,
            response => panic!("expected a peer failure, got {response:?}"),
        };

        assert_eq!(faulty_peers, vec![(faulty_column, faulty_request_id.peer)]);
    }
}
