use std::collections::{HashMap, HashSet};

use crate::sync::block_sidecar_coupling::{ByRangeRequest, CouplingError};
use crate::sync::network_context::MAX_COLUMN_RETRIES;
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
            self.attempt,
        );

        if let Err(CouplingError::DataColumnPeerFailure {
            error: _,
            faulty_peers,
            exceeded_retries: _,
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
        attempt: usize,
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
                if !columns.is_empty() {
                    for column in expected_custody_columns {
                        if let Some(naughty_peer) = column_to_peer.get(column) {
                            naughty_peers.push((*column, *naughty_peer));
                        }
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
                .map(|column| column.signed_block_header.signature.clone())
                .unique()
                .collect::<Vec<_>>();

            let column_block_root = match column_block_roots.as_slice() {
                // We expect a single unique block root
                [column_block_root] => *column_block_root,
                // If there are no block roots, penalize all peers
                [] => {
                    for column in &columns {
                        if let Some(naughty_peer) = column_to_peer.get(&column.index) {
                            naughty_peers.push((column.index, *naughty_peer));
                        }
                    }
                    continue;
                }
                // If theres more than one unique block root penalize the peers serving the bad block roots.
                column_block_roots => {
                    for column in columns {
                        if column_block_roots.contains(&column.block_root())
                            && block_root != column.block_root()
                            && let Some(naughty_peer) = column_to_peer.get(&column.index)
                        {
                            naughty_peers.push((column.index, *naughty_peer));
                        }
                    }
                    continue;
                }
            };

            let column_block_signature = match column_block_signatures.as_slice() {
                // We expect a single unique block signature
                [block_signature] => block_signature,
                // If there are no block signatures, penalize all peers
                [] => {
                    for column in &columns {
                        if let Some(naughty_peer) = column_to_peer.get(&column.index) {
                            naughty_peers.push((column.index, *naughty_peer));
                        }
                    }
                    continue;
                }
                // If theres more than one unique block signature, penalize the peers serving the
                // invalid block signatures.
                column_block_signatures => {
                    for column in columns {
                        if column_block_signatures.contains(&column.signed_block_header.signature)
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
                    if let Some(naughty_peer) = column_to_peer.get(&column.index) {
                        naughty_peers.push((column.index, *naughty_peer));
                    }
                }
            }

            // If the block signature doesn't match the columns block signature, penalize the peers
            if block.signature() != column_block_signature {
                for column in &columns {
                    if let Some(naughty_peer) = column_to_peer.get(&column.index) {
                        naughty_peers.push((column.index, *naughty_peer));
                    }
                }
            }

            let received_columns = columns.iter().map(|c| c.index).collect::<HashSet<_>>();

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
                exceeded_retries: attempt >= MAX_COLUMN_RETRIES,
            });
        }

        Ok(result)
    }
}
