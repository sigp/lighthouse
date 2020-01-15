use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use fnv::FnvHashMap;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use types::{BeaconBlock, EthSpec, Hash256, Slot};

/// A collection of sequential blocks that are requested from peers in a single RPC request.
#[derive(PartialEq)]
pub struct Batch<T: EthSpec> {
    /// The ID of the batch, these are sequential.
    pub id: u64,
    /// The requested start slot of the batch, inclusive.
    pub start_slot: Slot,
    /// The requested end slot of batch, exclusive.
    pub end_slot: Slot,
    /// The hash of the chain root to requested from the peer.
    pub head_root: Hash256,
    /// The peer that was originally assigned to the batch.
    pub _original_peer: PeerId,
    /// The peer that is currently assigned to the batch.
    pub current_peer: PeerId,
    /// The number of retries this batch has undergone.
    pub retries: u8,
    /// The blocks that have been downloaded.
    pub downloaded_blocks: Vec<BeaconBlock<T>>,
}

impl<T: EthSpec> Ord for Batch<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T: EthSpec> PartialOrd for Batch<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A structure that contains a mapping of pending batch requests, that also keeps track of which
/// peers are currently making batch requests.
///
/// This is used to optimise searches for idle peers (peers that have no outbound batch requests).
pub struct PendingBatches<T: EthSpec> {
    /// The current pending batches.
    batches: FnvHashMap<RequestId, Batch<T>>,
    /// A mapping of peers to the number of pending requests.
    peer_requests: HashMap<PeerId, HashSet<RequestId>>,
}

impl<T: EthSpec> PendingBatches<T> {
    pub fn new() -> Self {
        PendingBatches {
            batches: FnvHashMap::default(),
            peer_requests: HashMap::new(),
        }
    }

    pub fn insert(&mut self, request_id: RequestId, batch: Batch<T>) -> Option<Batch<T>> {
        let peer_request = batch.current_peer.clone();
        self.peer_requests
            .entry(peer_request)
            .or_insert_with(|| HashSet::new())
            .insert(request_id);
        self.batches.insert(request_id, batch)
    }

    pub fn remove(&mut self, request_id: &RequestId) -> Option<Batch<T>> {
        if let Some(batch) = self.batches.remove(request_id) {
            if let Entry::Occupied(mut entry) = self.peer_requests.entry(batch.current_peer.clone())
            {
                entry.get_mut().remove(request_id);

                if entry.get().is_empty() {
                    entry.remove();
                }
            }
            Some(batch)
        } else {
            None
        }
    }

    /// Adds a block to the batches if the request id exists. Returns None if there is no batch
    /// matching the request id.
    pub fn add_block(&mut self, request_id: &RequestId, block: BeaconBlock<T>) -> Option<()> {
        let batch = self.batches.get_mut(request_id)?;
        batch.downloaded_blocks.push(block);
        Some(())
    }

    /// Returns true if there the peer does not exist in the peer_requests mapping. Indicating it
    /// has no pending outgoing requests.
    pub fn peer_is_idle(&self, peer_id: &PeerId) -> bool {
        self.peer_requests.get(peer_id).is_none()
    }

    /// Removes a batch for a given peer.
    pub fn remove_batch_by_peer(&mut self, peer_id: &PeerId) -> Option<Batch<T>> {
        let request_ids = self.peer_requests.get(peer_id)?;

        let request_id = request_ids.iter().next()?.clone();
        self.remove(&request_id)
    }
}
