use super::chain::EPOCHS_PER_BATCH;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use fnv::FnvHashMap;
use ssz::Encode;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::ops::Sub;
use types::{EthSpec, SignedBeaconBlock, Slot};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct BatchId(pub u64);

impl std::ops::Deref for BatchId {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for BatchId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::convert::From<u64> for BatchId {
    fn from(id: u64) -> Self {
        BatchId(id)
    }
}

/// A collection of sequential blocks that are requested from peers in a single RPC request.
#[derive(PartialEq, Debug)]
pub struct Batch<T: EthSpec> {
    /// The ID of the batch, these are sequential.
    pub id: BatchId,
    /// The requested start slot of the batch, inclusive.
    pub start_slot: Slot,
    /// The requested end slot of batch, exclusive.
    pub end_slot: Slot,
    /// The peer that was originally assigned to the batch.
    pub original_peer: PeerId,
    /// The peer that is currently assigned to the batch.
    pub current_peer: PeerId,
    /// The number of retries this batch has undergone due to a failed request.
    pub retries: u8,
    /// The number of times this batch has attempted to be re-downloaded and re-processed. This
    /// occurs when a batch has been received but cannot be processed.
    pub reprocess_retries: u8,
    /// Marks the batch as undergoing a re-process, with a hash of the original blocks it received.
    pub original_hash: Option<u64>,
    /// The blocks that have been downloaded.
    pub downloaded_blocks: Vec<SignedBeaconBlock<T>>,
}

impl<T: EthSpec> Eq for Batch<T> {}

impl<T: EthSpec> Batch<T> {
    pub fn new(id: BatchId, start_slot: Slot, end_slot: Slot, peer_id: PeerId) -> Self {
        Batch {
            id,
            start_slot,
            end_slot,
            original_peer: peer_id.clone(),
            current_peer: peer_id,
            retries: 0,
            reprocess_retries: 0,
            original_hash: None,
            downloaded_blocks: Vec::new(),
        }
    }

    pub fn to_blocks_by_range_request(&self) -> BlocksByRangeRequest {
        BlocksByRangeRequest {
            start_slot: self.start_slot.into(),
            count: std::cmp::min(
                T::slots_per_epoch() * EPOCHS_PER_BATCH,
                self.end_slot.sub(self.start_slot).into(),
            ),
            step: 1,
        }
    }

    /// This gets a hash that represents the blocks currently downloaded. This allows comparing a
    /// previously downloaded batch of blocks with a new downloaded batch of blocks.
    pub fn hash(&self) -> u64 {
        // the hash used is the ssz-encoded list of blocks
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.downloaded_blocks.as_ssz_bytes().hash(&mut hasher);
        hasher.finish()
    }
}

impl<T: EthSpec> Ord for Batch<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.0.cmp(&other.id.0)
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
            .or_insert_with(HashSet::new)
            .insert(request_id);
        self.batches.insert(request_id, batch)
    }

    pub fn remove(&mut self, request_id: RequestId) -> Option<Batch<T>> {
        if let Some(batch) = self.batches.remove(&request_id) {
            if let Entry::Occupied(mut entry) = self.peer_requests.entry(batch.current_peer.clone())
            {
                entry.get_mut().remove(&request_id);

                if entry.get().is_empty() {
                    entry.remove();
                }
            }
            Some(batch)
        } else {
            None
        }
    }

    /// The number of current pending batch requests.
    pub fn len(&self) -> usize {
        self.batches.len()
    }

    /// Adds a block to the batches if the request id exists. Returns None if there is no batch
    /// matching the request id.
    pub fn add_block(&mut self, request_id: RequestId, block: SignedBeaconBlock<T>) -> Option<()> {
        let batch = self.batches.get_mut(&request_id)?;
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

        let request_id = *request_ids.iter().next()?;
        self.remove(request_id)
    }
}
