use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    BeaconChainTypes, payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid,
};
use parking_lot::RwLock;
use types::{BuilderIndex, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid, Slot};

pub struct GossipVerifiedPayloadBidCache<T: BeaconChainTypes> {
    highest_bid:
        RwLock<BTreeMap<Slot, HashMap<(ExecutionBlockHash, Hash256), GossipVerifiedPayloadBid<T>>>>,
    seen_bid: RwLock<BTreeMap<Slot, HashSet<BuilderIndex>>>,
}

impl<T: BeaconChainTypes> GossipVerifiedPayloadBidCache<T> {
    /// Get the cached bid for the tuple `(slot, parent_block_hash, parent_block_root)`.
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<T::EthSpec>>> {
        self.highest_bid.read().get(&slot).and_then(|map| {
            map.get(&(parent_block_hash, parent_block_root))
                .and_then(|b| Some(b.signed_bid.clone()))
        })
    }

    /// A gossip verified bid for `BuilderIndex` already exists at `slot`
    pub fn seen_builder_index(&self, slot: &Slot, builder_index: BuilderIndex) -> bool {
        self.seen_bid
            .read()
            .get(slot)
            .is_some_and(|seen_bids| seen_bids.contains(&builder_index))
    }
}
