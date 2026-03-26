use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    BeaconChainTypes,
    payload_bid_verification::gossip_verified_bid::{
        GossipVerifiedPayloadBid, SignatureVerifiedPayloadBid,
    },
};
use parking_lot::RwLock;
use types::{BuilderIndex, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid, Slot};

pub struct GossipVerifiedPayloadBidCache<T: BeaconChainTypes> {
    highest_bid:
        RwLock<BTreeMap<Slot, HashMap<(ExecutionBlockHash, Hash256), GossipVerifiedPayloadBid<T>>>>,
    seen_bid: RwLock<BTreeMap<Slot, HashSet<BuilderIndex>>>,
}

impl<T: BeaconChainTypes> Default for GossipVerifiedPayloadBidCache<T> {
    fn default() -> Self {
        Self {
            highest_bid: RwLock::new(BTreeMap::new()),
            seen_bid: RwLock::new(BTreeMap::new()),
        }
    }
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

    /// Insert a bid for the tuple `(slot, parent_block_hash, parent_block_root)`
    /// Since we only accept a `GossipVerifiedPayloadBid` we can be certain that the
    /// bid has passed all verification checks before reaching this cache.
    pub fn insert_highest_bid(&self, bid: GossipVerifiedPayloadBid<T>) {
        let mut highest_bid = self.highest_bid.write();
        highest_bid
            .entry(bid.signed_bid.message.slot)
            .or_insert_with(HashMap::new)
            .insert(
                (
                    bid.signed_bid.message.parent_block_hash,
                    bid.signed_bid.message.parent_block_root,
                ),
                bid.clone(),
            );
    }

    /// A gossip verified bid for `BuilderIndex` already exists at `slot`
    pub fn seen_builder_index(&self, slot: &Slot, builder_index: BuilderIndex) -> bool {
        self.seen_bid
            .read()
            .get(slot)
            .is_some_and(|seen_bids| seen_bids.contains(&builder_index))
    }

    /// Insert a builder into the seen cache. This function assumes signature verification
    /// has already been performed.
    pub fn insert_seen_builder(&self, bid: SignatureVerifiedPayloadBid<T>) {
        let mut seen_bid = self.seen_bid.write();
        seen_bid
            .entry(bid.signed_bid.message.slot)
            .or_insert_with(HashSet::new)
            .insert(bid.signed_bid.message.builder_index);
    }

    /// Prune anything before `current_slot`
    pub fn prune(&self, current_slot: Slot) {
        self.highest_bid
            .write()
            .retain(|&slot, _| slot >= current_slot);

        self.seen_bid
            .write()
            .retain(|&slot, _| slot >= current_slot);
    }
}
