use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    BeaconChainTypes, payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid,
};
use parking_lot::RwLock;
use types::{BuilderIndex, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid, Slot};

type HighestBidMap<T> =
    BTreeMap<Slot, HashMap<(ExecutionBlockHash, Hash256), GossipVerifiedPayloadBid<T>>>;

pub struct GossipVerifiedPayloadBidCache<T: BeaconChainTypes> {
    highest_bid: RwLock<HighestBidMap<T>>,
    seen_builder: RwLock<BTreeMap<Slot, HashSet<BuilderIndex>>>,
}

impl<T: BeaconChainTypes> Default for GossipVerifiedPayloadBidCache<T> {
    fn default() -> Self {
        Self {
            highest_bid: RwLock::new(BTreeMap::new()),
            seen_builder: RwLock::new(BTreeMap::new()),
        }
    }
}

impl<T: BeaconChainTypes> GossipVerifiedPayloadBidCache<T> {
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<T::EthSpec>>> {
        self.highest_bid.read().get(&slot).and_then(|map| {
            map.get(&(parent_block_hash, parent_block_root))
                .map(|b| b.signed_bid.clone())
        })
    }

    pub fn insert_highest_bid(&self, bid: GossipVerifiedPayloadBid<T>) {
        let bid_msg = bid.signed_bid.message();
        let key = (bid_msg.parent_block_hash(), bid_msg.parent_block_root());
        let slot = bid_msg.slot();
        let value = bid_msg.value();

        let mut highest_bid = self.highest_bid.write();
        let slot_map = highest_bid.entry(slot).or_default();

        if let Some(existing) = slot_map.get(&key)
            && existing.signed_bid.message().value() >= value
        {
            return;
        }
        slot_map.insert(key, bid);
    }

    pub fn seen_builder_index(&self, slot: &Slot, builder_index: BuilderIndex) -> bool {
        self.seen_builder
            .read()
            .get(slot)
            .is_some_and(|seen_builders| seen_builders.contains(&builder_index))
    }

    pub fn insert_seen_builder(&self, bid: &GossipVerifiedPayloadBid<T>) {
        let bid_msg = bid.signed_bid.message();
        let mut seen_builder = self.seen_builder.write();
        seen_builder
            .entry(bid_msg.slot())
            .or_default()
            .insert(bid_msg.builder_index());
    }

    pub fn prune(&self, current_slot: Slot) {
        self.highest_bid
            .write()
            .retain(|&slot, _| slot >= current_slot);

        self.seen_builder
            .write()
            .retain(|&slot, _| slot >= current_slot);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bls::Signature;
    use types::{
        ExecutionBlockHash, ExecutionPayloadBidGloas, Hash256, MinimalEthSpec,
        SignedExecutionPayloadBid, Slot,
    };

    use super::GossipVerifiedPayloadBidCache;
    use crate::{
        payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid,
        test_utils::EphemeralHarnessType,
    };

    type E = MinimalEthSpec;
    type T = EphemeralHarnessType<E>;

    fn make_gossip_verified(
        slot: Slot,
        builder_index: u64,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
        value: u64,
    ) -> GossipVerifiedPayloadBid<T> {
        GossipVerifiedPayloadBid {
            signed_bid: Arc::new(SignedExecutionPayloadBid::Gloas(
                types::SignedExecutionPayloadBidGloas {
                    message: ExecutionPayloadBidGloas {
                        slot,
                        builder_index,
                        parent_block_hash,
                        parent_block_root,
                        value,
                        ..ExecutionPayloadBidGloas::default()
                    },
                    signature: Signature::empty(),
                },
            )),
        }
    }

    #[test]
    fn prune_removes_old_retains_current() {
        let cache = GossipVerifiedPayloadBidCache::<T>::default();
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;

        for slot in [1, 2, 3, 7, 8, 9, 10] {
            let verified = make_gossip_verified(Slot::new(slot), slot, hash, root, slot * 100);
            cache.insert_seen_builder(&verified);
            cache.insert_highest_bid(verified);
        }

        cache.prune(Slot::new(8));

        for slot in [1, 2, 3, 7] {
            assert!(cache.get_highest_bid(Slot::new(slot), hash, root).is_none());
            assert!(!cache.seen_builder_index(&Slot::new(slot), slot));
        }
        for slot in [8, 9, 10] {
            assert!(cache.get_highest_bid(Slot::new(slot), hash, root).is_some());
            assert!(cache.seen_builder_index(&Slot::new(slot), slot));
        }
    }
}
