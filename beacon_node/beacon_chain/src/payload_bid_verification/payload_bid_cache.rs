use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use types::{
    BuilderIndex, EthSpec, ExecutionBlockHash, ExecutionPayloadBid, Hash256,
    SignedExecutionPayloadBid, Slot,
};

/// The parent a bid builds on: which beacon block, and which payload state of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BidParent {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Hash256,
}

impl BidParent {
    pub fn from_bid<E: EthSpec>(bid: &ExecutionPayloadBid<E>) -> Self {
        Self {
            parent_block_hash: bid.parent_block_hash,
            parent_block_root: bid.parent_block_root,
        }
    }
}

type HighestBidMap<E> = BTreeMap<Slot, HashMap<BidParent, GossipVerifiedPayloadBid<E>>>;

pub struct GossipVerifiedPayloadBidCache<E: EthSpec> {
    highest_bid: RwLock<HighestBidMap<E>>,
    seen_builder_bids: RwLock<BTreeMap<Slot, HashSet<(BidParent, BuilderIndex)>>>,
}

impl<E: EthSpec> Default for GossipVerifiedPayloadBidCache<E> {
    fn default() -> Self {
        Self {
            highest_bid: RwLock::new(BTreeMap::new()),
            seen_builder_bids: RwLock::new(BTreeMap::new()),
        }
    }
}

impl<E: EthSpec> GossipVerifiedPayloadBidCache<E> {
    /// Get the cached bid for `(slot, bid_parent)`.
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        bid_parent: BidParent,
    ) -> Option<Arc<SignedExecutionPayloadBid<E>>> {
        self.highest_bid
            .read()
            .get(&slot)
            .and_then(|map| map.get(&bid_parent).map(|b| b.signed_bid.clone()))
    }

    /// Insert a bid for `(slot, bid_parent)` only if its value is higher than the
    /// currently cached bid for that key.
    pub fn insert_highest_bid(&self, bid: GossipVerifiedPayloadBid<E>) {
        let key = BidParent::from_bid(&bid.signed_bid.message);
        let mut highest_bid = self.highest_bid.write();
        let slot_map = highest_bid.entry(bid.signed_bid.message.slot).or_default();

        if let Some(existing) = slot_map.get(&key)
            && existing.signed_bid.message.value >= bid.signed_bid.message.value
        {
            return;
        }
        slot_map.insert(key, bid);
    }

    /// A gossip verified bid for `BuilderIndex` already exists for `(slot, bid_parent)`.
    pub fn seen_builder_bid_for_parent(
        &self,
        slot: &Slot,
        bid_parent: BidParent,
        builder_index: BuilderIndex,
    ) -> bool {
        self.seen_builder_bids
            .read()
            .get(slot)
            .is_some_and(|seen_builders| seen_builders.contains(&(bid_parent, builder_index)))
    }

    /// Insert a builder into the seen cache.
    pub fn insert_seen_builder_bid(&self, bid: &GossipVerifiedPayloadBid<E>) {
        let mut seen_builder_bids = self.seen_builder_bids.write();
        seen_builder_bids
            .entry(bid.signed_bid.message.slot)
            .or_default()
            .insert((
                BidParent::from_bid(&bid.signed_bid.message),
                bid.signed_bid.message.builder_index,
            ));
    }

    /// Prune anything before `current_slot`
    pub fn prune(&self, current_slot: Slot) {
        self.highest_bid
            .write()
            .retain(|&slot, _| slot >= current_slot);

        self.seen_builder_bids
            .write()
            .retain(|&slot, _| slot >= current_slot);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bls::Signature;
    use types::{
        ExecutionBlockHash, ExecutionPayloadBid, Hash256, MinimalEthSpec,
        SignedExecutionPayloadBid, Slot,
    };

    use super::{BidParent, GossipVerifiedPayloadBidCache};
    use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;

    type E = MinimalEthSpec;

    fn make_gossip_verified(
        slot: Slot,
        builder_index: u64,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
        value: u64,
    ) -> GossipVerifiedPayloadBid<E> {
        GossipVerifiedPayloadBid {
            signed_bid: Arc::new(SignedExecutionPayloadBid {
                message: ExecutionPayloadBid {
                    slot,
                    builder_index,
                    parent_block_hash,
                    parent_block_root,
                    value,
                    ..ExecutionPayloadBid::default()
                },
                signature: Signature::empty(),
            }),
        }
    }

    #[test]
    fn seen_builder_for_parent() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let slot = Slot::new(1);
        let parent_a = BidParent {
            parent_block_hash: ExecutionBlockHash::zero(),
            parent_block_root: Hash256::ZERO,
        };
        let parent_b = BidParent {
            parent_block_hash: ExecutionBlockHash::from_root(Hash256::repeat_byte(0x01)),
            parent_block_root: Hash256::repeat_byte(0x02),
        };

        let verified = make_gossip_verified(
            slot,
            0,
            parent_a.parent_block_hash,
            parent_a.parent_block_root,
            100,
        );
        cache.insert_seen_builder_bid(&verified);

        // Seen only for the exact (slot, parent tuple, builder) combination.
        assert!(cache.seen_builder_bid_for_parent(&slot, parent_a, 0));
        assert!(!cache.seen_builder_bid_for_parent(&slot, parent_b, 0));
        assert!(!cache.seen_builder_bid_for_parent(&slot, parent_a, 1));
        assert!(!cache.seen_builder_bid_for_parent(&Slot::new(2), parent_a, 0));
    }

    #[test]
    fn highest_bid_for_parent() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let slot = Slot::new(1);
        let hash_a = ExecutionBlockHash::zero();
        let root_a = Hash256::ZERO;
        let hash_b = ExecutionBlockHash::from_root(Hash256::repeat_byte(0x01));
        let root_b = Hash256::repeat_byte(0x02);
        let parent_a = BidParent {
            parent_block_hash: hash_a,
            parent_block_root: root_a,
        };
        let parent_b = BidParent {
            parent_block_hash: hash_b,
            parent_block_root: root_b,
        };

        cache.insert_highest_bid(make_gossip_verified(slot, 0, hash_a, root_a, 100));
        cache.insert_highest_bid(make_gossip_verified(slot, 1, hash_b, root_b, 50));

        // Each parent tuple keeps its own highest bid.
        assert_eq!(
            cache.get_highest_bid(slot, parent_a).unwrap().message.value,
            100
        );
        assert_eq!(
            cache.get_highest_bid(slot, parent_b).unwrap().message.value,
            50
        );

        // A lower bid does not replace the cached bid for its tuple, and does
        // not touch the other tuple.
        cache.insert_highest_bid(make_gossip_verified(slot, 2, hash_a, root_a, 60));
        assert_eq!(
            cache.get_highest_bid(slot, parent_a).unwrap().message.value,
            100
        );
        assert_eq!(
            cache.get_highest_bid(slot, parent_b).unwrap().message.value,
            50
        );

        // A higher bid replaces the cached bid for its tuple.
        cache.insert_highest_bid(make_gossip_verified(slot, 3, hash_b, root_b, 70));
        let highest_b = cache.get_highest_bid(slot, parent_b).unwrap();
        assert_eq!(highest_b.message.value, 70);
        assert_eq!(highest_b.message.builder_index, 3);
    }

    #[test]
    fn prune_removes_old_retains_current() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;
        let bid_parent = BidParent {
            parent_block_hash: hash,
            parent_block_root: root,
        };

        for slot in [1, 2, 3, 7, 8, 9, 10] {
            let verified = make_gossip_verified(Slot::new(slot), slot, hash, root, slot * 100);
            cache.insert_seen_builder_bid(&verified);
            cache.insert_highest_bid(verified);
        }

        cache.prune(Slot::new(8));

        // Slots 1-7 pruned from both maps.
        for slot in [1, 2, 3, 7] {
            assert!(cache.get_highest_bid(Slot::new(slot), bid_parent).is_none());
            assert!(!cache.seen_builder_bid_for_parent(&Slot::new(slot), bid_parent, slot));
        }
        // Slots 8-10 retained in both maps.
        for slot in [8, 9, 10] {
            assert!(cache.get_highest_bid(Slot::new(slot), bid_parent).is_some());
            assert!(cache.seen_builder_bid_for_parent(&Slot::new(slot), bid_parent, slot));
        }
    }
}
