use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use types::{BuilderIndex, EthSpec, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid, Slot};

type HighestBidMap<E> =
    BTreeMap<Slot, HashMap<(ExecutionBlockHash, Hash256), GossipVerifiedPayloadBid<E>>>;

pub struct GossipVerifiedPayloadBidCache<E: EthSpec> {
    highest_bid: RwLock<HighestBidMap<E>>,
    seen_builder: RwLock<BTreeMap<Slot, HashSet<BuilderIndex>>>,
}

impl<E: EthSpec> Default for GossipVerifiedPayloadBidCache<E> {
    fn default() -> Self {
        Self {
            highest_bid: RwLock::new(BTreeMap::new()),
            seen_builder: RwLock::new(BTreeMap::new()),
        }
    }
}

impl<E: EthSpec> GossipVerifiedPayloadBidCache<E> {
    /// Get the cached bid for the tuple `(slot, parent_block_hash, parent_block_root)`.
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<E>>> {
        self.highest_bid.read().get(&slot).and_then(|map| {
            map.get(&(parent_block_hash, parent_block_root))
                .map(|b| b.signed_bid.clone())
        })
    }

    /// Insert a bid for the tuple `(slot, parent_block_hash, parent_block_root)` only if
    /// its value is higher than the currently cached bid for that tuple.
    pub fn insert_highest_bid(&self, bid: GossipVerifiedPayloadBid<E>) {
        let key = (
            bid.signed_bid.message.parent_block_hash,
            bid.signed_bid.message.parent_block_root,
        );
        let mut highest_bid = self.highest_bid.write();
        let slot_map = highest_bid.entry(bid.signed_bid.message.slot).or_default();

        if let Some(existing) = slot_map.get(&key)
            && existing.signed_bid.message.value >= bid.signed_bid.message.value
        {
            return;
        }
        slot_map.insert(key, bid);
    }

    /// A gossip verified bid for `BuilderIndex` already exists at `slot`
    pub fn seen_builder_index(&self, slot: &Slot, builder_index: BuilderIndex) -> bool {
        self.seen_builder
            .read()
            .get(slot)
            .is_some_and(|seen_builders| seen_builders.contains(&builder_index))
    }

    /// Insert a builder into the seen cache.
    pub fn insert_seen_builder(&self, bid: &GossipVerifiedPayloadBid<E>) {
        let mut seen_builder = self.seen_builder.write();
        seen_builder
            .entry(bid.signed_bid.message.slot)
            .or_default()
            .insert(bid.signed_bid.message.builder_index);
    }

    /// Prune anything before `current_slot`
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
        ExecutionBlockHash, ExecutionPayloadBid, Hash256, MinimalEthSpec,
        SignedExecutionPayloadBid, Slot,
    };

    use super::GossipVerifiedPayloadBidCache;
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
    fn prune_removes_old_retains_current() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;

        for slot in [1, 2, 3, 7, 8, 9, 10] {
            let verified = make_gossip_verified(Slot::new(slot), slot, hash, root, slot * 100);
            cache.insert_seen_builder(&verified);
            cache.insert_highest_bid(verified);
        }

        cache.prune(Slot::new(8));

        // Slots 1-7 pruned from both maps.
        for slot in [1, 2, 3, 7] {
            assert!(cache.get_highest_bid(Slot::new(slot), hash, root).is_none());
            assert!(!cache.seen_builder_index(&Slot::new(slot), slot));
        }
        // Slots 8-10 retained in both maps.
        for slot in [8, 9, 10] {
            assert!(cache.get_highest_bid(Slot::new(slot), hash, root).is_some());
            assert!(cache.seen_builder_index(&Slot::new(slot), slot));
        }
    }
}
