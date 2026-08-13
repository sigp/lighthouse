use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;
use educe::Educe;
use parking_lot::RwLock;
use std::{
    collections::hash_map,
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use types::{BuilderIndex, EthSpec, ExecutionBlockHash, Hash256, SignedExecutionPayloadBid, Slot};

/// The highest-value bid seen per `(slot, parent_block_hash, parent_block_root)` tuple.
///
/// Keyed first by `Slot` (in a `BTreeMap` so that stale slots can be pruned cheaply via
/// `split_off`), then by the `(parent_block_hash, parent_block_root)` of the block the bid
/// builds on.
type HighestBidMap<E> =
    BTreeMap<Slot, HashMap<(ExecutionBlockHash, Hash256), GossipVerifiedPayloadBid<E>>>;

/// The mutable state guarded by the cache's lock.
#[derive(Educe)]
#[educe(Default(bound = "E: EthSpec"))]
pub struct GossipBidCacheInner<E: EthSpec> {
    /// The current best bid for each `(slot, parent_block_hash, parent_block_root)` tuple.
    highest_bid: HighestBidMap<E>,
    /// The set of builders from which we have already accepted a gossip-verified bid, per slot.
    ///
    /// Used to enforce one bid per builder per slot.
    seen_builders: BTreeMap<Slot, HashSet<BuilderIndex>>,
}

/// A cache of gossip-verified payload bids.
///
/// Tracks, per slot, the highest-value bid observed for each parent block and the set of builders
/// that have already bid, so that duplicate and lower-value gossip bids can be rejected. Stale
/// entries are removed via [`prune`](Self::prune) as the chain advances.
#[derive(Educe)]
#[educe(Default(bound = "E: EthSpec"))]
pub struct GossipVerifiedPayloadBidCache<E: EthSpec> {
    inner: RwLock<GossipBidCacheInner<E>>,
}

impl<E: EthSpec> GossipVerifiedPayloadBidCache<E> {
    /// Create a new, empty cache.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(GossipBidCacheInner::default()),
        }
    }

    /// Get the highest-value cached bid for the tuple `(slot, parent_block_hash,
    /// parent_block_root)`, if one exists.
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<E>>> {
        self.inner.read().highest_bid.get(&slot).and_then(|map| {
            map.get(&(parent_block_hash, parent_block_root))
                .map(|b| b.signed_bid.clone())
        })
    }

    /// Record a gossip-verified `bid` in the cache.
    ///
    /// This always marks the bid's builder as seen for the bid's slot (see
    /// [`seen_builder_index`](Self::seen_builder_index)). Additionally, if the bid has a strictly
    /// higher value than the currently cached bid for its `(slot, parent_block_hash,
    /// parent_block_root)` tuple (or no bid is cached yet), it replaces the cached bid.
    ///
    /// Returns `true` if the bid became the new highest bid for its tuple, or `false` if an
    /// existing cached bid had an equal or greater value and was therefore retained.
    pub fn observe_bid(&self, bid: GossipVerifiedPayloadBid<E>) -> bool {
        let slot = bid.signed_bid.message.slot;
        let mut inner = self.inner.write();
        inner
            .seen_builders
            .entry(slot)
            .or_default()
            .insert(bid.signed_bid.message.builder_index);

        let key = (
            bid.signed_bid.message.parent_block_hash,
            bid.signed_bid.message.parent_block_root,
        );

        match inner.highest_bid.entry(slot).or_default().entry(key) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(bid);
                true
            }
            hash_map::Entry::Occupied(mut entry) => {
                if entry.get().signed_bid.message.value >= bid.signed_bid.message.value {
                    return false;
                }
                entry.insert(bid);
                true
            }
        }
    }

    /// Returns `true` if a gossip-verified bid from `builder_index` has already been seen for
    /// `slot`.
    pub fn seen_builder_index(&self, slot: &Slot, builder_index: BuilderIndex) -> bool {
        self.inner
            .read()
            .seen_builders
            .get(slot)
            .is_some_and(|seen_builders| seen_builders.contains(&builder_index))
    }

    /// Removes all cached bids and seen-builder records for slots older than `current_slot`.
    ///
    /// Entries for `current_slot` and later are retained.
    pub fn prune(&self, current_slot: Slot) {
        let mut inner = self.inner.write();
        inner.highest_bid = inner.highest_bid.split_off(&current_slot);
        inner.seen_builders = inner.seen_builders.split_off(&current_slot);
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
            cache.observe_bid(verified);
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
