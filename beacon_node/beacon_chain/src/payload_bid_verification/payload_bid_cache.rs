use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;
use educe::Educe;
use parking_lot::RwLock;
use std::{
    collections::hash_map,
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use types::{
    BuilderIndex, EthSpec, ExecutionBlockHash, ExecutionPayloadBidRef, Hash256,
    SignedExecutionPayloadBid, Slot,
};

/// The parent a bid builds on: which beacon block, and which payload state of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BidParent {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Hash256,
}

impl BidParent {
    pub fn from_bid<E: EthSpec>(bid: ExecutionPayloadBidRef<'_, E>) -> Self {
        Self {
            parent_block_hash: bid.parent_block_hash(),
            parent_block_root: bid.parent_block_root(),
        }
    }
}

/// The highest-value bid seen per `(slot, BidParent)`.
///
/// Keyed first by `Slot` (in a `BTreeMap` so that stale slots can be pruned cheaply via
/// `split_off`), then by the [`BidParent`] the bid builds on.
type HighestBidMap<E> = BTreeMap<Slot, HashMap<BidParent, GossipVerifiedPayloadBid<E>>>;

/// The mutable state guarded by the cache's lock.
#[derive(Educe)]
#[educe(Default(bound = "E: EthSpec"))]
pub struct GossipBidCacheInner<E: EthSpec> {
    /// The current best bid for each `(slot, BidParent)`.
    highest_bid: HighestBidMap<E>,
    /// The `(BidParent, BuilderIndex)` pairs for which we have already accepted a gossip-verified
    /// bid, per slot.
    ///
    /// Used to enforce one bid per builder per parent per slot: a builder may bid once for each
    /// parent view compatible with the head.
    seen_builder_bids: BTreeMap<Slot, HashSet<(BidParent, BuilderIndex)>>,
    /// The current best validator-fed bid (`POST validator/execution_payload_bids`) for each
    /// `(slot, BidParent)`.
    ///
    /// Kept apart from `highest_bid` and `seen_builder_bids`, which gossip validation reads: a fed
    /// bid is never broadcast, so it must not make this node ignore valid gossip bids. Only block
    /// production reads this map.
    validator_fed_highest_bid:
        BTreeMap<Slot, HashMap<BidParent, Arc<SignedExecutionPayloadBid<E>>>>,
}

/// A cache of gossip-verified payload bids.
///
/// Tracks, per slot, the highest-value bid observed for each parent a bid may build on and the
/// set of `(parent, builder)` pairs that have already bid, so that duplicate and lower-value
/// gossip bids can be rejected. Stale entries are removed via [`prune`](Self::prune) as the chain
/// advances.
///
/// It also holds validator-fed bids (`POST validator/execution_payload_bids`), kept apart from the
/// gossip state and read only by block production via
/// [`get_highest_gossip_or_fed_bid`](Self::get_highest_gossip_or_fed_bid).
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

    /// Get the highest-value cached bid for `(slot, bid_parent)`, if one exists.
    pub fn get_highest_bid(
        &self,
        slot: Slot,
        bid_parent: BidParent,
    ) -> Option<Arc<SignedExecutionPayloadBid<E>>> {
        self.inner
            .read()
            .highest_bid
            .get(&slot)
            .and_then(|map| map.get(&bid_parent).map(|b| b.signed_bid.clone()))
    }

    /// Get the best bid for block production at `(slot, bid_parent)`: the higher-value of the
    /// highest gossip bid and the highest validator-fed bid, if either exists. The gossip bid wins
    /// a tie.
    ///
    /// Block production and the `best_execution_payload_bid` event read this. Gossip validation must
    /// use [`get_highest_bid`](Self::get_highest_bid), which never sees validator-fed bids.
    pub fn get_highest_gossip_or_fed_bid(
        &self,
        slot: Slot,
        bid_parent: BidParent,
    ) -> Option<Arc<SignedExecutionPayloadBid<E>>> {
        let inner = self.inner.read();
        let gossip_bid = inner
            .highest_bid
            .get(&slot)
            .and_then(|map| map.get(&bid_parent))
            .map(|b| &b.signed_bid);
        let fed_bid = inner
            .validator_fed_highest_bid
            .get(&slot)
            .and_then(|map| map.get(&bid_parent));

        match (gossip_bid, fed_bid) {
            (Some(gossip_bid), Some(fed_bid))
                if fed_bid.message().value() > gossip_bid.message().value() =>
            {
                Some(fed_bid.clone())
            }
            (Some(gossip_bid), _) => Some(gossip_bid.clone()),
            (None, fed_bid) => fed_bid.cloned(),
        }
    }

    /// Whether `signed_bid` has a strictly higher value than the bid
    /// [`get_highest_gossip_or_fed_bid`](Self::get_highest_gossip_or_fed_bid) returns for its
    /// `(slot, BidParent)`, or no bid exists yet. Called before the bid is inserted: if it is then
    /// inserted, it is the new best bid for the `best_execution_payload_bid` event.
    pub fn beats_highest_gossip_or_fed_bid(
        &self,
        signed_bid: &SignedExecutionPayloadBid<E>,
    ) -> bool {
        self.get_highest_gossip_or_fed_bid(
            signed_bid.message().slot(),
            BidParent::from_bid(signed_bid.message()),
        )
        .is_none_or(|highest| signed_bid.message().value() > highest.message().value())
    }

    /// Record a gossip-verified `bid` in the cache.
    ///
    /// This always marks the bid's `(parent, builder)` pair as seen for the bid's slot (see
    /// [`seen_builder_bid_for_parent`](Self::seen_builder_bid_for_parent)). Additionally, if the
    /// bid has a strictly higher value than the currently cached bid for its `(slot, BidParent)`
    /// (or no bid is cached yet), it replaces the cached bid.
    ///
    /// Returns `true` if the bid became the new highest bid for its parent, or `false` if an
    /// existing cached bid had an equal or greater value and was therefore retained.
    pub fn observe_bid(&self, bid: GossipVerifiedPayloadBid<E>) -> bool {
        let slot = bid.signed_bid.message().slot();
        let key = BidParent::from_bid(bid.signed_bid.message());
        let mut inner = self.inner.write();
        inner
            .seen_builder_bids
            .entry(slot)
            .or_default()
            .insert((key, bid.signed_bid.message().builder_index()));

        match inner.highest_bid.entry(slot).or_default().entry(key) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(bid);
                true
            }
            hash_map::Entry::Occupied(mut entry) => {
                if entry.get().signed_bid.message().value() >= bid.signed_bid.message().value() {
                    return false;
                }
                entry.insert(bid);
                true
            }
        }
    }

    /// Record a verified validator-fed `signed_bid` (`POST validator/execution_payload_bids`) for
    /// block production. Only
    /// [`verify_validator_fed_bid`](crate::payload_bid_verification::validator_fed_bid::verify_validator_fed_bid)
    /// calls this, after the bid passes verification; it is `pub(crate)` so callers outside this
    /// crate can't skip that.
    ///
    /// Unlike [`observe_bid`](Self::observe_bid), this never touches the gossip state
    /// (`highest_bid`, `seen_builder_bids`), so a fed bid can't make gossip validation ignore a valid
    /// gossip bid. The bid replaces the stored fed bid for its `(slot, BidParent)` only if its value
    /// is strictly higher.
    ///
    /// Returns `true` if the bid became the new highest fed bid for its parent, or `false` if an
    /// existing fed bid had an equal or greater value and was therefore retained.
    pub(crate) fn insert_validator_fed_bid(
        &self,
        signed_bid: Arc<SignedExecutionPayloadBid<E>>,
    ) -> bool {
        let slot = signed_bid.message().slot();
        let key = BidParent::from_bid(signed_bid.message());
        let mut inner = self.inner.write();

        // Same replace-if-strictly-higher rule as `observe_bid`; keep the two in step.
        match inner
            .validator_fed_highest_bid
            .entry(slot)
            .or_default()
            .entry(key)
        {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(signed_bid);
                true
            }
            hash_map::Entry::Occupied(mut entry) => {
                if entry.get().message().value() >= signed_bid.message().value() {
                    return false;
                }
                entry.insert(signed_bid);
                true
            }
        }
    }

    /// Returns `true` if a gossip-verified bid from `builder_index` has already been seen for
    /// `(slot, bid_parent)`.
    pub fn seen_builder_bid_for_parent(
        &self,
        slot: &Slot,
        bid_parent: BidParent,
        builder_index: BuilderIndex,
    ) -> bool {
        self.inner
            .read()
            .seen_builder_bids
            .get(slot)
            .is_some_and(|seen_builders| seen_builders.contains(&(bid_parent, builder_index)))
    }

    /// Removes all cached bids and seen-builder records for slots older than `current_slot`.
    ///
    /// Entries for `current_slot` and later are retained.
    pub fn prune(&self, current_slot: Slot) {
        let mut inner = self.inner.write();
        inner.highest_bid = inner.highest_bid.split_off(&current_slot);
        inner.seen_builder_bids = inner.seen_builder_bids.split_off(&current_slot);
        inner.validator_fed_highest_bid = inner.validator_fed_highest_bid.split_off(&current_slot);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bls::Signature;
    use types::{
        ExecutionBlockHash, ExecutionPayloadBidGloas, Hash256, SignedExecutionPayloadBid,
        SignedExecutionPayloadBidGloas, Slot, Spec,
    };

    use super::{BidParent, GossipVerifiedPayloadBidCache};
    use crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid;

    type E = Spec;

    fn make_gossip_verified(
        slot: Slot,
        builder_index: u64,
        parent_block_hash: ExecutionBlockHash,
        parent_block_root: Hash256,
        value: u64,
    ) -> GossipVerifiedPayloadBid<E> {
        GossipVerifiedPayloadBid {
            signed_bid: Arc::new(SignedExecutionPayloadBid::Gloas(
                SignedExecutionPayloadBidGloas {
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
        cache.observe_bid(verified);

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

        assert!(cache.observe_bid(make_gossip_verified(slot, 0, hash_a, root_a, 100)));
        assert!(cache.observe_bid(make_gossip_verified(slot, 1, hash_b, root_b, 50)));

        // Each parent tuple keeps its own highest bid.
        assert_eq!(
            cache
                .get_highest_bid(slot, parent_a)
                .unwrap()
                .message()
                .value(),
            100
        );
        assert_eq!(
            cache
                .get_highest_bid(slot, parent_b)
                .unwrap()
                .message()
                .value(),
            50
        );

        // A lower bid does not replace the cached bid for its tuple, and does
        // not touch the other tuple.
        assert!(!cache.observe_bid(make_gossip_verified(slot, 2, hash_a, root_a, 60)));
        assert_eq!(
            cache
                .get_highest_bid(slot, parent_a)
                .unwrap()
                .message()
                .value(),
            100
        );
        assert_eq!(
            cache
                .get_highest_bid(slot, parent_b)
                .unwrap()
                .message()
                .value(),
            50
        );

        // A higher bid replaces the cached bid for its tuple.
        assert!(cache.observe_bid(make_gossip_verified(slot, 3, hash_b, root_b, 70)));
        let highest_b = cache.get_highest_bid(slot, parent_b).unwrap();
        assert_eq!(highest_b.message().value(), 70);
        assert_eq!(highest_b.message().builder_index(), 3);
    }

    #[test]
    fn validator_fed_bid_leaves_gossip_state_unchanged() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let slot = Slot::new(1);
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;
        let bid_parent = BidParent {
            parent_block_hash: hash,
            parent_block_root: root,
        };

        assert!(cache.observe_bid(make_gossip_verified(slot, 0, hash, root, 100)));
        let fed_bid = make_gossip_verified(slot, 1, hash, root, 500).signed_bid;
        assert!(cache.insert_validator_fed_bid(fed_bid));

        let highest = cache.get_highest_bid(slot, bid_parent).unwrap();
        assert_eq!(highest.message().value(), 100);
        assert_eq!(highest.message().builder_index(), 0);
        assert!(cache.seen_builder_bid_for_parent(&slot, bid_parent, 0));
        assert!(!cache.seen_builder_bid_for_parent(&slot, bid_parent, 1));
    }

    #[test]
    fn validator_fed_bid_replaced_only_by_higher_value() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let slot = Slot::new(1);
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;
        let bid_parent = BidParent {
            parent_block_hash: hash,
            parent_block_root: root,
        };
        let best_fed_builder = || {
            cache
                .get_highest_gossip_or_fed_bid(slot, bid_parent)
                .unwrap()
                .message()
                .builder_index()
        };

        assert!(
            cache.insert_validator_fed_bid(
                make_gossip_verified(slot, 0, hash, root, 100).signed_bid
            )
        );
        assert!(
            !cache
                .insert_validator_fed_bid(make_gossip_verified(slot, 1, hash, root, 50).signed_bid)
        );
        assert_eq!(best_fed_builder(), 0);
        assert!(
            !cache.insert_validator_fed_bid(
                make_gossip_verified(slot, 2, hash, root, 100).signed_bid
            )
        );
        assert_eq!(best_fed_builder(), 0);
        assert!(
            cache.insert_validator_fed_bid(
                make_gossip_verified(slot, 3, hash, root, 150).signed_bid
            )
        );
        assert_eq!(best_fed_builder(), 3);
    }

    #[test]
    fn highest_gossip_or_fed_bid_prefers_gossip_on_tie() {
        let cache = GossipVerifiedPayloadBidCache::<E>::default();
        let slot = Slot::new(1);
        let hash = ExecutionBlockHash::zero();
        let root = Hash256::ZERO;
        let bid_parent = BidParent {
            parent_block_hash: hash,
            parent_block_root: root,
        };

        assert!(cache.observe_bid(make_gossip_verified(slot, 0, hash, root, 100)));
        assert!(
            cache.insert_validator_fed_bid(
                make_gossip_verified(slot, 1, hash, root, 100).signed_bid
            )
        );

        let best = cache
            .get_highest_gossip_or_fed_bid(slot, bid_parent)
            .unwrap();
        assert_eq!(best.message().builder_index(), 0);
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
            cache.observe_bid(verified);
            let fed_bid = make_gossip_verified(Slot::new(slot), slot, hash, root, slot * 100 + 1);
            cache.insert_validator_fed_bid(fed_bid.signed_bid);
        }

        cache.prune(Slot::new(8));

        // Slots 1-7 pruned from all maps.
        for slot in [1, 2, 3, 7] {
            assert!(cache.get_highest_bid(Slot::new(slot), bid_parent).is_none());
            assert!(!cache.seen_builder_bid_for_parent(&Slot::new(slot), bid_parent, slot));
            assert!(
                cache
                    .get_highest_gossip_or_fed_bid(Slot::new(slot), bid_parent)
                    .is_none()
            );
        }
        // Slots 8-10 retained in all maps.
        for slot in [8, 9, 10] {
            assert!(cache.get_highest_bid(Slot::new(slot), bid_parent).is_some());
            assert!(cache.seen_builder_bid_for_parent(&Slot::new(slot), bid_parent, slot));
            let best = cache
                .get_highest_gossip_or_fed_bid(Slot::new(slot), bid_parent)
                .unwrap();
            assert_eq!(best.message().value(), slot * 100 + 1);
        }
    }
}
