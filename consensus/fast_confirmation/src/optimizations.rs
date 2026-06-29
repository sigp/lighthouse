//! Performance optimizations for the Fast Confirmation Rule.
//!
//! Nothing here is a spec function; each item computes a spec-defined quantity (e.g. the
//! per-block `get_attestation_score`) via a faster algorithm. They are deliberately kept out of
//! `lib.rs` so that module reads as the spec algorithm.

use crate::{BalanceSourceData, Error};
use proto_array::core::{ProtoArray, VoteTracker};
use safe_arith::SafeArith;
use std::collections::{BTreeSet, HashMap};
use types::{Checkpoint, Epoch, Hash256, Slot};

/// An observed-justified checkpoint paired with the balance snapshot anchored to it.
///
/// The fields are private and can only be set together through [`Self::new`], so the spec tracking
/// variable and its `get_*_balance_source` data cannot drift apart by accident. The balances carry
/// their own `checkpoint` (the one they were built for); [`Self::is_stale`] reports when that lags
/// the tracked `checkpoint` and a rebuild is due.
#[derive(Clone, Debug)]
pub struct CheckpointAndBalance {
    checkpoint: Checkpoint,
    balances: BalanceSourceData,
}

impl CheckpointAndBalance {
    pub fn new(checkpoint: Checkpoint, balances: BalanceSourceData) -> Self {
        Self {
            checkpoint,
            balances,
        }
    }

    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    pub fn balances(&self) -> &BalanceSourceData {
        &self.balances
    }
}

/// Cached implementation of the spec's `get_attestation_score`.
///
/// The Python spec computes `get_attestation_score(store, node, balance_source)` independently
/// for each candidate block. Lighthouse computes the same scores for a canonical chain segment in
/// one pass and then serves individual `get_attestation_score` calls from this cache.
pub(crate) struct AttestationScoreCache {
    scores: HashMap<Hash256, u64>,
}

impl AttestationScoreCache {
    pub(crate) fn for_chain(
        proto_array: &ProtoArray,
        chain: &[Hash256],
        terminal_slot: Slot,
        balance_source: &BalanceSourceData,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            scores: precompute_chain_attestation_scores(
                proto_array,
                chain,
                terminal_slot,
                balance_source,
                votes,
                equivocating_indices,
            )?,
        })
    }

    pub(crate) fn get_attestation_score(&self, block_root: Hash256) -> Option<u64> {
        self.scores.get(&block_root).copied()
    }
}

/// Identity hasher for `u64` keys that are already well-distributed (block-root byte prefixes).
/// The per-vote memos resolve each vote's root/checkpoint at most once across the whole validator
/// set; keying them on a root prefix with this no-op hasher avoids SipHashing a 32-byte `Hash256`
/// per validator (~1M times). Hash quality is irrelevant to correctness — the memo stores and
/// compares the full key.
#[derive(Default)]
struct IdentityU64Hasher(u64);
impl std::hash::Hasher for IdentityU64Hasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {}
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

/// First 8 bytes of a block root as a `u64` (roots are uniformly distributed, so this is a good
/// hash). The stored full key disambiguates the (2⁻⁶⁴) prefix collision.
fn root_prefix(root: &Hash256) -> u64 {
    u64::from_le_bytes(
        root.as_slice()[..8]
            .try_into()
            .expect("Hash256 is 32 bytes"),
    )
}

/// A key that can be hashed cheaply from the block root it contains.
pub(crate) trait RootKey: Copy + Eq {
    fn prefix_hash(&self) -> u64;
}

impl RootKey for Hash256 {
    fn prefix_hash(&self) -> u64 {
        root_prefix(self)
    }
}

impl RootKey for (Hash256, Epoch) {
    fn prefix_hash(&self) -> u64 {
        root_prefix(&self.0) ^ self.1.as_u64()
    }
}

/// Memoizes `K -> V`, hashing on the root's own bytes (via [`IdentityU64Hasher`]) and storing the
/// full key to resolve the rare prefix collision. Avoids re-hashing 32-byte keys in the
/// per-validator loops.
pub(crate) struct RootMemo<K: RootKey, V> {
    map: HashMap<u64, (K, V), std::hash::BuildHasherDefault<IdentityU64Hasher>>,
}

impl<K: RootKey, V: Copy> RootMemo<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }

    /// Returns the memoized value for `key`, computing and storing it with `f` on a miss.
    pub(crate) fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V {
        if let Some((k, v)) = self.map.get(&key.prefix_hash())
            && *k == key
        {
            return *v;
        }
        let v = f();
        self.map.insert(key.prefix_hash(), (key, v));
        v
    }

    /// Like [`Self::get_or_insert_with`] but `f` may fail; the error is propagated and not stored.
    pub(crate) fn get_or_try_insert_with<E>(
        &mut self,
        key: K,
        f: impl FnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        if let Some((k, v)) = self.map.get(&key.prefix_hash())
            && *k == key
        {
            return Ok(*v);
        }
        let v = f()?;
        self.map.insert(key.prefix_hash(), (key, v));
        Ok(v)
    }
}

/// Projects a vote root onto the canonical chain: resolves it to the deepest chain position it
/// descends from, memoizing the proto-array ancestor walk (each distinct root resolved at most
/// once across the validator set).
struct ChainProjector<'a> {
    proto_array: &'a ProtoArray,
    /// node index → position on the canonical chain segment.
    index_to_position: HashMap<usize, usize>,
    terminal_slot: Slot,
    memo: RootMemo<Hash256, Option<usize>>,
}

impl<'a> ChainProjector<'a> {
    fn new(proto_array: &'a ProtoArray, chain: &[Hash256], terminal_slot: Slot) -> Self {
        let mut index_to_position = HashMap::with_capacity(chain.len());
        for (pos, root) in chain.iter().enumerate() {
            if let Some(&idx) = proto_array.indices.get(root) {
                index_to_position.insert(idx, pos);
            }
        }
        Self {
            proto_array,
            index_to_position,
            terminal_slot,
            memo: RootMemo::new(),
        }
    }

    /// The deepest canonical position `vote_root` descends from, or `None` if it covers no block
    /// on the segment.
    fn project(&mut self, vote_root: Hash256) -> Option<usize> {
        // Destructure so the borrow checker sees `memo` (mut) and the read-only fields as disjoint.
        let Self {
            proto_array,
            index_to_position,
            terminal_slot,
            memo,
        } = self;
        memo.get_or_insert_with(vote_root, || {
            let &start_idx = proto_array.indices.get(&vote_root)?;
            let mut idx = start_idx;
            loop {
                if let Some(&pos) = index_to_position.get(&idx) {
                    return Some(pos);
                }
                let node = proto_array.nodes.get(idx)?;
                if node.slot() <= *terminal_slot {
                    break;
                }
                idx = node.parent()?;
            }
            None
        })
    }
}

/// Precompute the per-block attestation score (spec's `get_attestation_score`) for every block on
/// `chain`, ordered `terminal_root`-exclusive .. `chain_tip`-inclusive, with `terminal_slot` the
/// terminal's slot.
///
/// Replaces B separate O(V × depth) `get_attestation_score` calls with one pass: each vote is
/// charged to the deepest canonical block it covers, then a suffix-sum propagates that weight up
/// to all ancestors. Pure optimization — not a spec function.
pub fn precompute_chain_attestation_scores(
    proto_array: &ProtoArray,
    chain: &[Hash256],
    terminal_slot: Slot,
    balance_source: &BalanceSourceData,
    votes: &[VoteTracker],
    equivocating_indices: &BTreeSet<u64>,
) -> Result<HashMap<Hash256, u64>, Error> {
    let chain_len = chain.len();
    let mut score_at_position = vec![0u64; chain_len];
    let mut projector = ChainProjector::new(proto_array, chain, terminal_slot);

    for (val_idx, vote) in votes.iter().enumerate() {
        let vote_root = vote.current_root();
        if vote_root.is_zero() || equivocating_indices.contains(&(val_idx as u64)) {
            continue;
        }
        let balance = balance_source.unslashed_balance(val_idx);
        if balance == 0 {
            continue;
        }
        if let Some(pos) = projector.project(vote_root) {
            let score = score_at_position
                .get_mut(pos)
                .ok_or(Error::IndexOutOfBounds(pos))?;
            *score = score.safe_add(balance)?;
        }
    }

    // Suffix sum: a vote covering position j also covers all ancestors at positions 0..j.
    let mut scores = HashMap::with_capacity(chain_len);
    let mut running = 0u64;
    for i in (0..chain_len).rev() {
        running = running.safe_add(score_at_position[i])?;
        scores.insert(chain[i], running);
    }
    Ok(scores)
}
