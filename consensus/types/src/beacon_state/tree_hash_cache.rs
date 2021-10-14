#![allow(clippy::integer_arithmetic)]
#![allow(clippy::disallowed_method)]
#![allow(clippy::indexing_slicing)]

use super::Error;
use crate::{BeaconState, EthSpec, Hash256, ParticipationList, Slot, Unsigned, Validator};
use cached_tree_hash::{int_log, CacheArena, CachedTreeHash, TreeHashCache};
use rayon::prelude::*;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::cmp::Ordering;
use std::iter::ExactSizeIterator;
use tree_hash::{mix_in_length, MerkleHasher, TreeHash};

/// The number of leaves (including padding) on the `BeaconState` Merkle tree.
///
/// ## Note
///
/// This constant is set with the assumption that there are `> 16` and `<= 32` fields on the
/// `BeaconState`. **Tree hashing will fail if this value is set incorrectly.**
const NUM_BEACON_STATE_HASH_TREE_ROOT_LEAVES: usize = 32;

/// The number of nodes in the Merkle tree of a validator record.
const NODES_PER_VALIDATOR: usize = 15;

/// The number of validator record tree hash caches stored in each arena.
///
/// This is primarily used for concurrency; if we have 16 validators and set `VALIDATORS_PER_ARENA
/// == 8` then it is possible to do a 2-core concurrent hash.
///
/// Do not set to 0.
const VALIDATORS_PER_ARENA: usize = 4_096;

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Eth1DataVotesTreeHashCache<T: EthSpec> {
    arena: CacheArena,
    tree_hash_cache: TreeHashCache,
    voting_period: u64,
    roots: VariableList<Hash256, T::SlotsPerEth1VotingPeriod>,
}

impl<T: EthSpec> Eth1DataVotesTreeHashCache<T> {
    /// Instantiates a new cache.
    ///
    /// Allocates the necessary memory to store all of the cached Merkle trees. Only the leaves are
    /// hashed, leaving the internal nodes as all-zeros.
    pub fn new(state: &BeaconState<T>) -> Self {
        let mut arena = CacheArena::default();
        let roots: VariableList<_, _> = state
            .eth1_data_votes()
            .iter()
            .map(|eth1_data| eth1_data.tree_hash_root())
            .collect::<Vec<_>>()
            .into();
        let tree_hash_cache = roots.new_tree_hash_cache(&mut arena);

        Self {
            arena,
            tree_hash_cache,
            voting_period: Self::voting_period(state.slot()),
            roots,
        }
    }

    fn voting_period(slot: Slot) -> u64 {
        slot.as_u64() / T::SlotsPerEth1VotingPeriod::to_u64()
    }

    pub fn recalculate_tree_hash_root(&mut self, state: &BeaconState<T>) -> Result<Hash256, Error> {
        if state.eth1_data_votes().len() < self.roots.len()
            || Self::voting_period(state.slot()) != self.voting_period
        {
            *self = Self::new(state);
        }

        state
            .eth1_data_votes()
            .iter()
            .skip(self.roots.len())
            .try_for_each(|eth1_data| self.roots.push(eth1_data.tree_hash_root()))?;

        self.roots
            .recalculate_tree_hash_root(&mut self.arena, &mut self.tree_hash_cache)
            .map_err(Into::into)
    }
}

/// A cache that performs a caching tree hash of the entire `BeaconState` struct.
///
/// This type is a wrapper around the inner cache, which does all the work.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct BeaconTreeHashCache<T: EthSpec> {
    inner: Option<BeaconTreeHashCacheInner<T>>,
}

impl<T: EthSpec> BeaconTreeHashCache<T> {
    pub fn new(state: &BeaconState<T>) -> Self {
        Self {
            inner: Some(BeaconTreeHashCacheInner::new(state)),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.is_some()
    }

    /// Move the inner cache out so that the containing `BeaconState` can be borrowed.
    pub fn take(&mut self) -> Option<BeaconTreeHashCacheInner<T>> {
        self.inner.take()
    }

    /// Restore the inner cache after using `take`.
    pub fn restore(&mut self, inner: BeaconTreeHashCacheInner<T>) {
        self.inner = Some(inner);
    }

    /// Make the cache empty.
    pub fn uninitialize(&mut self) {
        self.inner = None;
    }

    /// Return the slot at which the cache was last updated.
    ///
    /// This should probably only be used during testing.
    pub fn initialized_slot(&self) -> Option<Slot> {
        Some(self.inner.as_ref()?.previous_state?.1)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct BeaconTreeHashCacheInner<T: EthSpec> {
    /// Tracks the previously generated state root to ensure the next state root provided descends
    /// directly from this state.
    previous_state: Option<(Hash256, Slot)>,
    // Validators cache
    validators: ValidatorsListTreeHashCache,
    // Arenas
    fixed_arena: CacheArena,
    balances_arena: CacheArena,
    slashings_arena: CacheArena,
    // Caches
    block_roots: TreeHashCache,
    state_roots: TreeHashCache,
    historical_roots: TreeHashCache,
    balances: TreeHashCache,
    randao_mixes: TreeHashCache,
    slashings: TreeHashCache,
    eth1_data_votes: Eth1DataVotesTreeHashCache<T>,
    inactivity_scores: OptionalTreeHashCache,
    // Participation caches
    previous_epoch_participation: OptionalTreeHashCache,
    current_epoch_participation: OptionalTreeHashCache,
}

impl<T: EthSpec> BeaconTreeHashCacheInner<T> {
    /// Instantiates a new cache.
    ///
    /// Allocates the necessary memory to store all of the cached Merkle trees. Only the leaves are
    /// hashed, leaving the internal nodes as all-zeros.
    pub fn new(state: &BeaconState<T>) -> Self {
        let mut fixed_arena = CacheArena::default();
        let block_roots = state.block_roots().new_tree_hash_cache(&mut fixed_arena);
        let state_roots = state.state_roots().new_tree_hash_cache(&mut fixed_arena);
        let historical_roots = state
            .historical_roots()
            .new_tree_hash_cache(&mut fixed_arena);
        let randao_mixes = state.randao_mixes().new_tree_hash_cache(&mut fixed_arena);

        let validators = ValidatorsListTreeHashCache::new::<T>(state.validators());

        let mut balances_arena = CacheArena::default();
        let balances = state.balances().new_tree_hash_cache(&mut balances_arena);

        let mut slashings_arena = CacheArena::default();
        let slashings = state.slashings().new_tree_hash_cache(&mut slashings_arena);

        let inactivity_scores = OptionalTreeHashCache::new(state.inactivity_scores().ok());

        let previous_epoch_participation = OptionalTreeHashCache::new(
            state
                .previous_epoch_participation()
                .ok()
                .map(ParticipationList::new)
                .as_ref(),
        );
        let current_epoch_participation = OptionalTreeHashCache::new(
            state
                .current_epoch_participation()
                .ok()
                .map(ParticipationList::new)
                .as_ref(),
        );

        Self {
            previous_state: None,
            validators,
            fixed_arena,
            balances_arena,
            slashings_arena,
            block_roots,
            state_roots,
            historical_roots,
            balances,
            randao_mixes,
            slashings,
            inactivity_scores,
            eth1_data_votes: Eth1DataVotesTreeHashCache::new(state),
            previous_epoch_participation,
            current_epoch_participation,
        }
    }

    /// Updates the cache and returns the tree hash root for the given `state`.
    ///
    /// The provided `state` should be a descendant of the last `state` given to this function, or
    /// the `Self::new` function. If the state is more than `SLOTS_PER_HISTORICAL_ROOT` slots
    /// after `self.previous_state` then the whole cache will be re-initialized.
    pub fn recalculate_tree_hash_root(&mut self, state: &BeaconState<T>) -> Result<Hash256, Error> {
        // If this cache has previously produced a root, ensure that it is in the state root
        // history of this state.
        //
        // This ensures that the states applied have a linear history, this
        // allows us to make assumptions about how the state changes over times and produce a more
        // efficient algorithm.
        if let Some((previous_root, previous_slot)) = self.previous_state {
            // The previously-hashed state must not be newer than `state`.
            if previous_slot > state.slot() {
                return Err(Error::TreeHashCacheSkippedSlot {
                    cache: previous_slot,
                    state: state.slot(),
                });
            }

            // If the state is newer, the previous root must be in the history of the given state.
            // If the previous slot is out of range of the `state_roots` array (indicating a long
            // gap between the cache's last use and the current state) then we re-initialize.
            match state.get_state_root(previous_slot) {
                Ok(state_previous_root) if *state_previous_root == previous_root => {}
                Ok(_) => return Err(Error::NonLinearTreeHashCacheHistory),
                Err(Error::SlotOutOfBounds) => {
                    *self = Self::new(state);
                }
                Err(e) => return Err(e),
            }
        }

        let mut hasher = MerkleHasher::with_leaves(NUM_BEACON_STATE_HASH_TREE_ROOT_LEAVES);

        hasher.write(state.genesis_time().tree_hash_root().as_bytes())?;
        hasher.write(state.genesis_validators_root().tree_hash_root().as_bytes())?;
        hasher.write(state.slot().tree_hash_root().as_bytes())?;
        hasher.write(state.fork().tree_hash_root().as_bytes())?;
        hasher.write(state.latest_block_header().tree_hash_root().as_bytes())?;
        hasher.write(
            state
                .block_roots()
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.block_roots)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .state_roots()
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.state_roots)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .historical_roots()
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.historical_roots)?
                .as_bytes(),
        )?;
        hasher.write(state.eth1_data().tree_hash_root().as_bytes())?;
        hasher.write(
            self.eth1_data_votes
                .recalculate_tree_hash_root(state)?
                .as_bytes(),
        )?;
        hasher.write(state.eth1_deposit_index().tree_hash_root().as_bytes())?;
        hasher.write(
            self.validators
                .recalculate_tree_hash_root(state.validators())?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .balances()
                .recalculate_tree_hash_root(&mut self.balances_arena, &mut self.balances)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .randao_mixes()
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.randao_mixes)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .slashings()
                .recalculate_tree_hash_root(&mut self.slashings_arena, &mut self.slashings)?
                .as_bytes(),
        )?;

        // Participation
        if let BeaconState::Base(state) = state {
            hasher.write(
                state
                    .previous_epoch_attestations
                    .tree_hash_root()
                    .as_bytes(),
            )?;
            hasher.write(state.current_epoch_attestations.tree_hash_root().as_bytes())?;
        } else {
            hasher.write(
                self.previous_epoch_participation
                    .recalculate_tree_hash_root(&ParticipationList::new(
                        state.previous_epoch_participation()?,
                    ))?
                    .as_bytes(),
            )?;
            hasher.write(
                self.current_epoch_participation
                    .recalculate_tree_hash_root(&ParticipationList::new(
                        state.current_epoch_participation()?,
                    ))?
                    .as_bytes(),
            )?;
        }

        hasher.write(state.justification_bits().tree_hash_root().as_bytes())?;
        hasher.write(
            state
                .previous_justified_checkpoint()
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(
            state
                .current_justified_checkpoint()
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(state.finalized_checkpoint().tree_hash_root().as_bytes())?;

        // Inactivity & light-client sync committees
        if let BeaconState::Altair(ref state) = state {
            hasher.write(
                self.inactivity_scores
                    .recalculate_tree_hash_root(&state.inactivity_scores)?
                    .as_bytes(),
            )?;

            hasher.write(state.current_sync_committee.tree_hash_root().as_bytes())?;
            hasher.write(state.next_sync_committee.tree_hash_root().as_bytes())?;
        }

        let root = hasher.finish()?;

        self.previous_state = Some((root, state.slot()));

        Ok(root)
    }

    /// Updates the cache and provides the root of the given `validators`.
    pub fn recalculate_validators_tree_hash_root(
        &mut self,
        validators: &[Validator],
    ) -> Result<Hash256, Error> {
        self.validators.recalculate_tree_hash_root(validators)
    }
}

/// A specialized cache for computing the tree hash root of `state.validators`.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
struct ValidatorsListTreeHashCache {
    list_arena: CacheArena,
    list_cache: TreeHashCache,
    values: ParallelValidatorTreeHash,
}

impl ValidatorsListTreeHashCache {
    /// Instantiates a new cache.
    ///
    /// Allocates the necessary memory to store all of the cached Merkle trees but does perform any
    /// hashing.
    fn new<E: EthSpec>(validators: &[Validator]) -> Self {
        let mut list_arena = CacheArena::default();
        Self {
            list_cache: TreeHashCache::new(
                &mut list_arena,
                int_log(E::ValidatorRegistryLimit::to_usize()),
                validators.len(),
            ),
            list_arena,
            values: ParallelValidatorTreeHash::new::<E>(validators),
        }
    }

    /// Updates the cache and returns the tree hash root for the given `state`.
    ///
    /// This function makes assumptions that the `validators` list will only change in accordance
    /// with valid per-block/per-slot state transitions.
    fn recalculate_tree_hash_root(&mut self, validators: &[Validator]) -> Result<Hash256, Error> {
        let mut list_arena = std::mem::take(&mut self.list_arena);

        let leaves = self.values.leaves(validators)?;
        let num_leaves = leaves.iter().map(|arena| arena.len()).sum();

        let leaves_iter = ForcedExactSizeIterator {
            iter: leaves.into_iter().flatten().map(|h| h.to_fixed_bytes()),
            len: num_leaves,
        };

        let list_root = self
            .list_cache
            .recalculate_merkle_root(&mut list_arena, leaves_iter)?;

        self.list_arena = list_arena;

        Ok(mix_in_length(&list_root, validators.len()))
    }
}

/// Provides a wrapper around some `iter` if the number of items in the iterator is known to the
/// programmer but not the compiler. This allows use of `ExactSizeIterator` in some occasions.
///
/// Care should be taken to ensure `len` is accurate.
struct ForcedExactSizeIterator<I> {
    iter: I,
    len: usize,
}

impl<V, I: Iterator<Item = V>> Iterator for ForcedExactSizeIterator<I> {
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<V, I: Iterator<Item = V>> ExactSizeIterator for ForcedExactSizeIterator<I> {
    fn len(&self) -> usize {
        self.len
    }
}

/// Provides a cache for each of the `Validator` objects in `state.validators` and computes the
/// roots of these using Rayon parallelization.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct ParallelValidatorTreeHash {
    /// Each arena and its associated sub-trees.
    arenas: Vec<(CacheArena, Vec<TreeHashCache>)>,
}

impl ParallelValidatorTreeHash {
    /// Instantiates a new cache.
    ///
    /// Allocates the necessary memory to store all of the cached Merkle trees but does perform any
    /// hashing.
    fn new<E: EthSpec>(validators: &[Validator]) -> Self {
        let num_arenas = std::cmp::max(
            1,
            (validators.len() + VALIDATORS_PER_ARENA - 1) / VALIDATORS_PER_ARENA,
        );

        let mut arenas = (1..=num_arenas)
            .map(|i| {
                let num_validators = if i == num_arenas {
                    validators.len() % VALIDATORS_PER_ARENA
                } else {
                    VALIDATORS_PER_ARENA
                };
                NODES_PER_VALIDATOR * num_validators
            })
            .map(|capacity| (CacheArena::with_capacity(capacity), vec![]))
            .collect::<Vec<_>>();

        validators.iter().enumerate().for_each(|(i, v)| {
            let (arena, caches) = &mut arenas[i / VALIDATORS_PER_ARENA];
            caches.push(v.new_tree_hash_cache(arena))
        });

        Self { arenas }
    }

    /// Returns the number of validators stored in self.
    fn len(&self) -> usize {
        self.arenas.last().map_or(0, |last| {
            // Subtraction cannot underflow because `.last()` ensures the `.len() > 0`.
            (self.arenas.len() - 1) * VALIDATORS_PER_ARENA + last.1.len()
        })
    }

    /// Updates the caches for each `Validator` in `validators` and returns a list that maps 1:1
    /// with `validators` to the hash of each validator.
    ///
    /// This function makes assumptions that the `validators` list will only change in accordance
    /// with valid per-block/per-slot state transitions.
    fn leaves(&mut self, validators: &[Validator]) -> Result<Vec<Vec<Hash256>>, Error> {
        match self.len().cmp(&validators.len()) {
            Ordering::Less => validators.iter().skip(self.len()).for_each(|v| {
                if self
                    .arenas
                    .last()
                    .map_or(true, |last| last.1.len() >= VALIDATORS_PER_ARENA)
                {
                    let mut arena = CacheArena::default();
                    let cache = v.new_tree_hash_cache(&mut arena);
                    self.arenas.push((arena, vec![cache]))
                } else {
                    let (arena, caches) = &mut self
                        .arenas
                        .last_mut()
                        .expect("Cannot reach this block if arenas is empty.");
                    caches.push(v.new_tree_hash_cache(arena))
                }
            }),
            Ordering::Greater => {
                return Err(Error::ValidatorRegistryShrunk);
            }
            Ordering::Equal => (),
        }

        self.arenas
            .par_iter_mut()
            .enumerate()
            .map(|(arena_index, (arena, caches))| {
                caches
                    .iter_mut()
                    .enumerate()
                    .map(move |(cache_index, cache)| {
                        let val_index = (arena_index * VALIDATORS_PER_ARENA) + cache_index;

                        let validator = validators
                            .get(val_index)
                            .ok_or(Error::TreeHashCacheInconsistent)?;

                        validator
                            .recalculate_tree_hash_root(arena, cache)
                            .map_err(Error::CachedTreeHashError)
                    })
                    .collect()
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct OptionalTreeHashCache {
    inner: Option<OptionalTreeHashCacheInner>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct OptionalTreeHashCacheInner {
    arena: CacheArena,
    tree_hash_cache: TreeHashCache,
}

impl OptionalTreeHashCache {
    /// Initialize a new cache if `item.is_some()`.
    fn new<C: CachedTreeHash<TreeHashCache>>(item: Option<&C>) -> Self {
        let inner = item.map(OptionalTreeHashCacheInner::new);
        Self { inner }
    }

    /// Compute the tree hash root for the given `item`.
    ///
    /// This function will initialize the inner cache if necessary (e.g. when crossing the fork).
    fn recalculate_tree_hash_root<C: CachedTreeHash<TreeHashCache>>(
        &mut self,
        item: &C,
    ) -> Result<Hash256, Error> {
        let cache = self
            .inner
            .get_or_insert_with(|| OptionalTreeHashCacheInner::new(item));
        item.recalculate_tree_hash_root(&mut cache.arena, &mut cache.tree_hash_cache)
            .map_err(Into::into)
    }
}

impl OptionalTreeHashCacheInner {
    fn new<C: CachedTreeHash<TreeHashCache>>(item: &C) -> Self {
        let mut arena = CacheArena::default();
        let tree_hash_cache = item.new_tree_hash_cache(&mut arena);
        OptionalTreeHashCacheInner {
            arena,
            tree_hash_cache,
        }
    }
}

#[cfg(feature = "arbitrary-fuzz")]
impl<T: EthSpec> arbitrary::Arbitrary<'_> for BeaconTreeHashCache<T> {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MainnetEthSpec, ParticipationFlags};

    #[test]
    fn validator_node_count() {
        let mut arena = CacheArena::default();
        let v = Validator::default();
        let _cache = v.new_tree_hash_cache(&mut arena);
        assert_eq!(arena.backing_len(), NODES_PER_VALIDATOR);
    }

    #[test]
    fn participation_flags() {
        type N = <MainnetEthSpec as EthSpec>::ValidatorRegistryLimit;
        let len = 65;
        let mut test_flag = ParticipationFlags::default();
        test_flag.add_flag(0).unwrap();
        let epoch_participation = VariableList::<_, N>::new(vec![test_flag; len]).unwrap();

        let mut cache = OptionalTreeHashCache { inner: None };

        let cache_root = cache
            .recalculate_tree_hash_root(&ParticipationList::new(&epoch_participation))
            .unwrap();
        let recalc_root = cache
            .recalculate_tree_hash_root(&ParticipationList::new(&epoch_participation))
            .unwrap();

        assert_eq!(cache_root, recalc_root, "recalculated root should match");
        assert_eq!(
            cache_root,
            epoch_participation.tree_hash_root(),
            "cached root should match uncached"
        );
    }
}
