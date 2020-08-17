#![allow(clippy::integer_arithmetic)]

use super::Error;
use crate::{BeaconState, EthSpec, Hash256, Slot, Unsigned, Validator};
use cached_tree_hash::{int_log, CacheArena, CachedTreeHash, TreeHashCache};
use rayon::prelude::*;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::cmp::Ordering;
use std::iter::ExactSizeIterator;
use tree_hash::{mix_in_length, MerkleHasher, TreeHash};

/// The number of fields on a beacon state.
const NUM_BEACON_STATE_HASHING_FIELDS: usize = 20;

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
            .eth1_data_votes
            .iter()
            .map(|eth1_data| eth1_data.tree_hash_root())
            .collect::<Vec<_>>()
            .into();
        let tree_hash_cache = roots.new_tree_hash_cache(&mut arena);

        Self {
            arena,
            tree_hash_cache,
            voting_period: Self::voting_period(state.slot),
            roots,
        }
    }

    fn voting_period(slot: Slot) -> u64 {
        slot.as_u64() / T::SlotsPerEth1VotingPeriod::to_u64()
    }

    pub fn recalculate_tree_hash_root(&mut self, state: &BeaconState<T>) -> Result<Hash256, Error> {
        if state.eth1_data_votes.len() < self.roots.len()
            || Self::voting_period(state.slot) != self.voting_period
        {
            *self = Self::new(state);
        }

        state
            .eth1_data_votes
            .iter()
            .skip(self.roots.len())
            .try_for_each(|eth1_data| self.roots.push(eth1_data.tree_hash_root()))?;

        self.roots
            .recalculate_tree_hash_root(&mut self.arena, &mut self.tree_hash_cache)
            .map_err(Into::into)
    }
}

/// A cache that performs a caching tree hash of the entire `BeaconState` struct.
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct BeaconTreeHashCache<T: EthSpec> {
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
}

impl<T: EthSpec> BeaconTreeHashCache<T> {
    /// Instantiates a new cache.
    ///
    /// Allocates the necessary memory to store all of the cached Merkle trees. Only the leaves are
    /// hashed, leaving the internal nodes as all-zeros.
    pub fn new(state: &BeaconState<T>) -> Self {
        let mut fixed_arena = CacheArena::default();
        let block_roots = state.block_roots.new_tree_hash_cache(&mut fixed_arena);
        let state_roots = state.state_roots.new_tree_hash_cache(&mut fixed_arena);
        let historical_roots = state.historical_roots.new_tree_hash_cache(&mut fixed_arena);
        let randao_mixes = state.randao_mixes.new_tree_hash_cache(&mut fixed_arena);

        let validators = ValidatorsListTreeHashCache::new::<T>(&state.validators[..]);

        let mut balances_arena = CacheArena::default();
        let balances = state.balances.new_tree_hash_cache(&mut balances_arena);

        let mut slashings_arena = CacheArena::default();
        let slashings = state.slashings.new_tree_hash_cache(&mut slashings_arena);

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
            eth1_data_votes: Eth1DataVotesTreeHashCache::new(state),
        }
    }

    /// Updates the cache and returns the tree hash root for the given `state`.
    ///
    /// The provided `state` should be a descendant of the last `state` given to this function, or
    /// the `Self::new` function.
    pub fn recalculate_tree_hash_root(&mut self, state: &BeaconState<T>) -> Result<Hash256, Error> {
        // If this cache has previously produced a root, ensure that it is in the state root
        // history of this state.
        //
        // This ensures that the states applied have a linear history, this
        // allows us to make assumptions about how the state changes over times and produce a more
        // efficient algorithm.
        if let Some((previous_root, previous_slot)) = self.previous_state {
            // The previously-hashed state must not be newer than `state`.
            if previous_slot > state.slot {
                return Err(Error::TreeHashCacheSkippedSlot {
                    cache: previous_slot,
                    state: state.slot,
                });
            }

            // If the state is newer, the previous root must be in the history of the given state.
            if previous_slot < state.slot && *state.get_state_root(previous_slot)? != previous_root
            {
                return Err(Error::NonLinearTreeHashCacheHistory);
            }
        }

        let mut hasher = MerkleHasher::with_leaves(NUM_BEACON_STATE_HASHING_FIELDS);

        hasher.write(state.genesis_time.tree_hash_root().as_bytes())?;
        hasher.write(state.genesis_validators_root.tree_hash_root().as_bytes())?;
        hasher.write(state.slot.tree_hash_root().as_bytes())?;
        hasher.write(state.fork.tree_hash_root().as_bytes())?;
        hasher.write(state.latest_block_header.tree_hash_root().as_bytes())?;
        hasher.write(
            state
                .block_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.block_roots)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .state_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.state_roots)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .historical_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.historical_roots)?
                .as_bytes(),
        )?;
        hasher.write(state.eth1_data.tree_hash_root().as_bytes())?;
        hasher.write(
            self.eth1_data_votes
                .recalculate_tree_hash_root(&state)?
                .as_bytes(),
        )?;
        hasher.write(state.eth1_deposit_index.tree_hash_root().as_bytes())?;
        hasher.write(
            self.validators
                .recalculate_tree_hash_root(&state.validators[..])?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .balances
                .recalculate_tree_hash_root(&mut self.balances_arena, &mut self.balances)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .randao_mixes
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.randao_mixes)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .slashings
                .recalculate_tree_hash_root(&mut self.slashings_arena, &mut self.slashings)?
                .as_bytes(),
        )?;
        hasher.write(
            state
                .previous_epoch_attestations
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(state.current_epoch_attestations.tree_hash_root().as_bytes())?;
        hasher.write(state.justification_bits.tree_hash_root().as_bytes())?;
        hasher.write(
            state
                .previous_justified_checkpoint
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(
            state
                .current_justified_checkpoint
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(state.finalized_checkpoint.tree_hash_root().as_bytes())?;

        let root = hasher.finish()?;

        self.previous_state = Some((root, state.slot));

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
                            .ok_or_else(|| Error::TreeHashCacheInconsistent)?;

                        validator
                            .recalculate_tree_hash_root(arena, cache)
                            .map_err(Error::CachedTreeHashError)
                    })
                    .collect()
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validator_node_count() {
        let mut arena = CacheArena::default();
        let v = Validator::default();
        let _cache = v.new_tree_hash_cache(&mut arena);
        assert_eq!(arena.backing_len(), NODES_PER_VALIDATOR);
    }
}
