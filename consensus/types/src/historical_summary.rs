use crate::test_utils::TestRandom;
use crate::Unsigned;
use crate::{BeaconState, EthSpec, Hash256};
use cached_tree_hash::Error;
use cached_tree_hash::{int_log, CacheArena, CachedTreeHash, TreeHashCache};
use compare_fields_derive::CompareFields;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash::{mix_in_length, TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;

/// `HistoricalSummary` matches the components of the phase0 `HistoricalBatch`
/// making the two hash_tree_root-compatible. This struct is introduced into the beacon state
/// in the Capella hard fork.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#historicalsummary
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    CompareFields,
    Clone,
    Copy,
    Default,
)]
pub struct HistoricalSummary {
    block_summary_root: Hash256,
    state_summary_root: Hash256,
}

impl HistoricalSummary {
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Self {
        Self {
            block_summary_root: state.block_roots().tree_hash_root(),
            state_summary_root: state.state_roots().tree_hash_root(),
        }
    }
}

/// Wrapper type allowing the implementation of `CachedTreeHash`.
#[derive(Debug)]
pub struct HistoricalSummaryCache<'a, N: Unsigned> {
    pub inner: &'a VariableList<HistoricalSummary, N>,
}

impl<'a, N: Unsigned> HistoricalSummaryCache<'a, N> {
    pub fn new(inner: &'a VariableList<HistoricalSummary, N>) -> Self {
        Self { inner }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, N: Unsigned> CachedTreeHash<TreeHashCache> for HistoricalSummaryCache<'a, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        TreeHashCache::new(arena, int_log(N::to_usize()), self.len())
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        Ok(mix_in_length(
            &cache.recalculate_merkle_root(arena, leaf_iter(self.inner))?,
            self.len(),
        ))
    }
}

pub fn leaf_iter(
    values: &[HistoricalSummary],
) -> impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator + '_ {
    values
        .iter()
        .map(|value| value.tree_hash_root())
        .map(Hash256::to_fixed_bytes)
}
