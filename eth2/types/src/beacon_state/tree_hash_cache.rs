use super::Error;
use crate::{BeaconState, EthSpec, Hash256, Unsigned, Validator};
use cached_tree_hash::{int_log, CachedTreeHash, TreeHashCache, VecArena};
use ssz_derive::{Decode, Encode};
use tree_hash::{mix_in_length, TreeHash};

#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct BeaconTreeHashCache {
    // Validators cache
    validators: ValidatorsTreeHashCache,
    // Arenas
    fixed_arena: VecArena,
    balances_arena: VecArena,
    slashings_arena: VecArena,
    // Caches
    block_roots: TreeHashCache,
    state_roots: TreeHashCache,
    historical_roots: TreeHashCache,
    balances: TreeHashCache,
    randao_mixes: TreeHashCache,
    slashings: TreeHashCache,
}

impl BeaconTreeHashCache {
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Self {
        let mut fixed_arena = VecArena::default();
        let block_roots = state.block_roots.new_tree_hash_cache(&mut fixed_arena);
        let state_roots = state.state_roots.new_tree_hash_cache(&mut fixed_arena);
        let historical_roots = state.historical_roots.new_tree_hash_cache(&mut fixed_arena);
        let randao_mixes = state.randao_mixes.new_tree_hash_cache(&mut fixed_arena);

        let validators = ValidatorsTreeHashCache::new::<T>(&state.validators[..]);

        let mut balances_arena = VecArena::default();
        let balances = state.balances.new_tree_hash_cache(&mut balances_arena);

        let mut slashings_arena = VecArena::default();
        let slashings = state.slashings.new_tree_hash_cache(&mut slashings_arena);

        Self {
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
        }
    }

    pub fn recalculate_tree_hash_root<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
    ) -> Result<Hash256, Error> {
        let mut leaves = vec![];

        leaves.append(&mut state.genesis_time.tree_hash_root());
        leaves.append(&mut state.slot.tree_hash_root());
        leaves.append(&mut state.fork.tree_hash_root());
        leaves.append(&mut state.latest_block_header.tree_hash_root());
        leaves.extend_from_slice(
            &mut state
                .block_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.block_roots)?
                .as_bytes(),
        );
        leaves.extend_from_slice(
            &mut state
                .state_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.state_roots)?
                .as_bytes(),
        );
        leaves.extend_from_slice(
            &mut state
                .historical_roots
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.historical_roots)?
                .as_bytes(),
        );
        leaves.append(&mut state.eth1_data.tree_hash_root());
        leaves.append(&mut state.eth1_data_votes.tree_hash_root());
        leaves.append(&mut state.eth1_deposit_index.tree_hash_root());
        leaves.extend_from_slice(
            &mut self
                .validators
                .recalculate_tree_hash_root(&state.validators[..])?
                .as_bytes(),
        );
        leaves.extend_from_slice(
            &mut state
                .balances
                .recalculate_tree_hash_root(&mut self.balances_arena, &mut self.balances)?
                .as_bytes(),
        );
        leaves.extend_from_slice(
            &mut state
                .randao_mixes
                .recalculate_tree_hash_root(&mut self.fixed_arena, &mut self.randao_mixes)?
                .as_bytes(),
        );
        leaves.extend_from_slice(
            &mut state
                .slashings
                .recalculate_tree_hash_root(&mut self.slashings_arena, &mut self.slashings)?
                .as_bytes(),
        );
        leaves.append(&mut state.previous_epoch_attestations.tree_hash_root());
        leaves.append(&mut state.current_epoch_attestations.tree_hash_root());
        leaves.append(&mut state.justification_bits.tree_hash_root());
        leaves.append(&mut state.previous_justified_checkpoint.tree_hash_root());
        leaves.append(&mut state.current_justified_checkpoint.tree_hash_root());
        leaves.append(&mut state.finalized_checkpoint.tree_hash_root());

        Ok(Hash256::from_slice(&tree_hash::merkle_root(&leaves, 0)))
    }
}

/// Multi-level tree hash cache.
///
/// Suitable for lists/vectors/containers holding values which themselves have caches.
///
/// Note: this cache could be made composable by replacing the hardcoded `Vec<TreeHashCache>` with
/// `Vec<C>`, allowing arbitrary nesting, but for now we stick to 2-level nesting because that's all
/// we need.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct ValidatorsTreeHashCache {
    arena: VecArena,
    list_cache: TreeHashCache,
    value_caches: Vec<TreeHashCache>,
}

impl ValidatorsTreeHashCache {
    fn new<E: EthSpec>(validators: &[Validator]) -> Self {
        let mut arena = VecArena::default();
        Self {
            list_cache: TreeHashCache::new(
                &mut arena,
                int_log(E::ValidatorRegistryLimit::to_usize()),
                validators.len(),
            ),
            value_caches: vec![],
            arena,
        }
    }

    fn recalculate_tree_hash_root(&mut self, validators: &[Validator]) -> Result<Hash256, Error> {
        let mut arena = std::mem::replace(&mut self.arena, VecArena::default());

        if validators.len() < self.value_caches.len() {
            return Err(Error::ValidatorRegistryShrunk);
        }

        // Resize the value caches to the size of the list.
        validators
            .iter()
            .skip(self.value_caches.len())
            .for_each(|value| {
                self.value_caches
                    .push(value.new_tree_hash_cache(&mut arena))
            });

        // Update all individual value caches.
        let leaves = validators
            .iter()
            .zip(self.value_caches.iter_mut())
            .map(|(value, cache)| {
                value
                    .recalculate_tree_hash_root(&mut arena, cache)
                    .map(|_| ())?;
                Ok(cache.root(&mut arena).to_fixed_bytes())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let list_root = self
            .list_cache
            .recalculate_merkle_root(&mut arena, leaves.into_iter())?;

        std::mem::replace(&mut self.arena, arena);

        Ok(Hash256::from_slice(&mix_in_length(
            list_root.as_bytes(),
            validators.len(),
        )))
    }
}
