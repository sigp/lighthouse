use super::Error;
use crate::{BeaconState, EthSpec, Hash256};
use cached_tree_hash::{CachedTreeHash, MultiTreeHashCache, TreeHashCache, VecArena};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;

#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct BeaconTreeHashCache {
    // Arenas
    fixed_arena: VecArena,
    validator_arena: VecArena,
    balances_arena: VecArena,
    slashings_arena: VecArena,
    // Caches
    block_roots: TreeHashCache,
    state_roots: TreeHashCache,
    historical_roots: TreeHashCache,
    validators: MultiTreeHashCache,
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

        let mut validator_arena = VecArena::default();
        let validators = state.validators.new_tree_hash_cache(&mut validator_arena);

        let mut balances_arena = VecArena::default();
        let balances = state.balances.new_tree_hash_cache(&mut balances_arena);

        let mut slashings_arena = VecArena::default();
        let slashings = state.slashings.new_tree_hash_cache(&mut slashings_arena);

        Self {
            fixed_arena,
            validator_arena,
            balances_arena,
            slashings_arena,
            block_roots,
            state_roots,
            historical_roots,
            validators,
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
            &mut state
                .validators
                .recalculate_tree_hash_root(&mut self.validator_arena, &mut self.validators)?
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
