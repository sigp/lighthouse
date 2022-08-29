use crate::TestHarness;
use state_processing::state_advance::complete_state_advance;
use std::collections::BTreeMap;
use types::*;

/// For every head removed, I spawn another.
#[derive(Default)]
pub struct Hydra<E: EthSpec> {
    states: BTreeMap<Hash256, BeaconState<E>>,
}

impl<E: EthSpec> Hydra<E> {
    pub fn update(&mut self, harness: &TestHarness<E>, current_epoch: Epoch, spec: &ChainSpec) {
        let finalized_checkpoint = harness
            .chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint();
        let finalized_slot = finalized_checkpoint.epoch.start_slot(E::slots_per_epoch());

        // Pull up every block on every viable chain that descends from finalization.
        for (head_block_root, _) in harness.chain.heads() {
            let relevant_block_roots = harness
                .chain
                .rev_iter_block_roots_from(head_block_root)
                .unwrap()
                .map(Result::unwrap)
                .take_while(|(_, slot)| *slot >= finalized_slot)
                .collect::<Vec<_>>();

            // Discard this head if it isn't descended from the finalized checkpoint (special case
            // for genesis).
            if relevant_block_roots.last().map(|(root, _)| root) != Some(&finalized_checkpoint.root)
                && finalized_slot != 0
            {
                continue;
            }

            for (block_root, _) in relevant_block_roots {
                self.ensure_block(harness, block_root, current_epoch, finalized_slot, spec);
            }
        }

        // Prune all stale heads.
        self.prune(finalized_checkpoint);
    }

    fn ensure_block(
        &mut self,
        harness: &TestHarness<E>,
        block_root: Hash256,
        current_epoch: Epoch,
        finalized_slot: Slot,
        spec: &ChainSpec,
    ) {
        use std::collections::btree_map::Entry;

        let state = match self.states.entry(block_root) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let block = harness
                    .chain
                    .get_blinded_block(&block_root)
                    .unwrap()
                    .unwrap();

                // This check necessary to prevent freakouts at skipped slots.
                if block.slot() < finalized_slot {
                    return;
                }

                let mut state = harness
                    .get_hot_state(block.state_root().into())
                    .unwrap_or_else(|| {
                        panic!(
                            "missing state for block {:?} at slot {}, current epoch: {:?}",
                            block_root,
                            block.slot(),
                            current_epoch
                        );
                    });
                state.build_all_caches(spec).unwrap();
                e.insert(state)
            }
        };

        if state.current_epoch() != current_epoch {
            complete_state_advance(
                state,
                None,
                current_epoch.start_slot(E::slots_per_epoch()),
                spec,
            )
            .unwrap();
        }
    }

    pub fn prune(&mut self, finalized_checkpoint: Checkpoint) {
        self.states.retain(|_, state| {
            state.finalized_checkpoint() == finalized_checkpoint || finalized_checkpoint.epoch == 0
        })
    }

    pub fn num_heads(&self) -> usize {
        self.states.len()
    }

    pub fn block_is_viable(&self, block_root: &Hash256) -> bool {
        self.states.contains_key(block_root)
    }

    pub fn proposer_heads_at_slot(
        &self,
        slot: Slot,
        validator_indices: &[usize],
        spec: &ChainSpec,
    ) -> BTreeMap<usize, Vec<(Hash256, &BeaconState<E>)>> {
        let mut proposer_heads = BTreeMap::new();

        for (block_root, state) in &self.states {
            let proposer = state.get_beacon_proposer_index(slot, spec).unwrap();
            if validator_indices.contains(&proposer) {
                proposer_heads
                    .entry(proposer)
                    .or_insert_with(Vec::new)
                    .push((*block_root, state));
            }
        }

        // Sort vecs to establish deterministic ordering.
        for (_, proposal_opps) in &mut proposer_heads {
            proposal_opps.sort_by_key(|(block_root, _)| *block_root);
        }

        proposer_heads
    }
}
