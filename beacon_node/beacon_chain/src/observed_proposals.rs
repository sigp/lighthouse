use crate::observed_block_producers::Error;
use bls::Hash256;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::Unsigned;
use types::{BeaconBlockRef, EthSpec, Slot};

#[derive(Eq, Hash, PartialEq, Default)]
struct ProposalKey {
    proposer: u64,
    slot: Slot,
}

pub struct ObservedProposals<E: EthSpec> {
    finalized_slot: Slot,
    items: HashMap<ProposalKey, HashSet<Hash256>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedProposals<E> {
    fn default() -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: <_>::default(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedProposals<E> {
    pub fn observe_proposal(
        &mut self,
        block: BeaconBlockRef<'_, E>,
        block_root: Hash256,
    ) -> Result<bool, Error> {
        self.sanitize_block(block)?;

        let entry = self.items.entry(ProposalKey {
            proposer: block.proposer_index(),
            slot: block.slot(),
        });

        let slashable_proposal = match entry {
            Entry::Occupied(mut occupied_entry) => {
                let block_roots = occupied_entry.get_mut();
                block_roots.insert(block_root);
                block_roots.len() > 1
            }
            Entry::Vacant(vacant_entry) => {
                let root_set = HashSet::from([block_root]);
                vacant_entry.insert(root_set);
                false
            }
        };

        Ok(slashable_proposal)
    }

    fn sanitize_block(&self, block: BeaconBlockRef<'_, E>) -> Result<(), Error> {
        if block.proposer_index() >= E::ValidatorRegistryLimit::to_u64() {
            return Err(Error::ValidatorIndexTooHigh(block.proposer_index()));
        }

        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && block.slot() <= finalized_slot {
            return Err(Error::FinalizedBlock {
                slot: block.slot(),
                finalized_slot,
            });
        }

        Ok(())
    }

    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|key, _| key.slot > finalized_slot);
    }
}
