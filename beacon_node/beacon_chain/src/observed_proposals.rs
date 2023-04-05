use crate::observed_block_producers::Error;
use bls::Hash256;
use std::collections::HashSet;
use std::marker::PhantomData;
use types::Unsigned;
use types::{BeaconBlockRef, EthSpec, Slot};

#[derive(Eq, Hash, PartialEq)]
struct ProposalKey {
    proposer: u64,
    slot: Slot,
    block_root: Hash256,
}

pub struct ObservedProposals<E: EthSpec> {
    finalized_slot: Slot,
    items: HashSet<ProposalKey>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedProposals<E> {
    fn default() -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashSet::new(),
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

        let newly_inserted = self.items.insert(ProposalKey {
            proposer: block.proposer_index(),
            slot: block.slot(),
            block_root,
        });

        Ok(!newly_inserted)
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
        self.items.retain(|key| key.slot > finalized_slot);
    }
}
