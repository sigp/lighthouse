use crate::{BeaconState, ChainSpec, Hash256};

pub enum Error {
    UnableToDetermineProducer,
}

impl BeaconState {
    pub fn per_slot_processing(
        &mut self,
        previous_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        self.slot += 1;

        let block_proposer = self
            .get_beacon_proposer_index(self.slot, spec)
            .ok_or_else(|| Error::UnableToDetermineProducer)?;

        self.validator_registry[block_proposer].proposer_slots += 1;
        self.latest_randao_mixes[(self.slot % spec.latest_randao_mixes_length) as usize] =
            self.latest_randao_mixes[((self.slot - 1) % spec.latest_randao_mixes_length) as usize];

        // Block roots.
        self.latest_block_roots[((self.slot - 1) % spec.latest_block_roots_length) as usize] =
            previous_block_root;

        if self.slot % spec.latest_block_roots_length == 0 {
            let root = merkle_root(&self.latest_block_roots[..]);
            self.batched_block_roots.push(root);
        }
        Ok(())
    }

    pub fn get_beacon_proposer_index(&self, slot: u64, spec: &ChainSpec) -> Option<usize> {
        // TODO: this is a stub; implement it properly.
        //
        // https://github.com/sigp/lighthouse/pull/148/files
        let validator_count = self.validator_registry.len();
        Some((slot as usize) % validator_count)
    }
}

fn merkle_root(_input: &[Hash256]) -> Hash256 {
    Hash256::zero()
}
