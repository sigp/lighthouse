use tree_hash::SignedRoot;
use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use types::*;

pub struct BlockProcessingBuilder<T: EthSpec> {
    pub state_builder: TestingBeaconStateBuilder<T>,
    pub block_builder: TestingBeaconBlockBuilder<T>,
    pub num_validators: usize,
}

impl<T: EthSpec> BlockProcessingBuilder<T> {
    pub fn new(num_validators: usize, spec: &ChainSpec) -> Self {
        let state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
        let block_builder = TestingBeaconBlockBuilder::new(spec);

        Self {
            state_builder,
            block_builder,
            num_validators: 0,
        }
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.state_builder.teleport_to_slot(slot);
    }

    pub fn build_caches(&mut self, spec: &ChainSpec) {
        // Builds all caches; benches will not contain shuffling/committee building times.
        self.state_builder.build_caches(&spec).unwrap();
    }

    pub fn build(
        mut self,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (BeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(Hash256::from_slice(
                &state.latest_block_header.signed_root(),
            )),
        }

        let proposer_index = state
            .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
            .unwrap();
        let keypair = &keypairs[proposer_index];

        match randao_sk {
            Some(sk) => builder.set_randao_reveal(&sk, &state.fork, spec),
            None => builder.set_randao_reveal(&keypair.sk, &state.fork, spec),
        }

        let block = self.block_builder.build(&keypair.sk, &state.fork, spec);

        (block, state)
    }
}
