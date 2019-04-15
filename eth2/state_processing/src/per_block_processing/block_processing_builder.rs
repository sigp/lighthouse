use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use types::*;

pub struct BlockProcessingBuilder {
    pub state_builder: TestingBeaconStateBuilder,
    pub block_builder: TestingBeaconBlockBuilder,

    pub num_validators: usize,
}

impl BlockProcessingBuilder {
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

    pub fn set_slot(&mut self, slot: Slot, spec: &ChainSpec) {
        self.state_builder.teleport_to_slot(slot, &spec);
    }

    pub fn build_caches(&mut self, spec: &ChainSpec) {
        // Builds all caches; benches will not contain shuffling/committee building times.
        self.state_builder.build_caches(&spec).unwrap();
    }

    pub fn build(mut self, spec: &ChainSpec) -> (BeaconBlock, BeaconState) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        let proposer_index = state
            .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
            .unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_randao_reveal(&keypair.sk, &state.fork, spec);

        let block = self.block_builder.build(&keypair.sk, &state.fork, spec);

        (block, state)
    }
}
