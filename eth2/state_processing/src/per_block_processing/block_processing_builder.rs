use std::convert::TryInto;
use tree_hash::TreeHash;
use types::test_utils::{
    AttestationTestTask, AttesterSlashingTestTask, DepositTestTask, ExitTestTask,
    ProposerSlashingTestTask, TestingBeaconBlockBuilder, TestingBeaconStateBuilder,
};
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

    pub fn build_with_n_deposits(
        mut self,
        num_deposits: u64,
        test_task: DepositTestTask,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (mut state, keypairs) = self.state_builder.build();

        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }

        self.block_builder.insert_deposits(
            spec.max_effective_balance,
            test_task,
            1,
            num_deposits,
            &mut state,
            spec,
        );

        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }

    pub fn build_with_n_exits(
        mut self,
        num_exits: usize,
        test_task: ExitTestTask,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (mut state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }
        match test_task {
            ExitTestTask::AlreadyInitiated => {
                for _ in 0..2 {
                    self.block_builder.insert_exit(
                        test_task,
                        &mut state,
                        (0 as usize).try_into().unwrap(),
                        &keypairs[0].sk,
                        spec,
                    )
                }
            }
            _ => {
                for (i, keypair) in keypairs.iter().take(num_exits).enumerate() {
                    self.block_builder.insert_exit(
                        test_task,
                        &mut state,
                        (i as usize).try_into().unwrap(),
                        &keypair.sk,
                        spec,
                    );
                }
            }
        }

        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }

    pub fn build_with_n_attestations(
        mut self,
        test_task: AttestationTestTask,
        num_attestations: u64,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }

        let all_secret_keys: Vec<&SecretKey> = keypairs.iter().map(|keypair| &keypair.sk).collect();
        self.block_builder
            .insert_attestations(
                test_task,
                &state,
                &all_secret_keys,
                num_attestations as usize,
                spec,
            )
            .unwrap();
        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }

    pub fn build_with_attester_slashing(
        mut self,
        test_task: AttesterSlashingTestTask,
        num_attester_slashings: u64,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }

        let mut validator_indices = vec![];
        let mut secret_keys = vec![];
        for i in 0..num_attester_slashings {
            validator_indices.push(i);
            secret_keys.push(&keypairs[i as usize].sk);
        }

        for _ in 0..num_attester_slashings {
            self.block_builder.insert_attester_slashing(
                test_task,
                &validator_indices,
                &secret_keys,
                &state.fork,
                state.genesis_validators_root,
                spec,
            );
        }
        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }

    pub fn build_with_proposer_slashing(
        mut self,
        test_task: ProposerSlashingTestTask,
        num_proposer_slashings: u64,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }

        for i in 0..num_proposer_slashings {
            let validator_indices = i;
            let secret_keys = &keypairs[i as usize].sk;
            self.block_builder.insert_proposer_slashing(
                test_task,
                validator_indices,
                &secret_keys,
                &state.fork,
                state.genesis_validators_root,
                spec,
            );
        }
        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }

    pub fn build(
        mut self,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        match previous_block_root {
            Some(root) => builder.set_parent_root(root),
            None => builder.set_parent_root(state.latest_block_header.tree_hash_root()),
        }

        let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_proposer_index(proposer_index as u64);

        match randao_sk {
            Some(sk) => {
                builder.set_randao_reveal(&sk, &state.fork, state.genesis_validators_root, spec)
            }
            None => builder.set_randao_reveal(
                &keypair.sk,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        }

        let block = self.block_builder.build(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );

        (block, state)
    }
}
