use tree_hash::TreeHash;
use types::test_utils::{
    AttestationTestTask, AttesterSlashingTestTask, DepositTestTask, ProposerSlashingTestTask,
    TestingAttestationDataBuilder, TestingBeaconBlockBuilder, TestingBeaconStateBuilder,
};
use types::*;

pub struct BlockProcessingBuilder<'a, T: EthSpec> {
    pub state: BeaconState<T>,
    pub keypairs: Vec<Keypair>,
    pub block_builder: TestingBeaconBlockBuilder<T>,
    pub spec: &'a ChainSpec,
}

impl<'a, T: EthSpec> BlockProcessingBuilder<'a, T> {
    pub fn new(num_validators: usize, state_slot: Slot, spec: &'a ChainSpec) -> Self {
        let mut state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
        state_builder.teleport_to_slot(state_slot);
        let (state, keypairs) = state_builder.build();
        let block_builder = TestingBeaconBlockBuilder::new(spec);

        Self {
            state,
            keypairs,
            block_builder,
            spec,
        }
    }

    pub fn build_caches(mut self) -> Self {
        self.state
            .build_all_caches(self.spec)
            .expect("caches build OK");
        self
    }

    pub fn build_with_n_deposits(
        mut self,
        num_deposits: u64,
        test_task: DepositTestTask,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (mut state, keypairs) = (self.state, self.keypairs);

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

    /// Insert a signed `VoluntaryIndex` for the given validator at the given `exit_epoch`.
    pub fn insert_exit(mut self, validator_index: u64, exit_epoch: Epoch) -> Self {
        self.block_builder.insert_exit(
            validator_index,
            exit_epoch,
            &self.keypairs[validator_index as usize].sk,
            &self.state,
            self.spec,
        );
        self
    }

    /// Insert an attestation for the given slot and index.
    ///
    /// It will be signed by all validators for which `should_sign` returns `true`
    /// when called with `(committee_position, validator_index)`.
    // TODO: consider using this pattern to replace the TestingAttestationBuilder
    pub fn insert_attestation(
        mut self,
        slot: Slot,
        index: u64,
        mut should_sign: impl FnMut(usize, usize) -> bool,
    ) -> Self {
        let committee = self.state.get_beacon_committee(slot, index).unwrap();
        let data = TestingAttestationDataBuilder::new(
            AttestationTestTask::Valid,
            &self.state,
            index,
            slot,
            self.spec,
        )
        .build();

        let mut attestation = Attestation {
            aggregation_bits: BitList::with_capacity(committee.committee.len()).unwrap(),
            data,
            signature: AggregateSignature::new(),
        };

        for (i, &validator_index) in committee.committee.into_iter().enumerate() {
            if should_sign(i, validator_index) {
                attestation
                    .sign(
                        &self.keypairs[validator_index].sk,
                        i,
                        &self.state.fork,
                        self.state.genesis_validators_root,
                        self.spec,
                    )
                    .unwrap();
            }
        }

        self.block_builder
            .block
            .body
            .attestations
            .push(attestation)
            .unwrap();

        self
    }

    /// Apply a mutation to the `BeaconBlock` before signing.
    pub fn modify(mut self, f: impl FnOnce(&mut BeaconBlock<T>)) -> Self {
        self.block_builder.modify(f);
        self
    }

    pub fn build_with_n_attestations(
        mut self,
        test_task: AttestationTestTask,
        num_attestations: u64,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = (self.state, self.keypairs);
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
        let (state, keypairs) = (self.state, self.keypairs);
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
        let (state, keypairs) = (self.state, self.keypairs);
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

    // NOTE: could remove optional args
    // NOTE: could return keypairs as well
    pub fn build(
        mut self,
        randao_sk: Option<SecretKey>,
        previous_block_root: Option<Hash256>,
    ) -> (SignedBeaconBlock<T>, BeaconState<T>) {
        let (state, keypairs) = (self.state, self.keypairs);
        let spec = self.spec;
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
