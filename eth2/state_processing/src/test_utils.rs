use log::info;
use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use types::{EthSpec, *};

pub struct BlockBuilder<T: EthSpec> {
    pub state_builder: TestingBeaconStateBuilder<T>,
    pub block_builder: TestingBeaconBlockBuilder<T>,

    pub num_validators: usize,
    pub num_proposer_slashings: usize,
    pub num_attester_slashings: usize,
    pub num_attestations: usize,
    pub num_deposits: usize,
    pub num_exits: usize,
    pub num_transfers: usize,
}

impl<T: EthSpec> BlockBuilder<T> {
    pub fn new(num_validators: usize, spec: &ChainSpec) -> Self {
        let state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
        let block_builder = TestingBeaconBlockBuilder::new(spec);

        Self {
            state_builder,
            block_builder,
            num_validators: 0,
            num_proposer_slashings: 0,
            num_attester_slashings: 0,
            num_attestations: 0,
            num_deposits: 0,
            num_exits: 0,
            num_transfers: 0,
        }
    }

    pub fn maximize_block_operations(&mut self) {
        self.num_proposer_slashings = T::MaxProposerSlashings::to_usize();
        self.num_attester_slashings = T::MaxAttesterSlashings::to_usize();
        self.num_attestations = T::MaxAttestations::to_usize();
        self.num_deposits = T::MaxDeposits::to_usize();
        self.num_exits = T::MaxVoluntaryExits::to_usize();
        self.num_transfers = T::MaxTransfers::to_usize();
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.state_builder.teleport_to_slot(slot);
    }

    pub fn build_caches(&mut self, spec: &ChainSpec) {
        // Builds all caches; benches will not contain shuffling/committee building times.
        self.state_builder.build_caches(&spec).unwrap();
    }

    pub fn build(mut self, spec: &ChainSpec) -> (BeaconBlock<T>, BeaconState<T>) {
        let (mut state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        let proposer_index = state
            .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
            .unwrap();

        let proposer_keypair = &keypairs[proposer_index];

        builder.set_randao_reveal(&proposer_keypair.sk, &state.fork, spec);

        let parent_root = state.latest_block_header.canonical_root();
        builder.set_parent_root(parent_root);

        // Used as a stream of validator indices for use in slashings, exits, etc.
        let mut validators_iter = 0..keypairs.len() as u64;

        // Insert `ProposerSlashing` objects.
        for _ in 0..self.num_proposer_slashings {
            let validator_index = validators_iter.next().expect("Insufficient validators.");

            builder.insert_proposer_slashing(
                validator_index,
                &keypairs[validator_index as usize].sk,
                &state.fork,
                spec,
            );
        }
        info!(
            "Inserted {} proposer slashings.",
            builder.block.body.proposer_slashings.len()
        );

        // Insert `AttesterSlashing` objects
        for _ in 0..self.num_attester_slashings {
            let mut attesters: Vec<u64> = vec![];
            let mut secret_keys: Vec<&SecretKey> = vec![];

            const NUM_SLASHED_INDICES: usize = 12;

            for _ in 0..NUM_SLASHED_INDICES {
                let validator_index = validators_iter.next().expect("Insufficient validators.");

                attesters.push(validator_index);
                secret_keys.push(&keypairs[validator_index as usize].sk);
            }

            builder.insert_attester_slashing(&attesters, &secret_keys, &state.fork, spec);
        }
        info!(
            "Inserted {} attester slashings.",
            builder.block.body.attester_slashings.len()
        );

        // Insert `Attestation` objects.
        let all_secret_keys: Vec<&SecretKey> = keypairs.iter().map(|keypair| &keypair.sk).collect();
        builder
            .insert_attestations(
                &state,
                &all_secret_keys,
                self.num_attestations as usize,
                spec,
            )
            .unwrap();
        info!(
            "Inserted {} attestations.",
            builder.block.body.attestations.len()
        );

        // Insert `Deposit` objects.
        for i in 0..self.num_deposits {
            builder.insert_deposit(
                32_000_000_000,
                state.eth1_data.deposit_count + (i as u64),
                &state,
                spec,
            );
        }
        state.eth1_data.deposit_count += self.num_deposits as u64;
        info!("Inserted {} deposits.", builder.block.body.deposits.len());

        // Insert the maximum possible number of `Exit` objects.
        for _ in 0..self.num_exits {
            let validator_index = validators_iter.next().expect("Insufficient validators.");

            builder.insert_exit(
                &state,
                validator_index,
                &keypairs[validator_index as usize].sk,
                spec,
            );
        }
        info!(
            "Inserted {} exits.",
            builder.block.body.voluntary_exits.len()
        );

        // Insert the maximum possible number of `Transfer` objects.
        for _ in 0..self.num_transfers {
            let validator_index = validators_iter.next().expect("Insufficient validators.");

            // Manually set the validator to be withdrawn.
            state.validators[validator_index as usize].withdrawable_epoch = state.previous_epoch();

            builder.insert_transfer(
                &state,
                validator_index,
                validator_index,
                1,
                keypairs[validator_index as usize].clone(),
                spec,
            );
        }
        info!("Inserted {} transfers.", builder.block.body.transfers.len());

        // Set the eth1 data to be different from the state.
        self.block_builder.block.body.eth1_data.block_hash = Hash256::from_slice(&[42; 32]);

        let block = self
            .block_builder
            .build(&proposer_keypair.sk, &state.fork, spec);

        (block, state)
    }
}
