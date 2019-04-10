use log::info;
use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use types::*;

pub struct BlockProcessingBuilder {
    pub state_builder: TestingBeaconStateBuilder,
    pub block_builder: TestingBeaconBlockBuilder,

    pub num_validators: usize,
    pub num_proposer_slashings: usize,
    pub num_attester_slashings: usize,
    pub num_indices_per_slashable_vote: usize,
    pub num_attestations: usize,
    pub num_deposits: usize,
    pub num_exits: usize,
    pub num_transfers: usize,
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
            num_proposer_slashings: 0,
            num_attester_slashings: 0,
            num_indices_per_slashable_vote: spec.max_indices_per_slashable_vote as usize,
            num_attestations: 0,
            num_deposits: 0,
            num_exits: 0,
            num_transfers: 0,
        }
    }

    pub fn maximize_block_operations(&mut self, spec: &ChainSpec) {
        self.num_proposer_slashings = spec.max_proposer_slashings as usize;
        self.num_attester_slashings = spec.max_attester_slashings as usize;
        self.num_indices_per_slashable_vote = spec.max_indices_per_slashable_vote as usize;
        self.num_attestations = spec.max_attestations as usize;
        self.num_deposits = spec.max_deposits as usize;
        self.num_exits = spec.max_voluntary_exits as usize;
        self.num_transfers = spec.max_transfers as usize;
    }

    pub fn set_slot(&mut self, slot: Slot, spec: &ChainSpec) {
        self.state_builder.teleport_to_slot(slot, &spec);
    }

    pub fn build_caches(&mut self, spec: &ChainSpec) {
        // Builds all caches; benches will not contain shuffling/committee building times.
        self.state_builder.build_caches(&spec).unwrap();
    }

    pub fn build(mut self, spec: &ChainSpec) -> (BeaconBlock, BeaconState) {
        let (mut state, keypairs) = self.state_builder.build();
        let builder = &mut self.block_builder;

        builder.set_slot(state.slot);

        let proposer_index = state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec).unwrap();
        let keypair = &keypairs[proposer_index];

        builder.set_randao_reveal(&keypair.sk, &state.fork, spec);

        // Used as a stream of validator indices for use in slashings, exits, etc.
        let mut validators_iter = (0..keypairs.len() as u64).into_iter();

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

            for _ in 0..self.num_indices_per_slashable_vote {
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
                state.deposit_index + (i as u64),
                &state,
                spec,
            );
        }
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
            state.validator_registry[validator_index as usize].withdrawable_epoch =
                state.previous_epoch(spec);

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

        let mut block = self.block_builder.build(&keypair.sk, &state.fork, spec);

        // Set the eth1 data to be different from the state.
        block.body.eth1_data.block_hash = Hash256::from_slice(&vec![42; 32]);

        (block, state)
    }
}
