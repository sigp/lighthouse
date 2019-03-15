use crate::{
    test_utils::{
        TestingAttestationBuilder, TestingAttesterSlashingBuilder, TestingDepositBuilder,
        TestingProposerSlashingBuilder, TestingTransferBuilder, TestingVoluntaryExitBuilder,
    },
    *,
};
use rayon::prelude::*;
use ssz::{SignedRoot, TreeHash};

/// Builds a beacon block to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingBeaconBlockBuilder {
    block: BeaconBlock,
}

impl TestingBeaconBlockBuilder {
    /// Create a new builder from genesis.
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            block: BeaconBlock::genesis(spec.zero_hash, spec),
        }
    }

    /// Set the slot of the block.
    pub fn set_slot(&mut self, slot: Slot) {
        self.block.slot = slot;
    }

    /// Signs the block.
    ///
    /// Modifying the block after signing may invalidate the signature.
    pub fn sign(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let proposal = self.block.proposal(spec);
        let message = proposal.signed_root();
        let epoch = self.block.slot.epoch(spec.slots_per_epoch);
        let domain = spec.get_domain(epoch, Domain::Proposal, fork);
        self.block.signature = Signature::new(&message, domain, sk);
    }

    /// Sets the randao to be a signature across the blocks epoch.
    ///
    /// Modifying the block's slot after signing may invalidate the signature.
    pub fn set_randao_reveal(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let epoch = self.block.slot.epoch(spec.slots_per_epoch);
        let message = epoch.hash_tree_root();
        let domain = spec.get_domain(epoch, Domain::Randao, fork);
        self.block.randao_reveal = Signature::new(&message, domain, sk);
    }

    /// Inserts a signed, valid `ProposerSlashing` for the validator.
    pub fn insert_proposer_slashing(
        &mut self,
        validator_index: u64,
        secret_key: &SecretKey,
        fork: &Fork,
        spec: &ChainSpec,
    ) {
        let proposer_slashing = build_proposer_slashing(validator_index, secret_key, fork, spec);
        self.block.body.proposer_slashings.push(proposer_slashing);
    }

    /// Inserts a signed, valid `AttesterSlashing` for each validator index in `validator_indices`.
    pub fn insert_attester_slashing(
        &mut self,
        validator_indices: &[u64],
        secret_keys: &[&SecretKey],
        fork: &Fork,
        spec: &ChainSpec,
    ) {
        let attester_slashing =
            build_double_vote_attester_slashing(validator_indices, secret_keys, fork, spec);
        self.block.body.attester_slashings.push(attester_slashing);
    }

    /// Fills the block with `MAX_ATTESTATIONS` attestations.
    ///
    /// It will first go and get each committee that is able to include an attestation in this
    /// block. If there are enough committees, it will produce an attestation for each. If there
    /// are _not_ enough committees, it will start splitting the committees in half until it
    /// achieves the target. It will then produce separate attestations for each split committee.
    ///
    /// Note: the signed messages of the split committees will be identical -- it would be possible
    /// to aggregate these split attestations.
    pub fn fill_with_attestations(
        &mut self,
        state: &BeaconState,
        secret_keys: &[&SecretKey],
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        let mut slot = self.block.slot - spec.min_attestation_inclusion_delay;
        let mut attestations_added = 0;

        // Stores the following (in order):
        //
        // - The slot of the committee.
        // - A list of all validators in the committee.
        // - A list of all validators in the committee that should sign the attestation.
        // - The shard of the committee.
        let mut committees: Vec<(Slot, Vec<usize>, Vec<usize>, u64)> = vec![];

        // Loop backwards through slots gathering each committee, until:
        //
        // - The slot is too old to be included in a block at this slot.
        // - The `MAX_ATTESTATIONS`.
        loop {
            if state.slot >= slot + spec.slots_per_epoch {
                break;
            }

            for (committee, shard) in state.get_crosslink_committees_at_slot(slot, spec)? {
                if attestations_added >= spec.max_attestations {
                    break;
                }

                committees.push((slot, committee.clone(), committee.clone(), *shard));

                attestations_added += 1;
            }

            slot -= 1;
        }

        // Loop through all the committees, splitting each one in half until we have
        // `MAX_ATTESTATIONS` committees.
        loop {
            if committees.len() >= spec.max_attestations as usize {
                break;
            }

            for index in 0..committees.len() {
                if committees.len() >= spec.max_attestations as usize {
                    break;
                }

                let (slot, committee, mut signing_validators, shard) = committees[index].clone();

                let new_signing_validators =
                    signing_validators.split_off(signing_validators.len() / 2);

                committees[index] = (slot, committee.clone(), signing_validators, shard);
                committees.push((slot, committee, new_signing_validators, shard));
            }
        }

        let mut attestations: Vec<Attestation> = committees
            .par_iter()
            .map(|(slot, committee, signing_validators, shard)| {
                let mut builder =
                    TestingAttestationBuilder::new(state, committee, *slot, *shard, spec);

                let signing_secret_keys: Vec<&SecretKey> = signing_validators
                    .iter()
                    .map(|validator_index| secret_keys[*validator_index])
                    .collect();
                builder.sign(signing_validators, &signing_secret_keys, &state.fork, spec);

                builder.build()
            })
            .collect();

        self.block.body.attestations.append(&mut attestations);

        Ok(())
    }

    /// Insert a `Valid` deposit into the state.
    pub fn insert_deposit(
        &mut self,
        amount: u64,
        index: u64,
        state: &BeaconState,
        spec: &ChainSpec,
    ) {
        let keypair = Keypair::random();

        let mut builder = TestingDepositBuilder::new(amount);
        builder.set_index(index);
        builder.sign(&keypair, state, spec);

        self.block.body.deposits.push(builder.build())
    }

    /// Insert a `Valid` exit into the state.
    pub fn insert_exit(
        &mut self,
        state: &BeaconState,
        validator_index: u64,
        secret_key: &SecretKey,
        spec: &ChainSpec,
    ) {
        let mut builder = TestingVoluntaryExitBuilder::new(
            state.slot.epoch(spec.slots_per_epoch),
            validator_index,
        );

        builder.sign(secret_key, &state.fork, spec);

        self.block.body.voluntary_exits.push(builder.build())
    }

    /// Insert a `Valid` transfer into the state.
    ///
    /// Note: this will set the validator to be withdrawable by directly modifying the state
    /// validator registry. This _may_ cause problems historic hashes, etc.
    pub fn insert_transfer(
        &mut self,
        state: &BeaconState,
        from: u64,
        to: u64,
        amount: u64,
        keypair: Keypair,
        spec: &ChainSpec,
    ) {
        let mut builder = TestingTransferBuilder::new(from, to, amount, state.slot);
        builder.sign(keypair, &state.fork, spec);

        self.block.body.transfers.push(builder.build())
    }

    /// Signs and returns the block, consuming the builder.
    pub fn build(mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) -> BeaconBlock {
        self.sign(sk, fork, spec);
        self.block
    }

    /// Returns the block, consuming the builder.
    pub fn build_without_signing(self) -> BeaconBlock {
        self.block
    }
}

/// Builds an `ProposerSlashing` for some `validator_index`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_proposer_slashing(
    validator_index: u64,
    secret_key: &SecretKey,
    fork: &Fork,
    spec: &ChainSpec,
) -> ProposerSlashing {
    let signer = |_validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let domain = spec.get_domain(epoch, domain, fork);
        Signature::new(message, domain, secret_key)
    };

    TestingProposerSlashingBuilder::double_vote(validator_index, signer, spec)
}

/// Builds an `AttesterSlashing` for some `validator_indices`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_double_vote_attester_slashing(
    validator_indices: &[u64],
    secret_keys: &[&SecretKey],
    fork: &Fork,
    spec: &ChainSpec,
) -> AttesterSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let key_index = validator_indices
            .iter()
            .position(|&i| i == validator_index)
            .expect("Unable to find attester slashing key");
        let domain = spec.get_domain(epoch, domain, fork);
        Signature::new(message, domain, secret_keys[key_index])
    };

    TestingAttesterSlashingBuilder::double_vote(validator_indices, signer)
}
