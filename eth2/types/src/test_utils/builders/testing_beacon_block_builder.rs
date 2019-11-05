use crate::{
    test_utils::{
        TestingAttestationBuilder, TestingAttesterSlashingBuilder, TestingDepositBuilder,
        TestingProposerSlashingBuilder, TestingTransferBuilder, TestingVoluntaryExitBuilder,
    },
    typenum::U4294967296,
    *,
};
use int_to_bytes::int_to_bytes32;
use merkle_proof::MerkleTree;
use rayon::prelude::*;
use tree_hash::{SignedRoot, TreeHash};

/// Builds a beacon block to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingBeaconBlockBuilder<T: EthSpec> {
    pub block: BeaconBlock<T>,
}

/// Enum used for passing test options to builder
#[derive(PartialEq)]
pub enum DepositTestTask {
    Valid,
    BadPubKey,
    BadSig,
    InvalidPubKey,
    NoReset,
}

/// Enum used for passing test options to builder
pub enum ExitTestTask {
    AlreadyInitiated,
    AlreadyExited,
    BadSignature,
    FutureEpoch,
    NotActive,
    Valid,
    ValidatorUnknown,
}

#[derive(PartialEq)]
/// Enum used for passing test options to builder
pub enum AttestationTestTask {
    Valid,
    BadParentCrosslinkStartEpoch,
    BadParentCrosslinkEndEpoch,
    BadParentCrosslinkHash,
    NoCommiteeForShard,
    WrongJustifiedCheckpoint,
    BadTargetTooLow,
    BadTargetTooHigh,
    BadShard,
    BadParentCrosslinkDataRoot,
    BadIndexedAttestationBadSignature,
    CustodyBitfieldNotSubset,
    CustodyBitfieldHasSetBits,
    BadCustodyBitfieldLen,
    BadAggregationBitfieldLen,
    BadSignature,
    ValidatorUnknown,
    IncludedTooEarly,
    IncludedTooLate,
    BadTargetEpoch,
}

#[derive(PartialEq)]
/// Enum used for passing test options to builder
pub enum AttesterSlashingTestTask {
    Valid,
    NotSlashable,
    IndexedAttestation1Invalid,
    IndexedAttestation2Invalid,
}

/// Enum used for passing test options to builder
#[derive(PartialEq)]
pub enum ProposerSlashingTestTask {
    Valid,
    ProposerUnknown,
    ProposalEpochMismatch,
    ProposalsIdentical,
    ProposerNotSlashable,
    BadProposal1Signature,
    BadProposal2Signature,
}

impl<T: EthSpec> TestingBeaconBlockBuilder<T> {
    /// Create a new builder from genesis.
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            block: BeaconBlock::empty(spec),
        }
    }

    /// Set the previous block root
    pub fn set_parent_root(&mut self, root: Hash256) {
        self.block.parent_root = root;
    }

    /// Set the slot of the block.
    pub fn set_slot(&mut self, slot: Slot) {
        self.block.slot = slot;
    }

    /// Signs the block.
    ///
    /// Modifying the block after signing may invalidate the signature.
    pub fn sign(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let message = self.block.signed_root();
        let epoch = self.block.slot.epoch(T::slots_per_epoch());
        let domain = spec.get_domain(epoch, Domain::BeaconProposer, fork);
        self.block.signature = Signature::new(&message, domain, sk);
    }

    /// Sets the randao to be a signature across the blocks epoch.
    ///
    /// Modifying the block's slot after signing may invalidate the signature.
    pub fn set_randao_reveal(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let epoch = self.block.slot.epoch(T::slots_per_epoch());
        let message = epoch.tree_hash_root();
        let domain = spec.get_domain(epoch, Domain::Randao, fork);
        self.block.body.randao_reveal = Signature::new(&message, domain, sk);
    }

    /// Has the randao reveal been set?
    pub fn randao_reveal_not_set(&mut self) -> bool {
        self.block.body.randao_reveal.is_empty()
    }

    /// Inserts a signed, valid `ProposerSlashing` for the validator.
    pub fn insert_proposer_slashing(
        &mut self,
        test_task: &ProposerSlashingTestTask,
        validator_index: u64,
        secret_key: &SecretKey,
        fork: &Fork,
        spec: &ChainSpec,
    ) {
        let proposer_slashing =
            build_proposer_slashing::<T>(test_task, validator_index, secret_key, fork, spec);
        self.block
            .body
            .proposer_slashings
            .push(proposer_slashing)
            .unwrap();
    }

    /// Inserts a signed, valid `AttesterSlashing` for each validator index in `validator_indices`.
    pub fn insert_attester_slashing(
        &mut self,
        test_task: &AttesterSlashingTestTask,
        validator_indices: &[u64],
        secret_keys: &[&SecretKey],
        fork: &Fork,
        spec: &ChainSpec,
    ) {
        let attester_slashing = build_double_vote_attester_slashing(
            test_task,
            validator_indices,
            secret_keys,
            fork,
            spec,
        );
        let _ = self.block.body.attester_slashings.push(attester_slashing);
    }

    /// Fills the block with `num_attestations` attestations.
    ///
    /// It will first go and get each committee that is able to include an attestation in this
    /// block. If there _are_ enough committees, it will produce an attestation for each. If there
    /// _are not_ enough committees, it will start splitting the committees in half until it
    /// achieves the target. It will then produce separate attestations for each split committee.
    ///
    /// Note: the signed messages of the split committees will be identical -- it would be possible
    /// to aggregate these split attestations.
    pub fn insert_attestations(
        &mut self,
        test_task: &AttestationTestTask,
        state: &BeaconState<T>,
        secret_keys: &[&SecretKey],
        num_attestations: usize,
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

        if slot < T::slots_per_epoch() {
            panic!("slot is too low, will get stuck in loop")
        }

        // Loop backwards through slots gathering each committee, until:
        //
        // - The slot is too old to be included in a block at this slot.
        // - The `MAX_ATTESTATIONS`.
        loop {
            if state.slot >= slot + T::slots_per_epoch() {
                break;
            }

            for crosslink_committee in state.get_crosslink_committees_at_slot(slot)? {
                if attestations_added >= num_attestations {
                    break;
                }

                committees.push((
                    slot,
                    crosslink_committee.committee.to_vec(),
                    crosslink_committee.committee.to_vec(),
                    crosslink_committee.shard,
                ));

                attestations_added += 1;
            }

            slot -= 1;
        }

        // Loop through all the committees, splitting each one in half until we have
        // `MAX_ATTESTATIONS` committees.
        loop {
            if committees.len() >= num_attestations as usize {
                break;
            }

            for index in 0..committees.len() {
                if committees.len() >= num_attestations as usize {
                    break;
                }

                let (slot, committee, mut signing_validators, shard) = committees[index].clone();

                let new_signing_validators =
                    signing_validators.split_off(signing_validators.len() / 2);

                committees[index] = (slot, committee.clone(), signing_validators, shard);
                committees.push((slot, committee, new_signing_validators, shard));
            }
        }

        let attestations: Vec<_> = committees
            .par_iter()
            .map(|(slot, committee, signing_validators, shard)| {
                let mut builder = TestingAttestationBuilder::new(
                    test_task, state, committee, *slot, *shard, spec,
                );

                let signing_secret_keys: Vec<&SecretKey> = signing_validators
                    .iter()
                    .map(|validator_index| secret_keys[*validator_index])
                    .collect();
                builder.sign(
                    test_task,
                    signing_validators,
                    &signing_secret_keys,
                    &state.fork,
                    spec,
                    false,
                );

                builder.build()
            })
            .collect();

        for attestation in attestations {
            self.block.body.attestations.push(attestation).unwrap();
        }

        Ok(())
    }

    /// Insert a `Valid` deposit into the state.
    pub fn insert_deposits(
        &mut self,
        amount: u64,
        test_task: DepositTestTask,
        // TODO: deal with the fact deposits no longer have explicit indices
        _index: u64,
        num_deposits: u64,
        state: &mut BeaconState<T>,
        spec: &ChainSpec,
    ) {
        // Vector containing deposits' data
        let mut datas = vec![];
        for _ in 0..num_deposits {
            let keypair = Keypair::random();

            let mut builder = TestingDepositBuilder::new(keypair.pk.clone(), amount);
            builder.sign(
                &test_task,
                &keypair,
                state.slot.epoch(T::slots_per_epoch()),
                &state.fork,
                spec,
            );
            datas.push(builder.build().data);
        }

        // Vector containing all leaves
        let leaves = datas
            .iter()
            .map(|data| Hash256::from_slice(&data.tree_hash_root()))
            .collect::<Vec<_>>();

        // Building a VarList from leaves
        let deposit_data_list = VariableList::<_, U4294967296>::from(leaves.clone());

        // Setting the deposit_root to be the tree_hash_root of the VarList
        state.eth1_data.deposit_root = Hash256::from_slice(&deposit_data_list.tree_hash_root());

        // Building the merkle tree used for generating proofs
        let tree = MerkleTree::create(&leaves[..], spec.deposit_contract_tree_depth as usize);

        // Building proofs
        let mut proofs = vec![];
        for i in 0..leaves.len() {
            let (_, mut proof) = tree.generate_proof(i, spec.deposit_contract_tree_depth as usize);
            proof.push(Hash256::from_slice(&int_to_bytes32(leaves.len() as u64)));
            proofs.push(proof);
        }

        // Building deposits
        let deposits = datas
            .into_par_iter()
            .zip(proofs.into_par_iter())
            .map(|(data, proof)| (data, proof.into()))
            .map(|(data, proof)| Deposit { proof, data })
            .collect::<Vec<_>>();

        // Pushing deposits to block body
        for deposit in deposits {
            let _ = self.block.body.deposits.push(deposit);
        }

        // Manually setting the deposit_count to process deposits
        // This is for test purposes only
        if test_task == DepositTestTask::NoReset {
            state.eth1_data.deposit_count += num_deposits;
        } else {
            state.eth1_deposit_index = 0;
            state.eth1_data.deposit_count = num_deposits;
        }
    }

    /// Insert a `Valid` exit into the state.
    pub fn insert_exit(
        &mut self,
        test_task: &ExitTestTask,
        state: &mut BeaconState<T>,
        mut validator_index: u64,
        secret_key: &SecretKey,
        spec: &ChainSpec,
    ) {
        let sk = &mut secret_key.clone();
        let mut exit_epoch = state.slot.epoch(T::slots_per_epoch());

        match test_task {
            ExitTestTask::BadSignature => *sk = SecretKey::random(),
            ExitTestTask::ValidatorUnknown => validator_index = 4242,
            ExitTestTask::AlreadyExited => {
                state.validators[validator_index as usize].exit_epoch = Epoch::from(314_159 as u64)
            }
            ExitTestTask::NotActive => {
                state.validators[validator_index as usize].activation_epoch =
                    Epoch::from(314_159 as u64)
            }
            ExitTestTask::FutureEpoch => exit_epoch = spec.far_future_epoch,
            _ => (),
        }

        let mut builder = TestingVoluntaryExitBuilder::new(exit_epoch, validator_index);

        builder.sign(sk, &state.fork, spec);

        self.block
            .body
            .voluntary_exits
            .push(builder.build())
            .unwrap();
    }

    /// Insert a `Valid` transfer into the state.
    ///
    /// Note: this will set the validator to be withdrawable by directly modifying the state
    /// validator registry. This _may_ cause problems historic hashes, etc.
    pub fn insert_transfer(
        &mut self,
        state: &BeaconState<T>,
        from: u64,
        to: u64,
        amount: u64,
        keypair: Keypair,
        spec: &ChainSpec,
    ) {
        let mut builder = TestingTransferBuilder::new(from, to, amount, state.slot);
        builder.sign::<T>(keypair, &state.fork, spec);

        self.block.body.transfers.push(builder.build()).unwrap()
    }

    /// Signs and returns the block, consuming the builder.
    pub fn build(mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) -> BeaconBlock<T> {
        self.sign(sk, fork, spec);
        self.block
    }

    /// Returns the block, consuming the builder.
    pub fn build_without_signing(self) -> BeaconBlock<T> {
        self.block
    }
}

/// Builds an `ProposerSlashing` for some `validator_index`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_proposer_slashing<T: EthSpec>(
    test_task: &ProposerSlashingTestTask,
    validator_index: u64,
    secret_key: &SecretKey,
    fork: &Fork,
    spec: &ChainSpec,
) -> ProposerSlashing {
    let signer = |_validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let domain = spec.get_domain(epoch, domain, fork);
        Signature::new(message, domain, secret_key)
    };

    TestingProposerSlashingBuilder::double_vote::<T, _>(test_task, validator_index, signer)
}

/// Builds an `AttesterSlashing` for some `validator_indices`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_double_vote_attester_slashing<T: EthSpec>(
    test_task: &AttesterSlashingTestTask,
    validator_indices: &[u64],
    secret_keys: &[&SecretKey],
    fork: &Fork,
    spec: &ChainSpec,
) -> AttesterSlashing<T> {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let key_index = validator_indices
            .iter()
            .position(|&i| i == validator_index)
            .expect("Unable to find attester slashing key");
        let domain = spec.get_domain(epoch, domain, fork);
        Signature::new(message, domain, secret_keys[key_index])
    };

    TestingAttesterSlashingBuilder::double_vote(test_task, validator_indices, signer)
}
