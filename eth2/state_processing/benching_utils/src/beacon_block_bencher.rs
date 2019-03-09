use rayon::prelude::*;
use ssz::{SignedRoot, TreeHash};
use types::{
    attester_slashing::AttesterSlashingBuilder, proposer_slashing::ProposerSlashingBuilder, *,
};

pub struct BeaconBlockBencher {
    block: BeaconBlock,
}

impl BeaconBlockBencher {
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            block: BeaconBlock::genesis(spec.zero_hash, spec),
        }
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.block.slot = slot;
    }

    /// Signs the block.
    pub fn sign(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let proposal = self.block.proposal(spec);
        let message = proposal.signed_root();
        let epoch = self.block.slot.epoch(spec.slots_per_epoch);
        let domain = spec.get_domain(epoch, Domain::Proposal, fork);
        self.block.signature = Signature::new(&message, domain, sk);
    }

    /// Sets the randao to be a signature across the blocks epoch.
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

    /// Fills the block with as many attestations as possible.
    ///
    /// Note: this will not perform well when `jepoch_committees_count % slots_per_epoch != 0`
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
            if attestations_added == spec.max_attestations {
                break;
            }
            if state.slot >= slot + spec.slots_per_epoch {
                break;
            }

            for (committee, shard) in state.get_crosslink_committees_at_slot(slot, spec)? {
                committees.push((slot, committee.clone(), committee.clone(), *shard))
            }

            attestations_added += 1;
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
                committee_to_attestation(
                    state,
                    &committee,
                    signing_validators,
                    secret_keys,
                    *shard,
                    *slot,
                    &state.fork,
                    spec,
                )
            })
            .collect();

        self.block.body.attestations.append(&mut attestations);

        Ok(())
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

    ProposerSlashingBuilder::double_vote(validator_index, signer, spec)
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

    AttesterSlashingBuilder::double_vote(validator_indices, signer)
}

/// Convert some committee into a valid `Attestation`.
///
/// Note: `committee` must be the full committee for the attestation. `signing_validators` is a
/// list of validator indices that should sign the attestation.
fn committee_to_attestation(
    state: &BeaconState,
    committee: &[usize],
    signing_validators: &[usize],
    secret_keys: &[&SecretKey],
    shard: u64,
    slot: Slot,
    fork: &Fork,
    spec: &ChainSpec,
) -> Attestation {
    let current_epoch = state.current_epoch(spec);
    let previous_epoch = state.previous_epoch(spec);

    let is_previous_epoch =
        state.slot.epoch(spec.slots_per_epoch) != slot.epoch(spec.slots_per_epoch);

    let justified_epoch = if is_previous_epoch {
        state.previous_justified_epoch
    } else {
        state.justified_epoch
    };

    let epoch_boundary_root = if is_previous_epoch {
        *state
            .get_block_root(previous_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    } else {
        *state
            .get_block_root(current_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    };

    let justified_block_root = *state
        .get_block_root(justified_epoch.start_slot(spec.slots_per_epoch), spec)
        .unwrap();

    let data = AttestationData {
        slot,
        shard,
        beacon_block_root: *state.get_block_root(slot, spec).unwrap(),
        epoch_boundary_root,
        crosslink_data_root: Hash256::zero(),
        latest_crosslink: state.latest_crosslinks[shard as usize].clone(),
        justified_epoch,
        justified_block_root,
    };

    let mut aggregate_signature = AggregateSignature::new();
    let mut aggregation_bitfield = Bitfield::new();
    let mut custody_bitfield = Bitfield::new();

    let message = AttestationDataAndCustodyBit {
        data: data.clone(),
        custody_bit: false,
    }
    .hash_tree_root();

    let domain = spec.get_domain(
        data.slot.epoch(spec.slots_per_epoch),
        Domain::Attestation,
        fork,
    );

    for (i, validator_index) in committee.iter().enumerate() {
        custody_bitfield.set(i, false);

        if signing_validators
            .iter()
            .any(|&signer| *validator_index == signer)
        {
            aggregation_bitfield.set(i, true);
            let signature = Signature::new(&message, domain, secret_keys[*validator_index]);
            aggregate_signature.add(&signature);
        } else {
            aggregation_bitfield.set(i, false);
        }
    }

    Attestation {
        aggregation_bitfield,
        data,
        custody_bitfield,
        aggregate_signature,
    }
}
