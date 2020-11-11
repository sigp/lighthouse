use types::{
    AggregateSignature, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
    BeaconBlockHeader, BitList, Checkpoint, Deposit, DepositData, Epoch, EthSpec, FixedVector,
    Hash256, IndexedAttestation, ProposerSlashing, PublicKeyBytes, Signature, SignatureBytes,
    SignedBeaconBlockHeader, SignedVoluntaryExit, Slot, Unsigned, VariableList, VoluntaryExit,
};

/// We spice up some of the values, based on a given `seed` parameter.
pub fn get_block<E: EthSpec>(seed: u64) -> BeaconBlock<E> {
    let spec = &mut E::default_spec();
    spec.genesis_slot = Slot::new(seed);

    let header = BeaconBlockHeader {
        slot: Slot::new(seed),
        proposer_index: 0,
        parent_root: Hash256::from_low_u64_be(222 * seed),
        state_root: Hash256::from_low_u64_be(333 * seed),
        body_root: Hash256::from_low_u64_be(444 * seed),
    };

    let signed_header = SignedBeaconBlockHeader {
        message: header,
        signature: Signature::empty(),
    };
    let indexed_attestation: IndexedAttestation<E> = IndexedAttestation {
        attesting_indices: VariableList::new(vec![
            0 as u64;
            E::MaxValidatorsPerCommittee::to_usize()
        ])
        .unwrap(),
        data: AttestationData::default(),
        signature: AggregateSignature::empty(),
    };

    let deposit_data = DepositData {
        pubkey: PublicKeyBytes::empty(),
        withdrawal_credentials: Hash256::from_low_u64_be(555 * seed),
        amount: 0,
        signature: SignatureBytes::empty(),
    };
    let proposer_slashing = ProposerSlashing {
        signed_header_1: signed_header.clone(),
        signed_header_2: signed_header,
    };

    let attester_slashing = AttesterSlashing {
        attestation_1: indexed_attestation.clone(),
        attestation_2: indexed_attestation,
    };

    let attestation: Attestation<E> = Attestation {
        aggregation_bits: BitList::with_capacity(E::MaxValidatorsPerCommittee::to_usize()).unwrap(),
        data: AttestationData::default(),
        signature: AggregateSignature::empty(),
    };

    let deposit = Deposit {
        proof: FixedVector::from_elem(Hash256::from_low_u64_be(666 * seed)),
        data: deposit_data,
    };

    let voluntary_exit = VoluntaryExit {
        epoch: Epoch::new(1),
        validator_index: 1,
    };

    let signed_voluntary_exit = SignedVoluntaryExit {
        message: voluntary_exit,
        signature: Signature::empty(),
    };

    let mut block: BeaconBlock<E> = BeaconBlock::empty(spec);
    for _ in 0..E::MaxProposerSlashings::to_usize() {
        block
            .body
            .proposer_slashings
            .push(proposer_slashing.clone())
            .unwrap();
    }
    for _ in 0..E::MaxDeposits::to_usize() {
        block.body.deposits.push(deposit.clone()).unwrap();
    }
    for _ in 0..E::MaxVoluntaryExits::to_usize() {
        block
            .body
            .voluntary_exits
            .push(signed_voluntary_exit.clone())
            .unwrap();
    }
    for _ in 0..E::MaxAttesterSlashings::to_usize() {
        block
            .body
            .attester_slashings
            .push(attester_slashing.clone())
            .unwrap();
    }

    for _ in 0..E::MaxAttestations::to_usize() {
        block.body.attestations.push(attestation.clone()).unwrap();
    }
    block
}

pub fn get_attestation<E: EthSpec>(seed: u64) -> AttestationData {
    let slot = Slot::from(seed);
    let epoch = slot.epoch(E::slots_per_epoch());

    let build_checkpoint = |epoch_u64: u64| -> Checkpoint {
        Checkpoint {
            epoch: Epoch::new(epoch_u64),
            root: Hash256::from_low_u64_be(333 * seed),
        }
    };

    let source = build_checkpoint(epoch.as_u64().saturating_sub(2));
    let target = build_checkpoint(epoch.as_u64());

    let index = 0xc137u64;

    AttestationData {
        slot,
        index,
        beacon_block_root: Hash256::from_low_u64_be(666 * seed),
        source,
        target,
    }
}
