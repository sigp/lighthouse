use std::collections::HashSet;
use std::sync::Arc;
use types::{
    indexed_attestation::{IndexedAttestationBase, IndexedAttestationElectra},
    AggregateSignature, AttestationData, AttesterSlashing, AttesterSlashingBase,
    AttesterSlashingElectra, BeaconBlockHeader, ChainSpec, Checkpoint, Epoch, EthSpec, Hash256,
    IndexedAttestation, MainnetEthSpec, Signature, SignedBeaconBlockHeader, Slot,
};

pub type E = MainnetEthSpec;

pub fn indexed_att_electra(
    attesting_indices: impl AsRef<[u64]>,
    source_epoch: u64,
    target_epoch: u64,
    target_root: u64,
) -> IndexedAttestation<E> {
    IndexedAttestation::Electra(IndexedAttestationElectra {
        attesting_indices: attesting_indices.as_ref().to_vec().into(),
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::zero(),
            source: Checkpoint {
                epoch: Epoch::new(source_epoch),
                root: Hash256::from_low_u64_be(0),
            },
            target: Checkpoint {
                epoch: Epoch::new(target_epoch),
                root: Hash256::from_low_u64_be(target_root),
            },
        },
        signature: AggregateSignature::empty(),
    })
}

pub fn indexed_att(
    attesting_indices: impl AsRef<[u64]>,
    source_epoch: u64,
    target_epoch: u64,
    target_root: u64,
) -> IndexedAttestation<E> {
    IndexedAttestation::Base(IndexedAttestationBase {
        attesting_indices: attesting_indices.as_ref().to_vec().into(),
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::zero(),
            source: Checkpoint {
                epoch: Epoch::new(source_epoch),
                root: Hash256::from_low_u64_be(0),
            },
            target: Checkpoint {
                epoch: Epoch::new(target_epoch),
                root: Hash256::from_low_u64_be(target_root),
            },
        },
        signature: AggregateSignature::empty(),
    })
}

pub fn att_slashing(
    attestation_1: &IndexedAttestation<E>,
    attestation_2: &IndexedAttestation<E>,
) -> AttesterSlashing<E> {
    match (attestation_1, attestation_2) {
        (IndexedAttestation::Base(att1), IndexedAttestation::Base(att2)) => {
            AttesterSlashing::Base(AttesterSlashingBase {
                attestation_1: att1.clone(),
                attestation_2: att2.clone(),
            })
        }
        // A slashing involving an electra attestation type must return an electra AttesterSlashing type
        (_, _) => AttesterSlashing::Electra(AttesterSlashingElectra {
            attestation_1: attestation_1.clone().to_electra(),
            attestation_2: attestation_2.clone().to_electra(),
        }),
    }
}

pub fn hashset_intersection(
    attestation_1_indices: &[u64],
    attestation_2_indices: &[u64],
) -> HashSet<u64> {
    &attestation_1_indices
        .iter()
        .copied()
        .collect::<HashSet<u64>>()
        & &attestation_2_indices
            .iter()
            .copied()
            .collect::<HashSet<u64>>()
}

pub fn slashed_validators_from_slashings(slashings: &HashSet<AttesterSlashing<E>>) -> HashSet<u64> {
    slashings
        .iter()
        .flat_map(|slashing| {
            let att1 = slashing.attestation_1();
            let att2 = slashing.attestation_2();
            assert!(
                att1.is_double_vote(att2) || att1.is_surround_vote(att2),
                "invalid slashing: {:#?}",
                slashing
            );
            let attesting_indices_1 = att1.attesting_indices_to_vec();
            let attesting_indices_2 = att2.attesting_indices_to_vec();
            hashset_intersection(&attesting_indices_1, &attesting_indices_2)
        })
        .collect()
}

pub fn slashed_validators_from_attestations(
    attestations: &[IndexedAttestation<E>],
) -> HashSet<u64> {
    let mut slashed_validators = HashSet::new();
    // O(n^2) code, watch out.
    for att1 in attestations {
        for att2 in attestations {
            if att1 == att2 {
                continue;
            }

            if att1.is_double_vote(att2) || att1.is_surround_vote(att2) {
                let attesting_indices_1 = att1.attesting_indices_to_vec();
                let attesting_indices_2 = att2.attesting_indices_to_vec();
                slashed_validators.extend(hashset_intersection(
                    &attesting_indices_1,
                    &attesting_indices_2,
                ));
            }
        }
    }
    slashed_validators
}

pub fn block(slot: u64, proposer_index: u64, block_root: u64) -> SignedBeaconBlockHeader {
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot::new(slot),
            proposer_index,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: Hash256::from_low_u64_be(block_root),
        },
        signature: Signature::empty(),
    }
}

pub fn chain_spec() -> Arc<ChainSpec> {
    Arc::new(E::default_spec())
}
