use itertools::Itertools;
use std::collections::HashMap;
use types::{
    AggregateSignature, Attestation, AttestationData, BeaconState, BitList, Checkpoint, Epoch,
    EthSpec, Hash256, IndexedAttestation, Slot,
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CheckpointKey {
    pub source: Checkpoint,
    pub target_epoch: Epoch,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CompactAttestationData {
    pub slot: Slot,
    pub index: u64,
    pub beacon_block_root: Hash256,
    pub target_root: Hash256,
}

#[derive(Debug, PartialEq)]
pub struct CompactIndexedAttestation<T: EthSpec> {
    pub attesting_indices: Vec<u64>,
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}

#[derive(Debug, Clone)]
pub struct AttestationRef<'a, T: EthSpec> {
    pub checkpoint: &'a CheckpointKey,
    pub data: &'a CompactAttestationData,
    pub indexed: &'a CompactIndexedAttestation<T>,
}

#[derive(Debug, Default)]
pub struct AttestationMap<T: EthSpec> {
    checkpoint_map: HashMap<CheckpointKey, AttestationDataMap<T>>,
}

#[derive(Debug, Default)]
pub struct AttestationDataMap<T: EthSpec> {
    attestations: HashMap<CompactAttestationData, Vec<CompactIndexedAttestation<T>>>,
}

fn split<T: EthSpec>(
    attestation: Attestation<T>,
    attesting_indices: Vec<u64>,
) -> (
    CheckpointKey,
    CompactAttestationData,
    CompactIndexedAttestation<T>,
) {
    let checkpoint_key = CheckpointKey {
        source: attestation.data.source,
        target_epoch: attestation.data.target.epoch,
    };
    let attestation_data = CompactAttestationData {
        slot: attestation.data.slot,
        index: attestation.data.index,
        beacon_block_root: attestation.data.beacon_block_root,
        target_root: attestation.data.target.root,
    };
    let indexed_attestation = CompactIndexedAttestation {
        attesting_indices,
        aggregation_bits: attestation.aggregation_bits,
        signature: attestation.signature,
    };
    (checkpoint_key, attestation_data, indexed_attestation)
}

impl<'a, T: EthSpec> AttestationRef<'a, T> {
    pub fn attestation_data(&self) -> AttestationData {
        AttestationData {
            slot: self.data.slot,
            index: self.data.index,
            beacon_block_root: self.data.beacon_block_root,
            source: self.checkpoint.source,
            target: Checkpoint {
                epoch: self.checkpoint.target_epoch,
                root: self.data.target_root,
            },
        }
    }

    pub fn clone_as_attestation(&self) -> Attestation<T> {
        Attestation {
            aggregation_bits: self.indexed.aggregation_bits.clone(),
            data: self.attestation_data(),
            signature: self.indexed.signature.clone(),
        }
    }
}

impl CheckpointKey {
    pub fn from_state<T: EthSpec>(state: &BeaconState<T>, epoch: Epoch) -> Self {
        if epoch == state.current_epoch() {
            CheckpointKey {
                source: state.current_justified_checkpoint(),
                target_epoch: epoch,
            }
        } else {
            CheckpointKey {
                source: state.previous_justified_checkpoint(),
                target_epoch: epoch,
            }
        }
    }
}

impl<T: EthSpec> CompactIndexedAttestation<T> {
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        self.aggregation_bits
            .intersection(&other.aggregation_bits)
            .is_zero()
    }

    pub fn aggregate(&mut self, other: &Self) {
        self.attesting_indices = self
            .attesting_indices
            .drain(..)
            .merge(other.attesting_indices.iter().copied())
            .collect();
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }
}

impl<T: EthSpec> AttestationMap<T> {
    pub fn insert(&mut self, attestation: Attestation<T>, attesting_indices: Vec<u64>) {
        let (checkpoint_key, attestation_data, indexed_attestation) =
            split(attestation, attesting_indices);

        let attestation_map = self
            .checkpoint_map
            .entry(checkpoint_key)
            .or_insert_with(AttestationDataMap::default);
        let attestations = attestation_map
            .attestations
            .entry(attestation_data)
            .or_insert_with(Vec::new);

        // Greedily aggregate the attestation with all existing attestations.
        // NOTE: this is sub-optimal and in future we will remove this in favour of max-clique
        // aggregation.
        let mut aggregated = false;
        for existing_attestation in attestations.iter_mut() {
            if existing_attestation.signers_disjoint_from(&indexed_attestation) {
                existing_attestation.aggregate(&indexed_attestation);
                aggregated = true;
            } else if *existing_attestation == indexed_attestation {
                aggregated = true;
            }
        }

        if !aggregated {
            attestations.push(indexed_attestation);
        }
    }

    pub fn get_attestations<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
    ) -> impl Iterator<Item = AttestationRef<'a, T>> + 'a {
        // It's a monad :O
        self.checkpoint_map
            .get(checkpoint_key)
            .into_iter()
            .flat_map(|attestation_map| {
                attestation_map
                    .attestations
                    .iter()
                    .flat_map(|(data, vec_indexed)| {
                        vec_indexed.iter().map(|indexed| AttestationRef {
                            checkpoint: checkpoint_key,
                            data,
                            indexed,
                        })
                    })
            })
    }
}
