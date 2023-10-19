use crate::AttestationStats;
use itertools::Itertools;
use std::collections::HashMap;
use types::{
    AggregateSignature, Attestation, AttestationData, BeaconState, BitList, Checkpoint, Epoch,
    EthSpec, Hash256, Slot,
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CheckpointKey {
    pub source: Checkpoint,
    pub target_epoch: Epoch,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CompactAttestationData {
    pub slot: Slot,
    pub index: u64,
    pub beacon_block_root: Hash256,
    pub target_root: Hash256,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CompactIndexedAttestation<T: EthSpec> {
    pub attesting_indices: Vec<u64>,
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}

#[derive(Debug)]
pub struct SplitAttestation<T: EthSpec> {
    pub checkpoint: CheckpointKey,
    pub data: CompactAttestationData,
    pub indexed: CompactIndexedAttestation<T>,
}

#[derive(Debug, Clone)]
pub struct AttestationRef<'a, T: EthSpec> {
    pub checkpoint: &'a CheckpointKey,
    pub data: &'a CompactAttestationData,
    pub indexed: &'a CompactIndexedAttestation<T>,
}

#[derive(Debug, Default, PartialEq)]
pub struct AttestationMap<T: EthSpec> {
    checkpoint_map: HashMap<CheckpointKey, AttestationDataMap<T>>,
}

#[derive(Debug, Default, PartialEq)]
pub struct AttestationDataMap<T: EthSpec> {
    pub aggregate_attestations: HashMap<CompactAttestationData, Vec<CompactIndexedAttestation<T>>>,
    pub unaggregate_attestations:
        HashMap<CompactAttestationData, Vec<CompactIndexedAttestation<T>>>,
}

impl<T: EthSpec> SplitAttestation<T> {
    pub fn new(attestation: Attestation<T>, attesting_indices: Vec<u64>) -> Self {
        let checkpoint = CheckpointKey {
            source: attestation.data.source,
            target_epoch: attestation.data.target.epoch,
        };
        let data = CompactAttestationData {
            slot: attestation.data.slot,
            index: attestation.data.index,
            beacon_block_root: attestation.data.beacon_block_root,
            target_root: attestation.data.target.root,
        };
        let indexed = CompactIndexedAttestation {
            attesting_indices,
            aggregation_bits: attestation.aggregation_bits,
            signature: attestation.signature,
        };
        Self {
            checkpoint,
            data,
            indexed,
        }
    }

    pub fn as_ref(&self) -> AttestationRef<T> {
        AttestationRef {
            checkpoint: &self.checkpoint,
            data: &self.data,
            indexed: &self.indexed,
        }
    }
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
    /// Return two checkpoint keys: `(previous, current)` for the previous and current epochs of
    /// the `state`.
    pub fn keys_for_state<T: EthSpec>(state: &BeaconState<T>) -> (Self, Self) {
        (
            CheckpointKey {
                source: state.previous_justified_checkpoint(),
                target_epoch: state.previous_epoch(),
            },
            CheckpointKey {
                source: state.current_justified_checkpoint(),
                target_epoch: state.current_epoch(),
            },
        )
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
            .dedup()
            .collect();
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }
}

impl<T: EthSpec> AttestationMap<T> {
    pub fn insert(&mut self, attestation: Attestation<T>, attesting_indices: Vec<u64>) {
        let SplitAttestation {
            checkpoint,
            data,
            indexed,
        } = SplitAttestation::new(attestation, attesting_indices);

        let attestation_map = self
            .checkpoint_map
            .entry(checkpoint)
            .or_default();
        let attestations = if indexed.attesting_indices.len() > 1 {
            attestation_map
                .aggregate_attestations
                .entry(data)
                .or_default()
        } else {
            attestation_map
                .unaggregate_attestations
                .entry(data)
                .or_insert_with(Vec::new)
        };
        let mut observed = false;
        for existing_attestation in attestations.iter_mut() {
            if *existing_attestation == indexed {
                observed = true;
            }
        }

        if !observed {
            attestations.push(indexed);
        }
    }

    /// Iterate all attestations in the map.
    pub fn iter(&self) -> impl Iterator<Item = AttestationRef<T>> {
        self.checkpoint_map
            .iter()
            .flat_map(|(checkpoint_key, attestation_map)| attestation_map.iter(checkpoint_key))
    }

    /// Prune attestations that are from before the previous epoch.
    pub fn prune(&mut self, current_epoch: Epoch) {
        self.checkpoint_map
            .retain(|checkpoint_key, _| current_epoch <= checkpoint_key.target_epoch + 1);
    }

    pub fn get_attestation_map(
        &self,
        checkpoint_key: &CheckpointKey,
    ) -> Option<&AttestationDataMap<T>> {
        self.checkpoint_map.get(checkpoint_key)
    }

    /// Statistics about all attestations stored in the map.
    pub fn stats(&self) -> AttestationStats {
        self.checkpoint_map
            .values()
            .map(AttestationDataMap::stats)
            .fold(AttestationStats::default(), |mut acc, new| {
                acc.num_attestations += new.num_attestations;
                acc.num_attestation_data += new.num_attestation_data;
                acc.max_aggregates_per_data =
                    std::cmp::max(acc.max_aggregates_per_data, new.max_aggregates_per_data);
                acc
            })
    }
}

impl<T: EthSpec> AttestationDataMap<T> {
    pub fn iter<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
    ) -> impl Iterator<Item = AttestationRef<'a, T>> + 'a {
        let aggregates = self
            .aggregate_attestations
            .iter()
            .flat_map(|(data, vec_indexed)| {
                vec_indexed.iter().map(|indexed| AttestationRef {
                    checkpoint: checkpoint_key,
                    data,
                    indexed,
                })
            });

        let unaggregates = self
            .aggregate_attestations
            .iter()
            .flat_map(|(data, vec_indexed)| {
                vec_indexed.iter().map(|indexed| AttestationRef {
                    checkpoint: checkpoint_key,
                    data,
                    indexed,
                })
            });

        aggregates.chain(unaggregates)
    }

    pub fn stats(&self) -> AttestationStats {
        let mut stats = AttestationStats::default();
        let mut data_to_num_attestations: HashMap<&CompactAttestationData, usize> = HashMap::new();

        for (data, aggregates) in self.aggregate_attestations.iter() {
            stats.num_attestations += aggregates.len();
            stats.num_attestation_data += 1;
            stats.max_aggregates_per_data =
                std::cmp::max(stats.max_aggregates_per_data, aggregates.len());

            data_to_num_attestations.insert(data, aggregates.len());
        }

        for (data, unaggregates) in self.unaggregate_attestations.iter() {
            stats.num_attestations += unaggregates.len();
            if let Some(aggregates_num) = data_to_num_attestations.get(data) {
                stats.max_aggregates_per_data = std::cmp::max(
                    stats.max_aggregates_per_data,
                    aggregates_num + unaggregates.len(),
                );
            } else {
                stats.num_attestation_data += 1;
                stats.max_aggregates_per_data =
                    std::cmp::max(stats.max_aggregates_per_data, unaggregates.len());
            }
        }

        stats
    }
}
