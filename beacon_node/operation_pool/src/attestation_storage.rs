use crate::AttestationStats;
use itertools::Itertools;
use std::collections::HashMap;
use types::{
    attestation::{AttestationBase, AttestationElectra},
    superstruct, AggregateSignature, Attestation, AttestationData, BeaconState, BitList, BitVector,
    Checkpoint, Epoch, EthSpec, Hash256, Slot,
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

#[superstruct(variants(Base, Electra), variant_attributes(derive(Debug, PartialEq,)))]
#[derive(Debug, PartialEq)]
pub struct CompactIndexedAttestation<E: EthSpec> {
    pub attesting_indices: Vec<u64>,
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommitteePerSlot>,
    pub signature: AggregateSignature,
    pub index: u64,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
}

#[derive(Debug)]
pub struct SplitAttestation<E: EthSpec> {
    pub checkpoint: CheckpointKey,
    pub data: CompactAttestationData,
    pub indexed: CompactIndexedAttestation<E>,
}

#[derive(Debug, Clone)]
pub struct AttestationRef<'a, E: EthSpec> {
    pub checkpoint: &'a CheckpointKey,
    pub data: &'a CompactAttestationData,
    pub indexed: &'a CompactIndexedAttestation<E>,
}

#[derive(Debug, Default, PartialEq)]
pub struct AttestationMap<E: EthSpec> {
    checkpoint_map: HashMap<CheckpointKey, AttestationDataMap<E>>,
}

#[derive(Debug, Default, PartialEq)]
pub struct AttestationDataMap<E: EthSpec> {
    attestations: HashMap<CompactAttestationData, Vec<CompactIndexedAttestation<E>>>,
}

impl<E: EthSpec> SplitAttestation<E> {
    pub fn new(attestation: Attestation<E>, attesting_indices: Vec<u64>) -> Self {
        let checkpoint = CheckpointKey {
            source: attestation.data().source,
            target_epoch: attestation.data().target.epoch,
        };
        let data = CompactAttestationData {
            slot: attestation.data().slot,
            index: attestation.data().index,
            beacon_block_root: attestation.data().beacon_block_root,
            target_root: attestation.data().target.root,
        };

        let indexed = match attestation.clone() {
            Attestation::Base(attn) => {
                CompactIndexedAttestation::Base(CompactIndexedAttestationBase {
                    attesting_indices,
                    aggregation_bits: attn.aggregation_bits,
                    signature: attestation.signature().clone(),
                    index: data.index,
                })
            }
            Attestation::Electra(attn) => {
                CompactIndexedAttestation::Electra(CompactIndexedAttestationElectra {
                    attesting_indices,
                    aggregation_bits: attn.aggregation_bits,
                    signature: attestation.signature().clone(),
                    index: data.index,
                    committee_bits: attn.committee_bits,
                })
            }
        };

        Self {
            checkpoint,
            data,
            indexed,
        }
    }

    pub fn as_ref(&self) -> AttestationRef<E> {
        AttestationRef {
            checkpoint: &self.checkpoint,
            data: &self.data,
            indexed: &self.indexed,
        }
    }
}

impl<'a, E: EthSpec> AttestationRef<'a, E> {
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

    pub fn clone_as_attestation(&self) -> Attestation<E> {
        match self.indexed {
            CompactIndexedAttestation::Base(indexed_att) => Attestation::Base(AttestationBase {
                aggregation_bits: indexed_att.aggregation_bits.clone(),
                data: self.attestation_data(),
                signature: indexed_att.signature.clone(),
            }),
            CompactIndexedAttestation::Electra(indexed_att) => {
                Attestation::Electra(AttestationElectra {
                    aggregation_bits: indexed_att.aggregation_bits.clone(),
                    data: self.attestation_data(),
                    signature: indexed_att.signature.clone(),
                    committee_bits: indexed_att.committee_bits.clone(),
                })
            }
        }
    }
}

impl CheckpointKey {
    /// Return two checkpoint keys: `(previous, current)` for the previous and current epochs of
    /// the `state`.
    pub fn keys_for_state<E: EthSpec>(state: &BeaconState<E>) -> (Self, Self) {
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

impl<E: EthSpec> CompactIndexedAttestation<E> {
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        match (self, other) {
            (CompactIndexedAttestation::Base(this), CompactIndexedAttestation::Base(other)) => {
                this.signers_disjoint_from(other)
            }
            (CompactIndexedAttestation::Electra(_), CompactIndexedAttestation::Electra(_)) => {
                todo!()
            }
            // TODO(electra) is a mix of electra and base compact indexed attestations an edge case we need to deal with?
            _ => false,
        }
    }

    pub fn aggregate(&mut self, other: &Self) {
        match (self, other) {
            (CompactIndexedAttestation::Base(this), CompactIndexedAttestation::Base(other)) => {
                this.aggregate(other)
            }
            (CompactIndexedAttestation::Electra(_), CompactIndexedAttestation::Electra(_)) => {
                todo!()
            }
            // TODO(electra) is a mix of electra and base compact indexed attestations an edge case we need to deal with?
            _ => (),
        }
    }
}

impl<E: EthSpec> CompactIndexedAttestationBase<E> {
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

impl<E: EthSpec> AttestationMap<E> {
    pub fn insert(&mut self, attestation: Attestation<E>, attesting_indices: Vec<u64>) {
        let SplitAttestation {
            checkpoint,
            data,
            indexed,
        } = SplitAttestation::new(attestation, attesting_indices);

        let attestation_map = self.checkpoint_map.entry(checkpoint).or_default();
        let attestations = attestation_map.attestations.entry(data).or_default();

        // Greedily aggregate the attestation with all existing attestations.
        // NOTE: this is sub-optimal and in future we will remove this in favour of max-clique
        // aggregation.
        let mut aggregated = false;
        for existing_attestation in attestations.iter_mut() {
            if existing_attestation.signers_disjoint_from(&indexed) {
                existing_attestation.aggregate(&indexed);
                aggregated = true;
            } else if *existing_attestation == indexed {
                aggregated = true;
            }
        }

        if !aggregated {
            attestations.push(indexed);
        }
    }

    /// Iterate all attestations matching the given `checkpoint_key`.
    pub fn get_attestations<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
    ) -> impl Iterator<Item = AttestationRef<'a, E>> + 'a {
        self.checkpoint_map
            .get(checkpoint_key)
            .into_iter()
            .flat_map(|attestation_map| attestation_map.iter(checkpoint_key))
    }

    /// Iterate all attestations in the map.
    pub fn iter(&self) -> impl Iterator<Item = AttestationRef<E>> {
        self.checkpoint_map
            .iter()
            .flat_map(|(checkpoint_key, attestation_map)| attestation_map.iter(checkpoint_key))
    }

    /// Prune attestations that are from before the previous epoch.
    pub fn prune(&mut self, current_epoch: Epoch) {
        self.checkpoint_map
            .retain(|checkpoint_key, _| current_epoch <= checkpoint_key.target_epoch + 1);
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

impl<E: EthSpec> AttestationDataMap<E> {
    pub fn iter<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
    ) -> impl Iterator<Item = AttestationRef<'a, E>> + 'a {
        self.attestations.iter().flat_map(|(data, vec_indexed)| {
            vec_indexed.iter().map(|indexed| AttestationRef {
                checkpoint: checkpoint_key,
                data,
                indexed,
            })
        })
    }

    pub fn stats(&self) -> AttestationStats {
        let mut stats = AttestationStats::default();

        for aggregates in self.attestations.values() {
            stats.num_attestations += aggregates.len();
            stats.num_attestation_data += 1;
            stats.max_aggregates_per_data =
                std::cmp::max(stats.max_aggregates_per_data, aggregates.len());
        }
        stats
    }
}
