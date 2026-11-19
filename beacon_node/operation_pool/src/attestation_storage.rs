use crate::AttestationStats;
use bls::AggregateSignature;
use itertools::Itertools;
use ssz::{BitList, BitVector, ProgressiveBitList};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use superstruct::superstruct;
use tree_hash::TreeHash;
use typenum::Unsigned;
use types::{
    Attestation, AttestationData, AttestationError, AttestationPq, AttestationProof, BeaconState,
    Checkpoint, Epoch, EthSpec, Hash256, Slot,
    attestation::{AttestationBase, AttestationElectra, AttestationGloas},
};

/// A verified network aggregate covers exactly one committee.
#[derive(Debug)]
pub struct CompactIndexedAttestationPq<E: EthSpec> {
    pub attestation: AttestationPq<E>,
    pub attesting_indices: Vec<u64>,
    pub proof: AttestationProof<E>,
}

type PqCommittees<E> = BTreeMap<(Hash256, u64), Arc<CompactIndexedAttestationPq<E>>>;

#[derive(Debug, Default)]
pub(crate) struct PqAttestationMap<E: EthSpec> {
    slots: BTreeMap<Slot, PqCommittees<E>>,
}

impl<E: EthSpec> PqAttestationMap<E> {
    pub(crate) fn insert(&mut self, entry: Arc<CompactIndexedAttestationPq<E>>) {
        let Some(committee) = entry.attestation.committee_index() else {
            return;
        };
        let slot_entries = self.slots.entry(entry.attestation.data.slot).or_default();
        let key = (entry.attestation.data.tree_hash_root(), committee);
        if let Some(current) = slot_entries.get_mut(&key) {
            if entry.attesting_indices.len() > current.attesting_indices.len() {
                *current = entry;
            }
            return;
        }
        // The wire allows several forks per committee. Cap proof memory even
        // when validators distribute their votes over many different forks.
        let max_entries = E::max_committees_per_slot_pq().saturating_mul(4);
        if slot_entries.len() >= max_entries {
            let Some((weakest_key, weakest)) = slot_entries
                .iter()
                .min_by_key(|(_, aggregate)| aggregate.attesting_indices.len())
            else {
                return;
            };
            if weakest.attesting_indices.len() >= entry.attesting_indices.len() {
                return;
            }
            let weakest_key = *weakest_key;
            slot_entries.remove(&weakest_key);
        }
        slot_entries.insert(key, entry);
    }

    pub(crate) fn prune(&mut self, current_epoch: Epoch) {
        let earliest_slot = current_epoch
            .saturating_sub(1u64)
            .start_slot(E::slots_per_epoch());
        self.slots.retain(|slot, _| *slot >= earliest_slot);
    }

    pub(crate) fn candidates(&self, latest_slot: Slot) -> Vec<Arc<CompactIndexedAttestationPq<E>>> {
        self.slots
            .range(..=latest_slot)
            .rev()
            .flat_map(|(_, committees)| committees.values().cloned())
            .collect()
    }
}

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

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(derive(Debug, PartialEq,))
)]
#[derive(Debug, PartialEq)]
pub struct CompactIndexedAttestation<E: EthSpec> {
    pub attesting_indices: Vec<u64>,
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerSlot>,
    #[superstruct(only(Gloas), partial_getter(rename = "aggregation_bits_gloas"))]
    pub aggregation_bits: ProgressiveBitList,
    pub signature: AggregateSignature,
    #[superstruct(only(Electra, Gloas))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
}

#[derive(Debug)]
pub struct SplitAttestation<E: EthSpec> {
    pub checkpoint: CheckpointKey,
    pub data: CompactAttestationData,
    pub indexed: CompactIndexedAttestation<E>,
}

#[derive(Debug, Clone)]
pub struct CompactAttestationRef<'a, E: EthSpec> {
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
    /// Errors for a Pq attestation: the pool aggregates by BLS signature, whereas Pq
    /// attestations are aggregated by proof.
    pub fn new(
        attestation: Attestation<E>,
        attesting_indices: Vec<u64>,
    ) -> Result<Self, AttestationError> {
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

        let indexed = match attestation {
            Attestation::Base(attn) => {
                CompactIndexedAttestation::Base(CompactIndexedAttestationBase {
                    attesting_indices,
                    aggregation_bits: attn.aggregation_bits,
                    signature: attn.signature,
                })
            }
            Attestation::Electra(attn) => {
                CompactIndexedAttestation::Electra(CompactIndexedAttestationElectra {
                    attesting_indices,
                    aggregation_bits: attn.aggregation_bits,
                    signature: attn.signature,
                    committee_bits: attn.committee_bits,
                })
            }
            Attestation::Gloas(attn) => {
                CompactIndexedAttestation::Gloas(CompactIndexedAttestationGloas {
                    attesting_indices,
                    aggregation_bits: attn.aggregation_bits,
                    signature: attn.signature,
                    committee_bits: attn.committee_bits,
                })
            }
            Attestation::Pq(_) => return Err(AttestationError::PqAttestationHasNoSignature),
        };

        Ok(Self {
            checkpoint,
            data,
            indexed,
        })
    }

    pub fn as_ref(&self) -> CompactAttestationRef<'_, E> {
        CompactAttestationRef {
            checkpoint: &self.checkpoint,
            data: &self.data,
            indexed: &self.indexed,
        }
    }
}

impl<E: EthSpec> CompactAttestationRef<'_, E> {
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

    pub fn get_committee_indices_map(&self) -> HashSet<u64> {
        match self.indexed {
            CompactIndexedAttestation::Base(_) => HashSet::from([self.data.index]),
            CompactIndexedAttestation::Electra(indexed_att) => indexed_att
                .committee_bits
                .iter()
                .enumerate()
                .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
                .collect(),
            CompactIndexedAttestation::Gloas(indexed_att) => indexed_att
                .committee_bits
                .iter()
                .enumerate()
                .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
                .collect(),
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
            CompactIndexedAttestation::Gloas(indexed_att) => Attestation::Gloas(AttestationGloas {
                aggregation_bits: indexed_att.aggregation_bits.clone(),
                data: self.attestation_data(),
                signature: indexed_att.signature.clone(),
                committee_bits: indexed_att.committee_bits.clone(),
            }),
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
    pub fn should_aggregate(&self, other: &Self) -> bool {
        match (self, other) {
            (CompactIndexedAttestation::Base(this), CompactIndexedAttestation::Base(other)) => {
                this.should_aggregate(other)
            }
            (
                CompactIndexedAttestation::Electra(this),
                CompactIndexedAttestation::Electra(other),
            ) => this.should_aggregate(other),
            (CompactIndexedAttestation::Gloas(this), CompactIndexedAttestation::Gloas(other)) => {
                this.should_aggregate(other)
            }
            _ => false,
        }
    }

    /// Returns `true` if aggregated, otherwise `false`.
    pub fn aggregate(&mut self, other: &Self) -> bool {
        match (self, other) {
            (CompactIndexedAttestation::Base(this), CompactIndexedAttestation::Base(other)) => {
                this.aggregate(other);
                true
            }
            (
                CompactIndexedAttestation::Electra(this),
                CompactIndexedAttestation::Electra(other),
            ) => this.aggregate_same_committee(other),
            (CompactIndexedAttestation::Gloas(this), CompactIndexedAttestation::Gloas(other)) => {
                this.aggregate_same_committee(other)
            }
            _ => false,
        }
    }
}

impl<E: EthSpec> CompactIndexedAttestationBase<E> {
    pub fn should_aggregate(&self, other: &Self) -> bool {
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

impl<E: EthSpec> CompactIndexedAttestationElectra<E> {
    pub fn should_aggregate(&self, other: &Self) -> bool {
        // For Electra, only aggregate attestations in the same committee.
        self.committee_bits == other.committee_bits
            && self
                .aggregation_bits
                .intersection(&other.aggregation_bits)
                .is_zero()
    }

    /// Returns `true` if aggregated, otherwise `false`.
    pub fn aggregate_same_committee(&mut self, other: &Self) -> bool {
        if self.committee_bits != other.committee_bits {
            return false;
        }
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.attesting_indices = self
            .attesting_indices
            .drain(..)
            .merge(other.attesting_indices.iter().copied())
            .dedup()
            .collect();
        self.signature.add_assign_aggregate(&other.signature);
        true
    }

    pub fn aggregate_with_disjoint_committees(&mut self, other: &Self) -> Option<()> {
        if !self
            .committee_bits
            .intersection(&other.committee_bits)
            .is_zero()
        {
            return None;
        }
        // The attestation being aggregated in must only have 1 committee bit set.
        if other.committee_bits.num_set_bits() != 1 {
            return None;
        }

        // Check we are aggregating in increasing committee index order (so we can append
        // aggregation bits).
        if self.committee_bits.highest_set_bit() >= other.committee_bits.highest_set_bit() {
            return None;
        }

        self.committee_bits = self.committee_bits.union(&other.committee_bits);
        if let Some(agg_bits) = bitlist_extend(&self.aggregation_bits, &other.aggregation_bits) {
            self.aggregation_bits = agg_bits;

            self.attesting_indices = self
                .attesting_indices
                .drain(..)
                .merge(other.attesting_indices.iter().copied())
                .dedup()
                .collect();
            self.signature.add_assign_aggregate(&other.signature);

            return Some(());
        }

        None
    }

    pub fn committee_index(&self) -> Option<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .find(|&(_, bit)| bit)
            .map(|(index, _)| index as u64)
    }

    pub fn get_committee_indices(&self) -> Vec<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}

impl<E: EthSpec> CompactIndexedAttestationGloas<E> {
    pub fn should_aggregate(&self, other: &Self) -> bool {
        // Only aggregate attestations in the same committee.
        self.committee_bits == other.committee_bits
            && self
                .aggregation_bits
                .intersection(&other.aggregation_bits)
                .is_zero()
    }

    /// Returns `true` if aggregated, otherwise `false`.
    pub fn aggregate_same_committee(&mut self, other: &Self) -> bool {
        if self.committee_bits != other.committee_bits {
            return false;
        }
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.attesting_indices = self
            .attesting_indices
            .drain(..)
            .merge(other.attesting_indices.iter().copied())
            .dedup()
            .collect();
        self.signature.add_assign_aggregate(&other.signature);
        true
    }

    pub fn aggregate_with_disjoint_committees(&mut self, other: &Self) -> Option<()> {
        if !self
            .committee_bits
            .intersection(&other.committee_bits)
            .is_zero()
        {
            return None;
        }
        // The attestation being aggregated in must only have 1 committee bit set.
        if other.committee_bits.num_set_bits() != 1 {
            return None;
        }

        // Check we are aggregating in increasing committee index order (so we can append
        // aggregation bits).
        if self.committee_bits.highest_set_bit() >= other.committee_bits.highest_set_bit() {
            return None;
        }

        self.committee_bits = self.committee_bits.union(&other.committee_bits);
        if let Some(agg_bits) =
            progressive_bitlist_extend(&self.aggregation_bits, &other.aggregation_bits)
        {
            self.aggregation_bits = agg_bits;

            self.attesting_indices = self
                .attesting_indices
                .drain(..)
                .merge(other.attesting_indices.iter().copied())
                .dedup()
                .collect();
            self.signature.add_assign_aggregate(&other.signature);

            return Some(());
        }

        None
    }

    pub fn committee_index(&self) -> Option<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .find(|&(_, bit)| bit)
            .map(|(index, _)| index as u64)
    }

    pub fn get_committee_indices(&self) -> Vec<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}

// TODO(electra): upstream this or a more efficient implementation
fn bitlist_extend<N: Unsigned>(list1: &BitList<N>, list2: &BitList<N>) -> Option<BitList<N>> {
    let new_length = list1.len() + list2.len();
    let mut list = BitList::<N>::with_capacity(new_length).ok()?;

    // Copy bits from list1.
    for (i, bit) in list1.iter().enumerate() {
        list.set(i, bit).ok()?;
    }

    // Copy bits from list2, starting from the end of list1.
    let offset = list1.len();
    for (i, bit) in list2.iter().enumerate() {
        list.set(offset + i, bit).ok()?;
    }

    Some(list)
}

/// Progressive (Gloas, EIP-7916) equivalent of [`bitlist_extend`].
fn progressive_bitlist_extend(
    list1: &ProgressiveBitList,
    list2: &ProgressiveBitList,
) -> Option<ProgressiveBitList> {
    let new_length = list1.len() + list2.len();
    let mut list = ProgressiveBitList::with_capacity(new_length);

    // Copy bits from list1.
    for (i, bit) in list1.iter().enumerate() {
        list.set(i, bit).ok()?;
    }

    // Copy bits from list2, starting from the end of list1.
    let offset = list1.len();
    for (i, bit) in list2.iter().enumerate() {
        list.set(offset + i, bit).ok()?;
    }

    Some(list)
}

impl<E: EthSpec> AttestationMap<E> {
    pub fn insert(
        &mut self,
        attestation: Attestation<E>,
        attesting_indices: Vec<u64>,
    ) -> Result<(), AttestationError> {
        let SplitAttestation {
            checkpoint,
            data,
            indexed,
        } = SplitAttestation::new(attestation, attesting_indices)?;

        let attestation_map = self.checkpoint_map.entry(checkpoint).or_default();
        let attestations = attestation_map.attestations.entry(data).or_default();

        // Greedily aggregate the attestation with all existing attestations.
        // NOTE: this is sub-optimal and in future we will remove this in favour of max-clique
        // aggregation.
        let mut aggregated = false;

        for existing_attestation in attestations.iter_mut() {
            if existing_attestation.should_aggregate(&indexed) {
                aggregated = existing_attestation.aggregate(&indexed);
            } else if *existing_attestation == indexed {
                aggregated = true;
            }
        }

        if !aggregated {
            attestations.push(indexed);
        }

        Ok(())
    }

    /// Aggregate Electra/Gloas attestations for the same attestation data signed by different
    /// committees.
    ///
    /// Base attestations are left as-is.
    pub fn aggregate_across_committees(&mut self, checkpoint_key: CheckpointKey) {
        let Some(attestation_map) = self.checkpoint_map.get_mut(&checkpoint_key) else {
            return;
        };
        for compact_indexed_attestations in attestation_map.attestations.values_mut() {
            let unaggregated_attestations = std::mem::take(compact_indexed_attestations);
            let mut aggregated_attestations: Vec<CompactIndexedAttestation<E>> = vec![];

            // Aggregate the best attestations for each committee and leave the rest.
            let mut best_attestations_by_committee: BTreeMap<
                u64,
                CompactIndexedAttestationElectra<E>,
            > = BTreeMap::new();
            let mut best_gloas_attestations_by_committee: BTreeMap<
                u64,
                CompactIndexedAttestationGloas<E>,
            > = BTreeMap::new();

            for committee_attestation in unaggregated_attestations {
                let mut electra_attestation = match committee_attestation {
                    CompactIndexedAttestation::Electra(att)
                        if att.committee_bits.num_set_bits() == 1 =>
                    {
                        att
                    }
                    CompactIndexedAttestation::Gloas(att)
                        if att.committee_bits.num_set_bits() == 1 =>
                    {
                        let mut gloas_attestation = att;
                        if let Some(committee_index) = gloas_attestation.committee_index() {
                            if let Some(existing_attestation) =
                                best_gloas_attestations_by_committee.get_mut(&committee_index)
                            {
                                // Search for the best (most aggregation bits) attestation for this
                                // committee index.
                                if gloas_attestation.aggregation_bits.num_set_bits()
                                    > existing_attestation.aggregation_bits.num_set_bits()
                                {
                                    // New attestation is better than the previously known one for
                                    // this committee. Replace it.
                                    std::mem::swap(existing_attestation, &mut gloas_attestation);
                                }
                                // Put the inferior attestation into the list of aggregated
                                // attestations without performing any cross-committee aggregation.
                                aggregated_attestations
                                    .push(CompactIndexedAttestation::Gloas(gloas_attestation));
                            } else {
                                // First attestation seen for this committee. Place it in the map
                                // provisionally.
                                best_gloas_attestations_by_committee
                                    .insert(committee_index, gloas_attestation);
                            }
                        }
                        continue;
                    }
                    other => {
                        // Aggregates that already cover multiple committees and Base attestations
                        // are left as-is.
                        aggregated_attestations.push(other);
                        continue;
                    }
                };
                if let Some(committee_index) = electra_attestation.committee_index() {
                    if let Some(existing_attestation) =
                        best_attestations_by_committee.get_mut(&committee_index)
                    {
                        // Search for the best (most aggregation bits) attestation for this committee
                        // index.
                        if electra_attestation.aggregation_bits.num_set_bits()
                            > existing_attestation.aggregation_bits.num_set_bits()
                        {
                            // New attestation is better than the previously known one for this
                            // committee. Replace it.
                            std::mem::swap(existing_attestation, &mut electra_attestation);
                        }
                        // Put the inferior attestation into the list of aggregated attestations
                        // without performing any cross-committee aggregation.
                        aggregated_attestations
                            .push(CompactIndexedAttestation::Electra(electra_attestation));
                    } else {
                        // First attestation seen for this committee. Place it in the map
                        // provisionally.
                        best_attestations_by_committee.insert(committee_index, electra_attestation);
                    }
                }
            }

            if let Some(on_chain_aggregate) =
                Self::compute_on_chain_aggregate(best_attestations_by_committee)
            {
                aggregated_attestations
                    .push(CompactIndexedAttestation::Electra(on_chain_aggregate));
            }

            if let Some(on_chain_aggregate) =
                Self::compute_on_chain_aggregate_gloas(best_gloas_attestations_by_committee)
            {
                aggregated_attestations.push(CompactIndexedAttestation::Gloas(on_chain_aggregate));
            }

            *compact_indexed_attestations = aggregated_attestations;
        }
    }

    pub fn compute_on_chain_aggregate(
        mut attestations_by_committee: BTreeMap<u64, CompactIndexedAttestationElectra<E>>,
    ) -> Option<CompactIndexedAttestationElectra<E>> {
        let (_, mut on_chain_aggregate) = attestations_by_committee.pop_first()?;
        for (_, attestation) in attestations_by_committee {
            on_chain_aggregate.aggregate_with_disjoint_committees(&attestation);
        }
        Some(on_chain_aggregate)
    }

    pub fn compute_on_chain_aggregate_gloas(
        mut attestations_by_committee: BTreeMap<u64, CompactIndexedAttestationGloas<E>>,
    ) -> Option<CompactIndexedAttestationGloas<E>> {
        let (_, mut on_chain_aggregate) = attestations_by_committee.pop_first()?;
        for (_, attestation) in attestations_by_committee {
            on_chain_aggregate.aggregate_with_disjoint_committees(&attestation);
        }
        Some(on_chain_aggregate)
    }

    /// Iterate all attestations matching the given `checkpoint_key`.
    pub fn get_attestations<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
    ) -> impl Iterator<Item = CompactAttestationRef<'a, E>> + 'a {
        self.checkpoint_map
            .get(checkpoint_key)
            .into_iter()
            .flat_map(|attestation_map| attestation_map.iter(checkpoint_key))
    }

    /// Iterate all attestations in the map.
    pub fn iter(&self) -> impl Iterator<Item = CompactAttestationRef<'_, E>> {
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
    ) -> impl Iterator<Item = CompactAttestationRef<'a, E>> + 'a {
        self.attestations.iter().flat_map(|(data, vec_indexed)| {
            vec_indexed.iter().map(|indexed| CompactAttestationRef {
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

#[cfg(test)]
mod pq_tests {
    use super::*;
    use types::MinimalEthSpec;

    fn aggregate(
        root_suffix: u8,
        committee: usize,
        count: u64,
    ) -> Arc<CompactIndexedAttestationPq<MinimalEthSpec>> {
        let mut committee_bits = types::CommitteeBitsPq::<MinimalEthSpec>::default();
        committee_bits.set(committee, true).unwrap();
        let mut aggregation_bits = ProgressiveBitList::with_capacity(count as usize);
        for index in 0..count as usize {
            aggregation_bits.set(index, true).unwrap();
        }
        Arc::new(CompactIndexedAttestationPq {
            attestation: AttestationPq {
                aggregation_bits,
                committee_bits,
                data: AttestationData {
                    beacon_block_root: Hash256::with_last_byte(root_suffix),
                    ..AttestationData::default()
                },
            },
            attesting_indices: (0..count).collect(),
            proof: Default::default(),
        })
    }

    #[test]
    fn pq_pool_keeps_the_best_proof_and_bounds_forks_per_slot() {
        let mut pool = PqAttestationMap::default();
        let slot = Slot::new(0);
        let weaker = aggregate(0, 0, 1);
        let stronger = aggregate(0, 0, 2);
        let other_committee = aggregate(0, 1, 1);
        pool.insert(Arc::clone(&weaker));
        pool.insert(Arc::clone(&stronger));
        pool.insert(weaker);
        pool.insert(Arc::clone(&other_committee));
        let candidates = pool.candidates(slot);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().any(|proof| Arc::ptr_eq(proof, &stronger)));
        assert!(
            candidates
                .iter()
                .any(|proof| Arc::ptr_eq(proof, &other_committee))
        );

        let capacity = MinimalEthSpec::max_committees_per_slot_pq() * 4;
        for root in 1..=capacity {
            pool.insert(aggregate(root as u8, 0, 1));
        }
        let best = aggregate((capacity + 1) as u8, 0, 3);
        pool.insert(Arc::clone(&best));
        let candidates = pool.candidates(slot);
        assert_eq!(candidates.len(), capacity);
        assert!(candidates.iter().any(|proof| Arc::ptr_eq(proof, &best)));

        pool.prune(Epoch::new(2));
        assert!(pool.candidates(slot).is_empty());
    }
}
