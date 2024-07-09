use crate::metrics;
use crate::observed_aggregates::AsReference;
use itertools::Itertools;
use smallvec::SmallVec;
use std::collections::HashMap;
use tree_hash::{MerkleHasher, TreeHash, TreeHashType};
use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use types::slot_data::SlotData;
use types::sync_committee_contribution::SyncContributionData;
use types::{
    Attestation, AttestationData, AttestationRef, CommitteeIndex, EthSpec, Hash256, Slot,
    SyncCommitteeContribution,
};

type AttestationKeyRoot = Hash256;
type SyncDataRoot = Hash256;

/// Post-Electra, we need a new key for Attestations that includes the committee index
#[derive(Debug, Clone, PartialEq)]
pub struct AttestationKey {
    data_root: Hash256,
    committee_index: Option<CommitteeIndex>,
    slot: Slot,
}

// A custom implementation of `TreeHash` such that:
//     AttestationKey(data, None).tree_hash_root() == data.tree_hash_root()
//     AttestationKey(data, Some(index)).tree_hash_root() == (data, index).tree_hash_root()
// This is necessary because pre-Electra, the validator will ask for the tree_hash_root()
// of the `AttestationData`
impl TreeHash for AttestationKey {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> SmallVec<[u8; 32]> {
        unreachable!("AttestationKey should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("AttestationKey should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        match self.committee_index {
            None => self.data_root, // Return just the data root if no committee index is present
            Some(index) => {
                // Combine the hash of the data with the hash of the index
                let mut hasher = MerkleHasher::with_leaves(2);
                hasher
                    .write(self.data_root.as_bytes())
                    .expect("should write data hash");
                hasher
                    .write(&index.to_le_bytes())
                    .expect("should write index");
                hasher.finish().expect("should give tree hash")
            }
        }
    }
}

impl AttestationKey {
    pub fn from_attestation_ref<E: EthSpec>(attestation: AttestationRef<E>) -> Result<Self, Error> {
        let slot = attestation.data().slot;
        match attestation {
            AttestationRef::Base(att) => Ok(Self {
                data_root: att.data.tree_hash_root(),
                committee_index: None,
                slot,
            }),
            AttestationRef::Electra(att) => {
                let committee_index = att
                    .committee_bits
                    .iter()
                    .enumerate()
                    .filter_map(|(i, bit)| if bit { Some(i) } else { None })
                    .at_most_one()
                    .map_err(|_| Error::MoreThanOneCommitteeBitSet)?
                    .ok_or(Error::NoCommitteeBitSet)?;

                Ok(Self {
                    data_root: att.data.tree_hash_root(),
                    committee_index: Some(committee_index as u64),
                    slot,
                })
            }
        }
    }

    pub fn new_base(data: &AttestationData) -> Self {
        let slot = data.slot;
        Self {
            data_root: data.tree_hash_root(),
            committee_index: None,
            slot,
        }
    }

    pub fn new_electra(slot: Slot, data_root: Hash256, committee_index: CommitteeIndex) -> Self {
        Self {
            data_root,
            committee_index: Some(committee_index),
            slot,
        }
    }

    pub fn new_base_from_slot_and_root(slot: Slot, data_root: Hash256) -> Self {
        Self {
            data_root,
            committee_index: None,
            slot,
        }
    }
}

impl SlotData for AttestationKey {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

/// The number of slots that will be stored in the pool.
///
/// For example, if `SLOTS_RETAINED == 3` and the pool is pruned at slot `6`, then all items
/// at slots less than `4` will be dropped and any future item with a slot less than `4`
/// will be refused.
const SLOTS_RETAINED: usize = 3;

/// The maximum number of distinct `AttestationData` that will be stored in each slot.
///
/// This is a DoS protection measure.
const MAX_ATTESTATIONS_PER_SLOT: usize = 16_384;

/// Returned upon successfully inserting an item into the pool.
#[derive(Debug, PartialEq)]
pub enum InsertOutcome {
    /// The item had not been seen before and was added to the pool.
    NewItemInserted { committee_index: usize },
    /// A validator signature for the given item's `Data` was already known. No changes were
    /// made.
    SignatureAlreadyKnown { committee_index: usize },
    /// The item's `Data` was known, but a signature for the given validator was not yet
    /// known. The signature was aggregated into the pool.
    SignatureAggregated { committee_index: usize },
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The given `data.slot` was too low to be stored. No changes were made.
    SlotTooLow {
        slot: Slot,
        lowest_permissible_slot: Slot,
    },
    /// The given `aggregation_bits` field was empty.
    NoAggregationBitsSet,
    /// The given `aggregation_bits` field had more than one signature. The number of
    /// signatures found is included.
    MoreThanOneAggregationBitSet(usize),
    /// The electra attestation has more than one committee bit set
    MoreThanOneCommitteeBitSet,
    /// The electra attestation has NO committee bit set
    NoCommitteeBitSet,
    /// We have reached the maximum number of unique items that can be stored in a
    /// slot. This is a DoS protection function.
    ReachedMaxItemsPerSlot(usize),
    /// The given `aggregation_bits` field had a different length to the one currently
    /// stored. This indicates a fairly serious error somewhere in the code that called this
    /// function.
    InconsistentBitfieldLengths,
    /// The given item was for the incorrect slot. This is an internal error.
    IncorrectSlot { expected: Slot, actual: Slot },
}

/// Implemented for items in the `NaiveAggregationPool`. Requires that items implement `SlotData`,
/// which means they have an associated slot. This handles aggregation of items that are inserted.
pub trait AggregateMap
where
    for<'a> <Self::Value as AsReference>::Reference<'a>: SlotData,
{
    /// `Key` should be a hash of `Data`.
    type Key;

    /// The item stored in the map
    type Value: Clone + SlotData + AsReference;

    /// The unique fields of `Value`, hashed to create `Key`.
    type Data: SlotData;

    /// Create a new `AggregateMap` with capacity `initial_capacity`.
    fn new(initial_capacity: usize) -> Self;

    /// Insert a `Value` into `Self`, returning a result.
    fn insert(
        &mut self,
        value: <Self::Value as AsReference>::Reference<'_>,
    ) -> Result<InsertOutcome, Error>;

    /// Get a `Value` from `Self` based on `Data`.
    fn get(&self, data: &Self::Data) -> Option<Self::Value>;

    /// Get a reference to the inner `HashMap`.
    fn get_map(&self) -> &HashMap<Self::Key, Self::Value>;

    /// The number of items store in `Self`.
    fn len(&self) -> usize;

    /// Start a timer observing inserts.
    fn start_insert_timer() -> Option<metrics::HistogramTimer>;

    /// Start a timer observing the time it takes to create a new map for a new slot.
    fn start_create_map_timer() -> Option<metrics::HistogramTimer>;

    /// Start a timer observing the time it takes to prune the pool.
    fn start_prune_timer() -> Option<metrics::HistogramTimer>;

    /// The default capacity of `Self`.
    fn default_capacity() -> usize;
}

/// A collection of `Attestation` objects, keyed by their `attestation.data`. Enforces that all
/// `attestation` are from the same slot.
pub struct AggregatedAttestationMap<E: EthSpec> {
    map: HashMap<AttestationKeyRoot, Attestation<E>>,
}

impl<E: EthSpec> AggregateMap for AggregatedAttestationMap<E> {
    type Key = AttestationKeyRoot;
    type Value = Attestation<E>;
    type Data = AttestationKey;

    /// Create an empty collection with the given `initial_capacity`.
    fn new(initial_capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature.
    fn insert(&mut self, a: AttestationRef<E>) -> Result<InsertOutcome, Error> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_CORE_INSERT);

        let aggregation_bit = *a
            .set_aggregation_bits()
            .iter()
            .at_most_one()
            .map_err(|iter| Error::MoreThanOneAggregationBitSet(iter.count()))?
            .ok_or(Error::NoAggregationBitsSet)?;

        let attestation_key = AttestationKey::from_attestation_ref(a)?;
        let attestation_key_root = attestation_key.tree_hash_root();

        if let Some(existing_attestation) = self.map.get_mut(&attestation_key_root) {
            if existing_attestation
                .get_aggregation_bit(aggregation_bit)
                .map_err(|_| Error::InconsistentBitfieldLengths)?
            {
                Ok(InsertOutcome::SignatureAlreadyKnown {
                    committee_index: aggregation_bit,
                })
            } else {
                let _timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_AGGREGATION);
                existing_attestation.aggregate(a);
                Ok(InsertOutcome::SignatureAggregated {
                    committee_index: aggregation_bit,
                })
            }
        } else {
            if self.map.len() >= MAX_ATTESTATIONS_PER_SLOT {
                return Err(Error::ReachedMaxItemsPerSlot(MAX_ATTESTATIONS_PER_SLOT));
            }

            self.map
                .insert(attestation_key_root, a.clone_as_attestation());
            Ok(InsertOutcome::NewItemInserted {
                committee_index: aggregation_bit,
            })
        }
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    ///
    /// The given `a.data.slot` must match the slot that `self` was initialized with.
    fn get(&self, data: &Self::Data) -> Option<Self::Value> {
        self.map.get(&data.tree_hash_root()).cloned()
    }

    fn get_map(&self) -> &HashMap<Self::Key, Self::Value> {
        &self.map
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn start_insert_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_INSERT)
    }

    fn start_create_map_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_CREATE_MAP)
    }

    fn start_prune_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_PRUNE)
    }

    /// Use the `TARGET_COMMITTEE_SIZE`.
    ///
    /// Note: hard-coded until `TARGET_COMMITTEE_SIZE` is available via `EthSpec`.
    fn default_capacity() -> usize {
        128
    }
}

/// A collection of `SyncCommitteeContribution`, keyed by their `SyncContributionData`. Enforces that all
/// contributions are from the same slot.
pub struct SyncContributionAggregateMap<E: EthSpec> {
    map: HashMap<SyncDataRoot, SyncCommitteeContribution<E>>,
}

impl<E: EthSpec> AggregateMap for SyncContributionAggregateMap<E> {
    type Key = SyncDataRoot;
    type Value = SyncCommitteeContribution<E>;
    type Data = SyncContributionData;

    /// Create an empty collection with the given `initial_capacity`.
    fn new(initial_capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Insert a sync committee contribution into `self`, aggregating it into the pool.
    ///
    /// The given sync contribution must only have one signature.
    fn insert(
        &mut self,
        contribution: &SyncCommitteeContribution<E>,
    ) -> Result<InsertOutcome, Error> {
        let _timer =
            metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_AGG_POOL_CORE_INSERT);

        let set_bits = contribution
            .aggregation_bits
            .iter()
            .enumerate()
            .filter(|(_i, bit)| *bit)
            .map(|(i, _bit)| i)
            .collect::<Vec<_>>();

        let committee_index = set_bits
            .first()
            .copied()
            .ok_or(Error::NoAggregationBitsSet)?;

        if set_bits.len() > 1 {
            return Err(Error::MoreThanOneAggregationBitSet(set_bits.len()));
        }

        let sync_data_root = SyncContributionData::from_contribution(contribution).tree_hash_root();

        if let Some(existing_contribution) = self.map.get_mut(&sync_data_root) {
            if existing_contribution
                .aggregation_bits
                .get(committee_index)
                .map_err(|_| Error::InconsistentBitfieldLengths)?
            {
                Ok(InsertOutcome::SignatureAlreadyKnown { committee_index })
            } else {
                let _timer = metrics::start_timer(
                    &metrics::SYNC_CONTRIBUTION_PROCESSING_AGG_POOL_AGGREGATION,
                );
                existing_contribution.aggregate(contribution);
                Ok(InsertOutcome::SignatureAggregated { committee_index })
            }
        } else {
            if self.map.len() >= E::sync_committee_size() {
                return Err(Error::ReachedMaxItemsPerSlot(E::sync_committee_size()));
            }

            self.map.insert(sync_data_root, contribution.clone());
            Ok(InsertOutcome::NewItemInserted { committee_index })
        }
    }

    /// Returns an aggregated `SyncCommitteeContribution` with the given `data`, if any.
    ///
    /// The given `data.slot` must match the slot that `self` was initialized with.
    fn get(&self, data: &SyncContributionData) -> Option<SyncCommitteeContribution<E>> {
        self.map.get(&data.tree_hash_root()).cloned()
    }

    fn get_map(&self) -> &HashMap<SyncDataRoot, SyncCommitteeContribution<E>> {
        &self.map
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn start_insert_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_AGG_POOL_INSERT)
    }

    fn start_create_map_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_AGG_POOL_CREATE_MAP)
    }

    fn start_prune_timer() -> Option<metrics::HistogramTimer> {
        metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_AGG_POOL_PRUNE)
    }

    /// Default to `SYNC_COMMITTEE_SUBNET_COUNT`.
    fn default_capacity() -> usize {
        SYNC_COMMITTEE_SUBNET_COUNT as usize
    }
}

/// A pool of `Attestation` or `SyncCommitteeContribution` that is specially designed to store
/// "unaggregated" messages from the native aggregation scheme.
///
/// **The `NaiveAggregationPool` does not do any verification. It assumes that all `Attestation`
/// or `SyncCommitteeContribution` objects provided are valid.**
///
/// ## Details
///
/// The pool sorts the items by `slot`, then by `Data`.
///
/// As each item is added it is aggregated with any existing item with the same `Data`. Considering
/// that the pool only accepts attestations or sync contributions with a single
/// signature, there should only ever be a single aggregated `Attestation` for any given
/// `AttestationData` or a single `SyncCommitteeContribution` for any given `SyncContributionData`.
///
/// The pool has a capacity for `SLOTS_RETAINED` slots, when a new `slot` is
/// provided, the oldest slot is dropped and replaced with the new slot. The pool can also be
/// pruned by supplying a `current_slot`; all existing items with a slot lower than
/// `current_slot - SLOTS_RETAINED` will be removed and any future item with a slot lower
/// than that will also be refused. Pruning is done automatically based upon the items it
/// receives and it can be triggered manually.
pub struct NaiveAggregationPool<T>
where
    T: AggregateMap,
    for<'a> <T::Value as AsReference>::Reference<'a>: SlotData,
{
    lowest_permissible_slot: Slot,
    maps: HashMap<Slot, T>,
}

impl<T> Default for NaiveAggregationPool<T>
where
    T: AggregateMap,
    for<'a> <T::Value as AsReference>::Reference<'a>: SlotData,
{
    fn default() -> Self {
        Self {
            lowest_permissible_slot: Slot::new(0),
            maps: HashMap::new(),
        }
    }
}

impl<T> NaiveAggregationPool<T>
where
    T: AggregateMap,
    for<'a> <T::Value as AsReference>::Reference<'a>: SlotData,
{
    /// Insert an item into `self`, aggregating it into the pool.
    ///
    /// The given item must only have one signature and have an
    /// `slot` that is not lower than `self.lowest_permissible_slot`.
    ///
    /// The pool may be pruned if the given item has a slot higher than any
    /// previously seen.
    pub fn insert(
        &mut self,
        item: <T::Value as AsReference>::Reference<'_>,
    ) -> Result<InsertOutcome, Error> {
        let _timer = T::start_insert_timer();
        let slot = item.get_slot();
        let lowest_permissible_slot = self.lowest_permissible_slot;

        // Reject any items that are too old.
        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        let outcome = if let Some(map) = self.maps.get_mut(&slot) {
            map.insert(item)
        } else {
            let _timer = T::start_create_map_timer();
            // To avoid re-allocations, try and determine a rough initial capacity for the new item
            // by obtaining the mean size of all items in earlier epoch.
            let (count, sum) = self
                .maps
                .iter()
                // Only include epochs that are less than the given slot in the average. This should
                // generally avoid including recent epochs that are still "filling up".
                .filter(|(map_slot, _item)| **map_slot < slot)
                .map(|(_slot, map)| map.len())
                .fold((0, 0), |(count, sum), len| (count + 1, sum + len));

            let initial_capacity = sum.checked_div(count).unwrap_or_else(T::default_capacity);

            let mut aggregate_map = T::new(initial_capacity);
            let outcome = aggregate_map.insert(item);
            self.maps.insert(slot, aggregate_map);

            outcome
        };

        self.prune(slot);

        outcome
    }

    /// Returns the total number of items stored in `self`.
    pub fn num_items(&self) -> usize {
        self.maps.values().map(T::len).sum()
    }

    /// Returns an aggregated `T::Value` with the given `T::Data`, if any.
    pub fn get(&self, data: &T::Data) -> Option<T::Value> {
        self.maps
            .get(&data.get_slot())
            .and_then(|map| map.get(data))
    }

    /// Iterate all items in all slots of `self`.
    pub fn iter(&self) -> impl Iterator<Item = &T::Value> {
        self.maps.values().flat_map(|map| map.get_map().values())
    }

    /// Removes any items with a slot lower than `current_slot` and bars any future
    /// items with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&mut self, current_slot: Slot) {
        let _timer = T::start_prune_timer();

        let lowest_permissible_slot = current_slot.saturating_sub(Slot::from(SLOTS_RETAINED));

        // No need to prune if the lowest permissible slot has not changed and the queue length is
        // less than the maximum
        if self.lowest_permissible_slot == lowest_permissible_slot
            && self.maps.len() <= SLOTS_RETAINED
        {
            return;
        }

        self.lowest_permissible_slot = lowest_permissible_slot;

        // Remove any maps that are definitely expired.
        self.maps
            .retain(|slot, _map| *slot >= lowest_permissible_slot);

        // If we have too many maps, remove the lowest amount to ensure we only have
        // `SLOTS_RETAINED` left.
        if self.maps.len() > SLOTS_RETAINED {
            let mut slots = self.maps.keys().copied().collect::<Vec<_>>();
            // Sort is generally pretty slow, however `SLOTS_RETAINED` is quite low so it should be
            // negligible.
            slots.sort_unstable();
            slots
                .into_iter()
                .take(self.maps.len().saturating_sub(SLOTS_RETAINED))
                .for_each(|slot| {
                    self.maps.remove(&slot);
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::BitList;
    use store::BitVector;
    use tree_hash::TreeHash;
    use types::{
        test_utils::{generate_deterministic_keypair, test_random_instance},
        Attestation, AttestationBase, AttestationElectra, Fork, Hash256, SyncCommitteeMessage,
    };

    type E = types::MainnetEthSpec;

    fn get_attestation_base(slot: Slot) -> Attestation<E> {
        let mut a: AttestationBase<E> = test_random_instance();
        a.data.slot = slot;
        a.aggregation_bits = BitList::with_capacity(4).expect("should create bitlist");
        Attestation::Base(a)
    }

    fn get_attestation_electra(slot: Slot) -> Attestation<E> {
        let mut a: AttestationElectra<E> = test_random_instance();
        a.data.slot = slot;
        a.aggregation_bits = BitList::with_capacity(4).expect("should create bitlist");
        a.committee_bits = BitVector::new();
        a.committee_bits
            .set(0, true)
            .expect("should set committee bit");
        Attestation::Electra(a)
    }

    fn get_sync_contribution(slot: Slot) -> SyncCommitteeContribution<E> {
        let mut a: SyncCommitteeContribution<E> = test_random_instance();
        a.slot = slot;
        a.aggregation_bits = BitVector::new();
        a
    }

    fn sign_attestation(a: &mut Attestation<E>, i: usize, genesis_validators_root: Hash256) {
        a.sign(
            &generate_deterministic_keypair(i).sk,
            i,
            &Fork::default(),
            genesis_validators_root,
            &E::default_spec(),
        )
        .expect("should sign attestation");
    }

    fn sign_sync_contribution(
        a: &mut SyncCommitteeContribution<E>,
        i: usize,
        genesis_validators_root: Hash256,
    ) {
        let sync_message = SyncCommitteeMessage::new::<E>(
            a.slot,
            a.beacon_block_root,
            i as u64,
            &generate_deterministic_keypair(i).sk,
            &Fork::default(),
            genesis_validators_root,
            &E::default_spec(),
        );
        let signed_contribution: SyncCommitteeContribution<E> =
            SyncCommitteeContribution::from_message(&sync_message, a.subcommittee_index, i)
                .unwrap();

        a.aggregate(&signed_contribution);
    }

    fn unset_attestation_bit(a: &mut Attestation<E>, i: usize) {
        match a {
            Attestation::Base(ref mut att) => att
                .aggregation_bits
                .set(i, false)
                .expect("should unset aggregation bit"),
            Attestation::Electra(ref mut att) => att
                .aggregation_bits
                .set(i, false)
                .expect("should unset aggregation bit"),
        }
    }

    fn unset_sync_contribution_bit(a: &mut SyncCommitteeContribution<E>, i: usize) {
        a.aggregation_bits
            .set(i, false)
            .expect("should unset aggregation bit")
    }

    fn mutate_attestation_block_root(a: &mut Attestation<E>, block_root: Hash256) {
        a.data_mut().beacon_block_root = block_root
    }

    fn mutate_attestation_slot(a: &mut Attestation<E>, slot: Slot) {
        a.data_mut().slot = slot
    }

    fn attestation_block_root_comparator(a: &Attestation<E>, block_root: Hash256) -> bool {
        a.data().beacon_block_root == block_root
    }

    fn key_from_attestation(a: &Attestation<E>) -> AttestationKey {
        AttestationKey::from_attestation_ref(a.to_ref()).expect("should create attestation key")
    }

    fn mutate_sync_contribution_block_root(
        a: &mut SyncCommitteeContribution<E>,
        block_root: Hash256,
    ) {
        a.beacon_block_root = block_root
    }

    fn mutate_sync_contribution_slot(a: &mut SyncCommitteeContribution<E>, slot: Slot) {
        a.slot = slot
    }

    fn sync_contribution_block_root_comparator(
        a: &SyncCommitteeContribution<E>,
        block_root: Hash256,
    ) -> bool {
        a.beacon_block_root == block_root
    }

    fn key_from_sync_contribution(a: &SyncCommitteeContribution<E>) -> SyncContributionData {
        SyncContributionData::from_contribution(a)
    }

    #[test]
    fn attestation_key_tree_hash_tests() {
        let attestation_base = get_attestation_base(Slot::new(42));
        // for a base attestation, the tree_hash_root() of the key should be the same as the tree_hash_root() of the data
        let attestation_key_base = AttestationKey::from_attestation_ref(attestation_base.to_ref())
            .expect("should create attestation key");
        assert_eq!(
            attestation_key_base.tree_hash_root(),
            attestation_base.data().tree_hash_root()
        );
        let mut attestation_electra = get_attestation_electra(Slot::new(42));
        // for an electra attestation, the tree_hash_root() of the key should be different from the tree_hash_root() of the data
        let attestation_key_electra =
            AttestationKey::from_attestation_ref(attestation_electra.to_ref())
                .expect("should create attestation key");
        assert_ne!(
            attestation_key_electra.tree_hash_root(),
            attestation_electra.data().tree_hash_root()
        );
        // for an electra attestation, the tree_hash_root() of the key should be dependent on which committee bit is set
        let committe_bits = attestation_electra
            .committee_bits_mut()
            .expect("should get committee bits");
        committe_bits
            .set(0, false)
            .expect("should set committee bit");
        committe_bits
            .set(1, true)
            .expect("should set committee bit");
        let new_attestation_key_electra =
            AttestationKey::from_attestation_ref(attestation_electra.to_ref())
                .expect("should create attestation key");
        // this new key should have a different tree_hash_root() than the previous key
        assert_ne!(
            attestation_key_electra.tree_hash_root(),
            new_attestation_key_electra.tree_hash_root()
        );
    }

    macro_rules! test_suite {
        (
            $mod_name: ident,
            $get_method_name: ident,
            $sign_method_name: ident,
            $unset_method_name: ident,
            $block_root_mutator: ident,
            $slot_mutator: ident,
            $block_root_comparator: ident,
            $key_getter: ident,
            $map_type: ident,
            $item_limit: expr
        ) => {
            #[cfg(test)]
            mod $mod_name {
                use super::*;

                #[test]
                fn single_item() {
                    let mut a = $get_method_name(Slot::new(0));

                    let mut pool: NaiveAggregationPool<$map_type<E>> =
                        NaiveAggregationPool::<$map_type<E>>::default();

                    assert_eq!(
                        pool.insert(a.as_reference()),
                        Err(Error::NoAggregationBitsSet),
                        "should not accept item without any signatures"
                    );

                    $sign_method_name(&mut a, 0, Hash256::random());

                    assert_eq!(
                        pool.insert(a.as_reference()),
                        Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                        "should accept new item"
                    );
                    assert_eq!(
                        pool.insert(a.as_reference()),
                        Ok(InsertOutcome::SignatureAlreadyKnown { committee_index: 0 }),
                        "should acknowledge duplicate signature"
                    );

                    let retrieved = pool
                        .get(&$key_getter(&a))
                        .expect("should not error while getting item");
                    assert_eq!(retrieved, a, "retrieved item should equal the one inserted");

                    $sign_method_name(&mut a, 1, Hash256::random());

                    assert_eq!(
                        pool.insert(a.as_reference()),
                        Err(Error::MoreThanOneAggregationBitSet(2)),
                        "should not accept item with multiple signatures"
                    );
                }

                #[test]
                fn multiple_items() {
                    let mut a_0 = $get_method_name(Slot::new(0));
                    let mut a_1 = a_0.clone();

                    let genesis_validators_root = Hash256::random();
                    $sign_method_name(&mut a_0, 0, genesis_validators_root);
                    $sign_method_name(&mut a_1, 1, genesis_validators_root);

                    let mut pool: NaiveAggregationPool<$map_type<E>> =
                        NaiveAggregationPool::<$map_type<E>>::default();

                    assert_eq!(
                        pool.insert(a_0.as_reference()),
                        Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                        "should accept a_0"
                    );
                    assert_eq!(
                        pool.insert(a_1.as_reference()),
                        Ok(InsertOutcome::SignatureAggregated { committee_index: 1 }),
                        "should accept a_1"
                    );

                    let retrieved = pool
                        .get(&$key_getter(&a_0))
                        .expect("should not error while getting attestation");

                    let mut a_01 = a_0.clone();
                    a_01.aggregate(a_1.as_reference());

                    assert_eq!(retrieved, a_01, "retrieved item should be aggregated");

                    /*
                     * Throw different data in there and ensure it isn't aggregated
                     */

                    let mut a_different = a_0.clone();
                    let different_root = Hash256::from_low_u64_be(1337);
                    $unset_method_name(&mut a_different, 0);
                    $sign_method_name(&mut a_different, 2, genesis_validators_root);
                    assert!(!$block_root_comparator(&a_different, different_root));
                    $block_root_mutator(&mut a_different, different_root);

                    assert_eq!(
                        pool.insert(a_different.as_reference()),
                        Ok(InsertOutcome::NewItemInserted { committee_index: 2 }),
                        "should accept a_different"
                    );

                    assert_eq!(
                        pool.get(&$key_getter(&a_0))
                            .expect("should not error while getting item"),
                        retrieved,
                        "should not have aggregated different items with different data"
                    );
                }

                #[test]
                fn auto_pruning_item() {
                    let mut base = $get_method_name(Slot::new(0));
                    $sign_method_name(&mut base, 0, Hash256::random());

                    let mut pool: NaiveAggregationPool<$map_type<E>> =
                        NaiveAggregationPool::<$map_type<E>>::default();

                    for i in 0..SLOTS_RETAINED * 2 {
                        let slot = Slot::from(i);
                        let mut a = base.clone();
                        $slot_mutator(&mut a, slot);

                        assert_eq!(
                            pool.insert(a.as_reference()),
                            Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                            "should accept new item"
                        );

                        if i < SLOTS_RETAINED {
                            let len = i + 1;
                            assert_eq!(pool.maps.len(), len, "the pool should have length {}", len);
                        } else {
                            assert_eq!(
                                pool.maps.len(),
                                SLOTS_RETAINED,
                                "the pool should have length SLOTS_RETAINED"
                            );

                            let mut pool_slots = pool
                                .maps
                                .iter()
                                .map(|(slot, _map)| *slot)
                                .collect::<Vec<_>>();

                            pool_slots.sort_unstable();

                            for (j, pool_slot) in pool_slots.iter().enumerate() {
                                let expected_slot = slot - (SLOTS_RETAINED - 1 - j) as u64;
                                assert_eq!(
                                    *pool_slot, expected_slot,
                                    "the slot of the map should be {}",
                                    expected_slot
                                )
                            }
                        }
                    }
                }

                #[test]
                fn max_items() {
                    let mut base = $get_method_name(Slot::new(0));
                    $sign_method_name(&mut base, 0, Hash256::random());

                    let mut pool: NaiveAggregationPool<$map_type<E>> =
                        NaiveAggregationPool::<$map_type<E>>::default();

                    for i in 0..=$item_limit {
                        let mut a = base.clone();
                        $block_root_mutator(&mut a, Hash256::from_low_u64_be(i as u64));

                        if i < $item_limit {
                            assert_eq!(
                                pool.insert(a.as_reference()),
                                Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                                "should accept item below limit"
                            );
                        } else {
                            assert_eq!(
                                pool.insert(a.as_reference()),
                                Err(Error::ReachedMaxItemsPerSlot($item_limit)),
                                "should not accept item above limit"
                            );
                        }
                    }
                }
            }
        };
    }

    test_suite! {
        attestation_tests_base,
        get_attestation_base,
        sign_attestation,
        unset_attestation_bit,
        mutate_attestation_block_root,
        mutate_attestation_slot,
        attestation_block_root_comparator,
        key_from_attestation,
        AggregatedAttestationMap,
        MAX_ATTESTATIONS_PER_SLOT
    }

    test_suite! {
        attestation_tests_electra,
        get_attestation_electra,
        sign_attestation,
        unset_attestation_bit,
        mutate_attestation_block_root,
        mutate_attestation_slot,
        attestation_block_root_comparator,
        key_from_attestation,
        AggregatedAttestationMap,
        MAX_ATTESTATIONS_PER_SLOT
    }

    test_suite! {
        sync_contribution_tests,
        get_sync_contribution,
        sign_sync_contribution,
        unset_sync_contribution_bit,
        mutate_sync_contribution_block_root,
        mutate_sync_contribution_slot,
        sync_contribution_block_root_comparator,
        key_from_sync_contribution,
        SyncContributionAggregateMap,
        E::sync_committee_size()
    }
}
