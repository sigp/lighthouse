//! Provides two structs that help us filter out attestation gossip from validators that have
//! already published attestations:
//!
//! - `ObservedAttesters`: allows filtering unaggregated attestations from the same validator in
//!   the same epoch.
//! - `ObservedAggregators`: allows filtering aggregated attestations from the same aggregators in
//!   the same epoch
//!
//! Provides an additional two structs that help us filter out sync committee message and
//! contribution gossip from validators that have already published messages this slot:
//!
//! - `ObservedSyncContributors`: allows filtering sync committee messages from the same validator in
//!   the same slot.
//! - `ObservedSyncAggregators`: allows filtering sync committee contributions from the same aggregators in
//!   the same slot and in the same subcommittee.

use crate::types::consts::altair::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE;
use bitvec::vec::BitVec;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::marker::PhantomData;
use types::slot_data::SlotData;
use types::{Epoch, EthSpec, Hash256, Slot, Unsigned};

/// The maximum capacity of the `AutoPruningEpochContainer`.
///
/// Fits the next, current and previous epochs. We require the next epoch due to the
/// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`. We require the previous epoch since the specification
/// declares:
///
/// ```ignore
/// aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE
///      >= current_slot >= aggregate.data.slot
/// ```
///
/// This means that during the current epoch we will always accept an attestation
/// from at least one slot in the previous epoch.
pub const MAX_CACHED_EPOCHS: u64 = 3;

pub type ObservedAttesters<E> = AutoPruningEpochContainer<EpochBitfield, E>;
pub type ObservedSyncContributors<E> =
    AutoPruningSlotContainer<SlotSubcommitteeIndex, Hash256, SyncContributorSlotHashSet<E>, E>;
pub type ObservedAggregators<E> = AutoPruningEpochContainer<EpochHashSet, E>;
pub type ObservedSyncAggregators<E> =
    AutoPruningSlotContainer<SlotSubcommitteeIndex, (), SyncAggregatorSlotHashSet, E>;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochTooLow {
        epoch: Epoch,
        lowest_permissible_epoch: Epoch,
    },
    SlotTooLow {
        slot: Slot,
        lowest_permissible_slot: Slot,
    },
    /// We have reached the maximum number of unique items that can be observed in a slot.
    /// This is a DoS protection function.
    ReachedMaxObservationsPerSlot(usize),
    /// The function to obtain a set index failed, this is an internal error.
    ValidatorIndexTooHigh(usize),
}

/// Implemented on an item in an `AutoPruningContainer`.
pub trait Item<T> {
    /// Instantiate `Self` with the given `capacity`.
    fn with_capacity(capacity: usize) -> Self;

    /// The default capacity for self. Used when we can't guess a reasonable size.
    fn default_capacity() -> usize;

    /// Returns the allocated size of `self`, measured by validator indices.
    fn len(&self) -> usize;

    /// Returns the number of validators that have been observed by `self`.
    fn validator_count(&self) -> usize;

    /// Store `validator_index` and `value` in `self`.
    fn insert(&mut self, validator_index: usize, value: T) -> bool;

    /// Returns `Some(T)` if there is an entry for `validator_index`.
    fn get(&self, validator_index: usize) -> Option<T>;
}

/// Stores a `BitVec` that represents which validator indices have attested or sent sync committee
/// signatures during an epoch.
pub struct EpochBitfield {
    bitfield: BitVec,
}

impl Item<()> for EpochBitfield {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bitfield: BitVec::with_capacity(capacity),
        }
    }

    /// Uses a default size that equals the number of genesis validators.
    fn default_capacity() -> usize {
        16_384
    }

    fn len(&self) -> usize {
        self.bitfield.len()
    }

    fn validator_count(&self) -> usize {
        self.bitfield.iter().filter(|bit| **bit).count()
    }

    fn insert(&mut self, validator_index: usize, _value: ()) -> bool {
        self.bitfield
            .get_mut(validator_index)
            .map(|mut bit| {
                if *bit {
                    true
                } else {
                    *bit = true;
                    false
                }
            })
            .unwrap_or_else(|| {
                self.bitfield
                    .resize(validator_index.saturating_add(1), false);
                if let Some(mut bit) = self.bitfield.get_mut(validator_index) {
                    *bit = true;
                }
                false
            })
    }

    fn get(&self, validator_index: usize) -> Option<()> {
        self.bitfield
            .get(validator_index)
            .map_or(false, |bit| *bit)
            .then_some(())
    }
}

/// Stores a `HashSet` of which validator indices have created an aggregate during an
/// epoch.
pub struct EpochHashSet {
    set: HashSet<usize>,
}

impl Item<()> for EpochHashSet {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            set: HashSet::with_capacity(capacity),
        }
    }

    /// Defaults to the target number of aggregators per committee (16) multiplied by the expected
    /// max committee count (64).
    fn default_capacity() -> usize {
        16 * 64
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn validator_count(&self) -> usize {
        self.set.len()
    }

    /// Inserts the `validator_index` in the set. Returns `true` if the `validator_index` was
    /// already in the set.
    fn insert(&mut self, validator_index: usize, _value: ()) -> bool {
        !self.set.insert(validator_index)
    }

    /// Returns `true` if the `validator_index` is in the set.
    fn get(&self, validator_index: usize) -> Option<()> {
        self.set.contains(&validator_index).then_some(())
    }
}

/// Stores a `HashSet` of which validator indices have created a sync aggregate during a
/// slot.
pub struct SyncContributorSlotHashSet<E> {
    map: HashMap<usize, Hash256>,
    phantom: PhantomData<E>,
}

impl<E: EthSpec> Item<Hash256> for SyncContributorSlotHashSet<E> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            phantom: PhantomData,
        }
    }

    /// Defaults to the `SYNC_SUBCOMMITTEE_SIZE`.
    fn default_capacity() -> usize {
        E::sync_subcommittee_size()
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn validator_count(&self) -> usize {
        self.map.len()
    }

    /// Inserts the `validator_index` in the set. Returns `true` if the `validator_index` was
    /// already in the set.
    fn insert(&mut self, validator_index: usize, beacon_block_root: Hash256) -> bool {
        self.map
            .insert(validator_index, beacon_block_root)
            .is_some()
    }

    /// Returns `true` if the `validator_index` is in the set.
    fn get(&self, validator_index: usize) -> Option<Hash256> {
        self.map.get(&validator_index).copied()
    }
}

/// Stores a `HashSet` of which validator indices have created a sync aggregate during a
/// slot.
pub struct SyncAggregatorSlotHashSet {
    set: HashSet<usize>,
}

impl Item<()> for SyncAggregatorSlotHashSet {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            set: HashSet::with_capacity(capacity),
        }
    }

    /// Defaults to the `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE`.
    fn default_capacity() -> usize {
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE as usize
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn validator_count(&self) -> usize {
        self.set.len()
    }

    /// Inserts the `validator_index` in the set. Returns `true` if the `validator_index` was
    /// already in the set.
    fn insert(&mut self, validator_index: usize, _value: ()) -> bool {
        !self.set.insert(validator_index)
    }

    /// Returns `true` if the `validator_index` is in the set.
    fn get(&self, validator_index: usize) -> Option<()> {
        self.set.contains(&validator_index).then_some(())
    }
}

/// A container that stores some number of `T` items.
///
/// This container is "auto-pruning" since it gets an idea of the current slot by which
/// attestations are provided to it and prunes old entries based upon that. For example, if
/// `Self::max_capacity == 32` and an attestation with `a.data.target.epoch` is supplied, then all
/// attestations with an epoch prior to `a.data.target.epoch - 32` will be cleared from the cache.
///
/// `T` should be set to a `EpochBitfield` or `EpochHashSet`.
pub struct AutoPruningEpochContainer<T, E: EthSpec> {
    lowest_permissible_epoch: Epoch,
    items: HashMap<Epoch, T>,
    _phantom: PhantomData<E>,
}

impl<T, E: EthSpec> Default for AutoPruningEpochContainer<T, E> {
    fn default() -> Self {
        Self {
            lowest_permissible_epoch: Epoch::new(0),
            items: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<T: Item<()>, E: EthSpec> AutoPruningEpochContainer<T, E> {
    /// Observe that `validator_index` has produced attestation `a`. Returns `Ok(true)` if `a` has
    /// previously been observed for `validator_index`.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `a.data.target.slot` is earlier than `self.lowest_permissible_slot`.
    pub fn observe_validator(
        &mut self,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<bool, Error> {
        self.sanitize_request(epoch, validator_index)?;

        self.prune(epoch);

        if let Some(item) = self.items.get_mut(&epoch) {
            Ok(item.insert(validator_index, ()))
        } else {
            // To avoid re-allocations, try and determine a rough initial capacity for the new item
            // by obtaining the mean size of all items in earlier epoch.
            let (count, sum) = self
                .items
                .iter()
                // Only include epochs that are less than the given slot in the average. This should
                // generally avoid including recent epochs that are still "filling up".
                .filter(|(item_epoch, _item)| **item_epoch < epoch)
                .map(|(_epoch, item)| item.len())
                .fold((0, 0), |(count, sum), len| (count + 1, sum + len));

            let initial_capacity = sum.checked_div(count).unwrap_or_else(T::default_capacity);

            let mut item = T::with_capacity(initial_capacity);
            item.insert(validator_index, ());
            self.items.insert(epoch, item);

            Ok(false)
        }
    }

    /// Returns `Ok(true)` if the `validator_index` has produced an attestation conflicting with
    /// `a`.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `a.data.target.slot` is earlier than `self.lowest_permissible_slot`.
    pub fn validator_has_been_observed(
        &self,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<bool, Error> {
        self.sanitize_request(epoch, validator_index)?;

        let exists = self
            .items
            .get(&epoch)
            .map_or(false, |item| item.get(validator_index).is_some());

        Ok(exists)
    }

    /// Returns the number of validators that have been observed at the given `epoch`. Returns
    /// `None` if `self` does not have a cache for that epoch.
    pub fn observed_validator_count(&self, epoch: Epoch) -> Option<usize> {
        self.items.get(&epoch).map(|item| item.validator_count())
    }

    fn sanitize_request(&self, epoch: Epoch, validator_index: usize) -> Result<(), Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        let lowest_permissible_epoch = self.lowest_permissible_epoch;
        if epoch < lowest_permissible_epoch {
            return Err(Error::EpochTooLow {
                epoch,
                lowest_permissible_epoch,
            });
        }

        Ok(())
    }

    /// The maximum number of epochs stored in `self`.
    fn max_capacity(&self) -> u64 {
        MAX_CACHED_EPOCHS
    }

    /// Updates `self` with the current epoch, removing all attestations that become expired
    /// relative to `Self::max_capacity`.
    ///
    /// Also sets `self.lowest_permissible_epoch` with relation to `current_epoch` and
    /// `Self::max_capacity`.
    pub fn prune(&mut self, current_epoch: Epoch) {
        let lowest_permissible_epoch =
            current_epoch.saturating_sub(self.max_capacity().saturating_sub(1));

        self.lowest_permissible_epoch = lowest_permissible_epoch;

        self.items
            .retain(|epoch, _item| *epoch >= lowest_permissible_epoch);
    }

    #[allow(dead_code)]
    /// Returns the `lowest_permissible_epoch`. Used in tests.
    pub(crate) fn get_lowest_permissible(&self) -> Epoch {
        self.lowest_permissible_epoch
    }

    /// Returns `true` if the given `index` has been stored in `self` at `epoch`.
    ///
    /// This is useful for doppelganger detection.
    pub fn index_seen_at_epoch(&self, index: usize, epoch: Epoch) -> bool {
        self.items
            .get(&epoch)
            .map(|item| item.get(index).is_some())
            .unwrap_or(false)
    }
}

/// A container that stores some number of `V` items.
///
/// This container is "auto-pruning" since it gets an idea of the current slot by which
/// sync contributions are provided to it and prunes old entries based upon that. For example, if
/// `Self::max_capacity == 3` and an attestation with `data.slot` is supplied, then all
/// sync contributions with an epoch prior to `data.slot - 3` will be cleared from the cache.
///
/// `V` should be set to a `SyncAggregatorSlotHashSet` or a `SyncContributorSlotHashSet`.
pub struct AutoPruningSlotContainer<K: SlotData + Eq + Hash, S, V, E: EthSpec> {
    lowest_permissible_slot: Slot,
    items: HashMap<K, V>,
    _phantom_e: PhantomData<E>,
    _phantom_s: PhantomData<S>,
}

impl<K: SlotData + Eq + Hash, S, V, E: EthSpec> Default for AutoPruningSlotContainer<K, S, V, E> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: Slot::new(0),
            items: HashMap::new(),
            _phantom_e: PhantomData,
            _phantom_s: PhantomData,
        }
    }
}

impl<K: SlotData + Eq + Hash + Copy, S, V: Item<S>, E: EthSpec>
    AutoPruningSlotContainer<K, S, V, E>
{
    /// Observes the given `value` for the given `validator_index`.
    ///
    /// The `override_observation` function is supplied `previous_observation`
    /// and `value`. If it returns `true`, then any existing observation will be
    /// overridden.
    ///
    /// This function returns `Some` if:
    /// - An observation already existed for the validator, AND,
    /// - The `override_observation` function returned `false`.
    ///
    /// Alternatively, it returns `None` if:
    /// - An observation did not already exist for the given validator, OR,
    /// - The `override_observation` function returned `true`.
    pub fn observe_validator_with_override<F>(
        &mut self,
        key: K,
        validator_index: usize,
        value: S,
        override_observation: F,
    ) -> Result<Option<S>, Error>
    where
        F: Fn(&S, &S) -> bool,
    {
        if let Some(prev_observation) = self.observation_for_validator(key, validator_index)? {
            if override_observation(&prev_observation, &value) {
                self.observe_validator(key, validator_index, value)?;
                Ok(None)
            } else {
                Ok(Some(prev_observation))
            }
        } else {
            self.observe_validator(key, validator_index, value)?;
            Ok(None)
        }
    }

    /// Observe that `validator_index` has produced a sync committee message. Returns `Ok(true)` if
    /// the sync committee message  has previously been observed for `validator_index`.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `key.slot` is earlier than `self.lowest_permissible_slot`.
    pub fn observe_validator(
        &mut self,
        key: K,
        validator_index: usize,
        value: S,
    ) -> Result<bool, Error> {
        let slot = key.get_slot();
        self.sanitize_request(slot, validator_index)?;

        self.prune(slot);

        if let Some(item) = self.items.get_mut(&key) {
            Ok(item.insert(validator_index, value))
        } else {
            // To avoid re-allocations, try and determine a rough initial capacity for the new item
            // by obtaining the mean size of all items in earlier slot.
            let (count, sum) = self
                .items
                .iter()
                // Only include slots that are less than the given slot in the average. This should
                // generally avoid including recent slots that are still "filling up".
                .filter(|(item_key, _item)| item_key.get_slot() < slot)
                .map(|(_, item)| item.len())
                .fold((0, 0), |(count, sum), len| (count + 1, sum + len));

            let initial_capacity = sum.checked_div(count).unwrap_or_else(V::default_capacity);

            let mut item = V::with_capacity(initial_capacity);
            item.insert(validator_index, value);
            self.items.insert(key, item);

            Ok(false)
        }
    }

    // Identical to `Self::observation_for_validator` but discards the
    // observation, simply returning `true` if the validator has been observed
    // at all.
    pub fn validator_has_been_observed(
        &self,
        key: K,
        validator_index: usize,
    ) -> Result<bool, Error> {
        self.observation_for_validator(key, validator_index)
            .map(|observation| observation.is_some())
    }

    /// Returns `Ok(Some)` if the `validator_index` has already produced a
    /// conflicting sync committee message.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `key.slot` is earlier than `self.lowest_permissible_slot`.
    pub fn observation_for_validator(
        &self,
        key: K,
        validator_index: usize,
    ) -> Result<Option<S>, Error> {
        self.sanitize_request(key.get_slot(), validator_index)?;

        let observation = self
            .items
            .get(&key)
            .and_then(|item| item.get(validator_index));

        Ok(observation)
    }

    /// Returns the number of validators that have been observed at the given `slot`. Returns
    /// `None` if `self` does not have a cache for that slot.
    pub fn observed_validator_count(&self, key: K) -> Option<usize> {
        self.items.get(&key).map(|item| item.validator_count())
    }

    fn sanitize_request(&self, slot: Slot, validator_index: usize) -> Result<(), Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        let lowest_permissible_slot = self.lowest_permissible_slot;
        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        Ok(())
    }

    /// The maximum number of slots stored in `self`.
    fn max_capacity(&self) -> u64 {
        // The next, current and previous slots. We require the next slot due to the
        // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
        3
    }

    /// Updates `self` with the current slot, removing all sync committee messages that become expired
    /// relative to `Self::max_capacity`.
    ///
    /// Also sets `self.lowest_permissible_slot` with relation to `current_slot` and
    /// `Self::max_capacity`.
    pub fn prune(&mut self, current_slot: Slot) {
        let lowest_permissible_slot =
            current_slot.saturating_sub(self.max_capacity().saturating_sub(1));

        self.lowest_permissible_slot = lowest_permissible_slot;

        self.items
            .retain(|key, _item| key.get_slot() >= lowest_permissible_slot);
    }

    #[allow(dead_code)]
    /// Returns the `lowest_permissible_slot`. Used in tests.
    pub(crate) fn get_lowest_permissible(&self) -> Slot {
        self.lowest_permissible_slot
    }
}

/// This is used to key information about sync committee aggregators. We require the
/// `subcommittee_index` because it is possible that a validator can aggregate for multiple
/// subcommittees in the same slot.
#[derive(Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord, Debug)]
pub struct SlotSubcommitteeIndex {
    slot: Slot,
    subcommittee_index: u64,
}

impl SlotData for SlotSubcommitteeIndex {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

impl SlotSubcommitteeIndex {
    pub fn new(slot: Slot, subcommittee_index: u64) -> Self {
        Self {
            slot,
            subcommittee_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type E = types::MainnetEthSpec;

    #[test]
    fn value_storage() {
        type Container = AutoPruningSlotContainer<Slot, Hash256, SyncContributorSlotHashSet<E>, E>;

        let mut store: Container = <_>::default();
        let key = Slot::new(0);
        let validator_index = 0;
        let value = Hash256::zero();

        // Assert there is no entry.
        assert!(store
            .observation_for_validator(key, validator_index)
            .unwrap()
            .is_none());
        assert!(!store
            .validator_has_been_observed(key, validator_index)
            .unwrap());

        // Add an entry.
        assert!(!store
            .observe_validator(key, validator_index, value)
            .unwrap());

        // Assert there is a correct entry.
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            Some(value)
        );
        assert!(store
            .validator_has_been_observed(key, validator_index)
            .unwrap());

        let alternate_value = Hash256::from_low_u64_be(1);

        // Assert that override false does not override.
        assert_eq!(
            store
                .observe_validator_with_override(key, validator_index, alternate_value, |_, _| {
                    false
                })
                .unwrap(),
            Some(value)
        );

        // Assert that override true overrides and acts as if there was never an
        // entry there.
        assert_eq!(
            store
                .observe_validator_with_override(key, validator_index, alternate_value, |_, _| {
                    true
                })
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            Some(alternate_value)
        );

        // Reset the store.
        let mut store: Container = <_>::default();

        // Asset that a new entry with override = false is inserted
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .observe_validator_with_override(key, validator_index, value, |_, _| { false })
                .unwrap(),
            None,
        );
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            Some(value)
        );

        // Reset the store.
        let mut store: Container = <_>::default();

        // Asset that a new entry with override = true is inserted
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .observe_validator_with_override(key, validator_index, value, |_, _| { true })
                .unwrap(),
            None,
        );
        assert_eq!(
            store
                .observation_for_validator(key, validator_index)
                .unwrap(),
            Some(value)
        );
    }

    macro_rules! test_suite_epoch {
        ($mod_name: ident, $type: ident) => {
            #[cfg(test)]
            mod $mod_name {
                use super::*;

                fn single_period_test(store: &mut $type<E>, period: Epoch) {
                    let validator_indices = [0, 1, 2, 3, 5, 6, 7, 18, 22];

                    for &i in &validator_indices {
                        assert_eq!(
                            store.validator_has_been_observed(period, i),
                            Ok(false),
                            "should indicate an unknown item is unknown"
                        );
                        assert_eq!(
                            store.observe_validator(period, i),
                            Ok(false),
                            "should observe new item"
                        );
                    }

                    for &i in &validator_indices {
                        assert_eq!(
                            store.validator_has_been_observed(period, i),
                            Ok(true),
                            "should indicate a known item is known"
                        );
                        assert_eq!(
                            store.observe_validator(period, i),
                            Ok(true),
                            "should acknowledge an existing item"
                        );
                    }
                }

                #[test]
                fn single_period() {
                    let mut store = $type::default();

                    single_period_test(&mut store, Epoch::new(0));

                    assert_eq!(store.items.len(), 1, "should have a single bitfield stored");
                }

                #[test]
                fn mulitple_contiguous_periods() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    for i in 0..max_cap * 3 {
                        let period = Epoch::new(i);

                        single_period_test(&mut store, period);

                        /*
                         * Ensure that the number of sets is correct.
                         */

                        if i < max_cap {
                            assert_eq!(
                                store.items.len(),
                                i as usize + 1,
                                "should have a {} items stored",
                                i + 1
                            );
                        } else {
                            assert_eq!(
                                store.items.len(),
                                max_cap as usize,
                                "should have max_capacity items stored"
                            );
                        }

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _set)| *period)
                            .collect::<Vec<_>>();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        store_periods.sort_unstable();

                        let expected_periods = (i.saturating_sub(max_cap - 1)..=i)
                            .map(Epoch::new)
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods, store_periods,
                            "should have expected slots"
                        );
                    }
                }

                #[test]
                fn mulitple_non_contiguous_periods() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    let to_skip = [1_u64, 3, 4, 5];
                    let periods = (0..max_cap * 3)
                        .into_iter()
                        .filter(|i| !to_skip.contains(i))
                        .collect::<Vec<_>>();

                    for &i in &periods {
                        if to_skip.contains(&i) {
                            continue;
                        }

                        let period = Epoch::from(i);

                        single_period_test(&mut store, period);

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _)| *period)
                            .collect::<Vec<_>>();

                        store_periods.sort_unstable();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        let lowest = store.get_lowest_permissible().as_u64();
                        let highest = period.as_u64();
                        let expected_periods = (lowest..=highest)
                            .filter(|i| !to_skip.contains(i))
                            .map(Epoch::new)
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods,
                            &store_periods[..],
                            "should have expected epochs"
                        );
                    }
                }
            }
        };
    }

    test_suite_epoch!(observed_attesters, ObservedAttesters);
    test_suite_epoch!(observed_aggregators, ObservedAggregators);

    macro_rules! test_suite_slot {
        ($mod_name: ident, $type: ident, $value: expr) => {
            #[cfg(test)]
            mod $mod_name {
                use super::*;

                fn single_period_test(store: &mut $type<E>, key: SlotSubcommitteeIndex) {
                    let validator_indices = [0, 1, 2, 3, 5, 6, 7, 18, 22];

                    for &i in &validator_indices {
                        assert_eq!(
                            store.validator_has_been_observed(key, i),
                            Ok(false),
                            "should indicate an unknown item is unknown"
                        );
                        assert_eq!(
                            store.observe_validator(key, i, $value),
                            Ok(false),
                            "should observe new item"
                        );
                    }

                    for &i in &validator_indices {
                        assert_eq!(
                            store.validator_has_been_observed(key, i),
                            Ok(true),
                            "should indicate a known item is known"
                        );
                        assert_eq!(
                            store.observe_validator(key, i, $value),
                            Ok(true),
                            "should acknowledge an existing item"
                        );
                    }
                }

                #[test]
                fn single_period() {
                    let mut store = $type::default();

                    single_period_test(&mut store, SlotSubcommitteeIndex::new(Slot::new(0), 0));

                    assert_eq!(store.items.len(), 1, "should have a single bitfield stored");
                }

                #[test]
                fn single_period_multiple_subcommittees() {
                    let mut store = $type::default();

                    single_period_test(&mut store, SlotSubcommitteeIndex::new(Slot::new(0), 0));
                    single_period_test(&mut store, SlotSubcommitteeIndex::new(Slot::new(0), 1));
                    single_period_test(&mut store, SlotSubcommitteeIndex::new(Slot::new(0), 2));

                    assert_eq!(store.items.len(), 3, "should have three hash sets stored");
                }

                #[test]
                fn mulitple_contiguous_periods_same_subcommittee() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    for i in 0..max_cap * 3 {
                        let period = SlotSubcommitteeIndex::new(Slot::new(i), 0);

                        single_period_test(&mut store, period);

                        /*
                         * Ensure that the number of sets is correct.
                         */

                        if i < max_cap {
                            assert_eq!(
                                store.items.len(),
                                i as usize + 1,
                                "should have a {} items stored",
                                i + 1
                            );
                        } else {
                            assert_eq!(
                                store.items.len(),
                                max_cap as usize,
                                "should have max_capacity items stored"
                            );
                        }

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _set)| *period)
                            .collect::<Vec<_>>();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        store_periods.sort_unstable();

                        let expected_periods = (i.saturating_sub(max_cap - 1)..=i)
                            .map(|i| SlotSubcommitteeIndex::new(Slot::new(i), 0))
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods, store_periods,
                            "should have expected slots"
                        );
                    }
                }

                #[test]
                fn mulitple_non_contiguous_periods_same_subcommitte() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    let to_skip = [1_u64, 3, 4, 5];
                    let periods = (0..max_cap * 3)
                        .into_iter()
                        .filter(|i| !to_skip.contains(i))
                        .collect::<Vec<_>>();

                    for &i in &periods {
                        if to_skip.contains(&i) {
                            continue;
                        }

                        let period = SlotSubcommitteeIndex::new(Slot::from(i), 0);

                        single_period_test(&mut store, period);

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _)| *period)
                            .collect::<Vec<_>>();

                        store_periods.sort_unstable();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        let lowest = store.get_lowest_permissible().as_u64();
                        let highest = period.slot.as_u64();
                        let expected_periods = (lowest..=highest)
                            .filter(|i| !to_skip.contains(i))
                            .map(|i| SlotSubcommitteeIndex::new(Slot::new(i), 0))
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods,
                            &store_periods[..],
                            "should have expected epochs"
                        );
                    }
                }

                #[test]
                fn mulitple_contiguous_periods_different_subcommittee() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    for i in 0..max_cap * 3 {
                        let period = SlotSubcommitteeIndex::new(Slot::new(i), i);

                        single_period_test(&mut store, period);

                        /*
                         * Ensure that the number of sets is correct.
                         */

                        if i < max_cap {
                            assert_eq!(
                                store.items.len(),
                                i as usize + 1,
                                "should have a {} items stored",
                                i + 1
                            );
                        } else {
                            assert_eq!(
                                store.items.len(),
                                max_cap as usize,
                                "should have max_capacity items stored"
                            );
                        }

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _set)| *period)
                            .collect::<Vec<_>>();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        store_periods.sort_unstable();

                        let expected_periods = (i.saturating_sub(max_cap - 1)..=i)
                            .map(|i| SlotSubcommitteeIndex::new(Slot::new(i), i))
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods, store_periods,
                            "should have expected slots"
                        );
                    }
                }

                #[test]
                fn mulitple_non_contiguous_periods_different_subcommitte() {
                    let mut store = $type::default();
                    let max_cap = store.max_capacity();

                    let to_skip = [1_u64, 3, 4, 5];
                    let periods = (0..max_cap * 3)
                        .into_iter()
                        .filter(|i| !to_skip.contains(i))
                        .collect::<Vec<_>>();

                    for &i in &periods {
                        if to_skip.contains(&i) {
                            continue;
                        }

                        let period = SlotSubcommitteeIndex::new(Slot::from(i), i);

                        single_period_test(&mut store, period);

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_periods = store
                            .items
                            .iter()
                            .map(|(period, _)| *period)
                            .collect::<Vec<_>>();

                        store_periods.sort_unstable();

                        assert!(
                            store_periods.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        let lowest = store.get_lowest_permissible().as_u64();
                        let highest = period.slot.as_u64();
                        let expected_periods = (lowest..=highest)
                            .filter(|i| !to_skip.contains(i))
                            .map(|i| SlotSubcommitteeIndex::new(Slot::new(i), i))
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_periods,
                            &store_periods[..],
                            "should have expected epochs"
                        );
                    }
                }
            }
        };
    }
    test_suite_slot!(
        observed_sync_contributors,
        ObservedSyncContributors,
        Hash256::zero()
    );
    test_suite_slot!(observed_sync_aggregators, ObservedSyncAggregators, ());
}
