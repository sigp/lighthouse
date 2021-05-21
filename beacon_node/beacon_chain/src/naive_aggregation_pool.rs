use crate::metrics;
use std::collections::HashMap;
use tree_hash::TreeHash;
use types::attestation::SlotData;
use types::sync_committee_contribution::SyncContributionData;
use types::{Attestation, AttestationData, EthSpec, Hash256, Slot, SyncCommitteeContribution};

type AttestationDataRoot = Hash256;
type SyncDataRoot = Hash256;

/// The number of slots that will be stored in the pool.
///
/// For example, if `SLOTS_RETAINED == 3` and the pool is pruned at slot `6`, then all attestations
/// at slots less than `4` will be dropped and any future attestation with a slot less than `4`
/// will be refused.
const SLOTS_RETAINED: usize = 3;

/// The maximum number of distinct `AttestationData` that will be stored in each slot.
///
/// This is a DoS protection measure.
const MAX_ATTESTATIONS_PER_SLOT: usize = 16_384;

/// The maximum number of distinct `SyncCommitteeData` that will be stored in each slot.
///
/// This is a DoS protection measure.
const MAX_SYNC_CONTRIBUTIONS_PER_SLOT: usize = 16_384;

/// Returned upon successfully inserting an attestation into the pool.
#[derive(Debug, PartialEq)]
pub enum InsertOutcome {
    /// The item had not been seen before and was added to the pool.
    NewItemInserted { committee_index: usize },
    /// A validator signature for the given `attestation.data` was already known. No changes were
    /// made.
    SignatureAlreadyKnown { committee_index: usize },
    /// The `attestation.data` was known, but a signature for the given validator was not yet
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

//FIXME(sean): add docs
pub trait AggregateMap {
    type Key;
    type Value: Clone + SlotData;
    type Data: SlotData;
    fn new(initial_capacity: usize) -> Self;
    fn insert(&mut self, a: &Self::Value) -> Result<InsertOutcome, Error>;
    fn get(&self, data: &Self::Data) -> Option<Self::Value>;
    fn get_map(&self) -> &HashMap<Self::Key, Self::Value>;
    fn get_by_root(&self, root: &Self::Key) -> Option<&Self::Value>;
    fn len(&self) -> usize;
}

/// A collection of `Attestation` objects, keyed by their `attestation.data`. Enforces that all
/// `attestation` are from the same slot.
pub struct AggregatedAttestationMap<E: EthSpec> {
    map: HashMap<AttestationDataRoot, Attestation<E>>,
}

impl<E: EthSpec> AggregateMap for AggregatedAttestationMap<E> {
    type Key = AttestationDataRoot;
    type Value = Attestation<E>;
    type Data = AttestationData;

    /// Create an empty collection with the given `initial_capacity`.
    fn new(initial_capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature.
    fn insert(&mut self, a: &Self::Value) -> Result<InsertOutcome, Error> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_CORE_INSERT);

        let set_bits = a
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

        let attestation_data_root = a.data.tree_hash_root();

        if let Some(existing_attestation) = self.map.get_mut(&attestation_data_root) {
            if existing_attestation
                .aggregation_bits
                .get(committee_index)
                .map_err(|_| Error::InconsistentBitfieldLengths)?
            {
                Ok(InsertOutcome::SignatureAlreadyKnown { committee_index })
            } else {
                let _timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_AGGREGATION);
                existing_attestation.aggregate(a);
                Ok(InsertOutcome::SignatureAggregated { committee_index })
            }
        } else {
            if self.map.len() >= MAX_ATTESTATIONS_PER_SLOT {
                return Err(Error::ReachedMaxItemsPerSlot(MAX_ATTESTATIONS_PER_SLOT));
            }

            self.map.insert(attestation_data_root, a.clone());
            Ok(InsertOutcome::NewItemInserted { committee_index })
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

    /// Returns an aggregated `Attestation` with the given `root`, if any.
    fn get_by_root(&self, root: &Self::Key) -> Option<&Self::Value> {
        self.map.get(root)
    }

    fn len(&self) -> usize {
        self.map.len()
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

    //FIXME(sean): should this accept `SyncCommitteeSignature` instead?
    /// Insert a sync committee signature into `self`, aggregating it into the pool.
    ///
    /// The given sync committee (`a`) must only have one signature.
    fn insert(&mut self, a: &SyncCommitteeContribution<E>) -> Result<InsertOutcome, Error> {
        //FIXME(sean): fix metrics
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_CORE_INSERT);

        let set_bits = a
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

        let sync_data_root = SyncContributionData::from_contribution(a).tree_hash_root();

        if let Some(existing_contribution) = self.map.get_mut(&sync_data_root) {
            if existing_contribution
                .aggregation_bits
                .get(committee_index)
                .map_err(|_| Error::InconsistentBitfieldLengths)?
            {
                Ok(InsertOutcome::SignatureAlreadyKnown { committee_index })
            } else {
                let _timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_AGGREGATION);
                existing_contribution.aggregate(a);
                Ok(InsertOutcome::SignatureAggregated { committee_index })
            }
        } else {
            if self.map.len() >= MAX_SYNC_CONTRIBUTIONS_PER_SLOT {
                return Err(Error::ReachedMaxItemsPerSlot(MAX_SYNC_CONTRIBUTIONS_PER_SLOT));
            }

            self.map.insert(sync_data_root, a.clone());
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

    /// Returns an aggregated `SyncCommitteeContribution` with the given `root`, if any.
    fn get_by_root(&self, root: &SyncDataRoot) -> Option<&SyncCommitteeContribution<E>> {
        self.map.get(root)
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A pool of `Attestation` that is specially designed to store "unaggregated" attestations from
/// the native aggregation scheme.
///
/// **The `NaiveAggregationPool` does not do any signature or attestation verification. It assumes
/// that all `Attestation` objects provided are valid.**
///
/// ## Details
///
/// The pool sorts the `Attestation` by `attestation.data.slot`, then by `attestation.data`.
///
/// As each unaggregated attestation is added it is aggregated with any existing `attestation` with
/// the same `AttestationData`. Considering that the pool only accepts attestations with a single
/// signature, there should only ever be a single aggregated `Attestation` for any given
/// `AttestationData`.
///
/// The pool has a capacity for `SLOTS_RETAINED` slots, when a new `attestation.data.slot` is
/// provided, the oldest slot is dropped and replaced with the new slot. The pool can also be
/// pruned by supplying a `current_slot`; all existing attestations with a slot lower than
/// `current_slot - SLOTS_RETAINED` will be removed and any future attestation with a slot lower
/// than that will also be refused. Pruning is done automatically based upon the attestations it
/// receives and it can be triggered manually.
pub struct NaiveAggregationPool<T: AggregateMap> {
    lowest_permissible_slot: Slot,
    maps: HashMap<Slot, T>,
}

impl<T: AggregateMap> Default for NaiveAggregationPool<T> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: Slot::new(0),
            maps: HashMap::new(),
        }
    }
}

impl<T: AggregateMap> NaiveAggregationPool<T> {
    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature and have an
    /// `attestation.data.slot` that is not lower than `self.lowest_permissible_slot`.
    ///
    /// The pool may be pruned if the given `attestation.data` has a slot higher than any
    /// previously seen.
    pub fn insert(&mut self, item: &T::Value) -> Result<InsertOutcome, Error> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_INSERT);
        let slot = item.get_slot();
        let lowest_permissible_slot = self.lowest_permissible_slot;

        // Reject any attestations that are too old.
        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        let lock_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_MAPS_WRITE_LOCK);
        drop(lock_timer);

        let outcome = if let Some(map) = self.maps.get_mut(&slot) {
            map.insert(item)
        } else {
            let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_CREATE_MAP);
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

            // Use the mainnet default committee size if we can't determine an average.
            let initial_capacity = sum.checked_div(count).unwrap_or(128);

            let mut aggregate_map = T::new(initial_capacity);
            let outcome = aggregate_map.insert(item);
            self.maps.insert(slot, aggregate_map);

            outcome
        };

        self.prune(slot);

        outcome
    }

    /// Returns the total number of attestations stored in `self`.
    pub fn num_items(&self) -> usize {
        self.maps.iter().map(|(_, map)| map.len()).sum()
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    pub fn get(&self, data: &T::Data) -> Option<T::Value> {
        self.maps
            .get(&data.get_slot())
            .and_then(|map| map.get(data))
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    pub fn get_by_slot_and_root(&self, slot: Slot, root: &T::Key) -> Option<T::Value> {
        self.maps
            .get(&slot)
            .and_then(|map| map.get_by_root(root).cloned())
    }

    /// Iterate all attestations in all slots of `self`.
    pub fn iter(&self) -> impl Iterator<Item = &T::Value> {
        self.maps
            .iter()
            .map(|(_slot, map)| map.get_map().iter().map(|(_key, value)| value))
            .flatten()
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&mut self, current_slot: Slot) {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_AGG_POOL_PRUNE);

        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - Slot::from(SLOTS_RETAINED);

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
            let mut slots = self
                .maps
                .iter()
                .map(|(slot, _map)| *slot)
                .collect::<Vec<_>>();
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
    use types::{
        test_utils::{generate_deterministic_keypair, test_random_instance},
        AggregateSignature, Domain, Fork, Hash256, SignedRoot, SyncCommitteeSignature,
    };

    type E = types::MainnetEthSpec;

    fn get_attestation(slot: Slot) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.aggregation_bits = BitList::with_capacity(4).expect("should create bitlist");
        a
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
        let sync_signature = SyncCommitteeSignature::new::<E>(
            a.slot,
            a.beacon_block_root,
            i as u64,
            &generate_deterministic_keypair(i).sk,
            &Fork::default(),
            genesis_validators_root,
            &E::default_spec(),
        );
        let signed_contribution: SyncCommitteeContribution<E> =
            SyncCommitteeContribution::from_signature(&sync_signature, a.subcommittee_index, i)
                .unwrap();

        a.aggregate(&signed_contribution);
    }

    fn unset_attestation_bit(a: &mut Attestation<E>, i: usize) {
        a.aggregation_bits
            .set(i, false)
            .expect("should unset aggregation bit")
    }

    fn unset_sync_contribution_bit(a: &mut SyncCommitteeContribution<E>, i: usize) {
        a.aggregation_bits
            .set(i, false)
            .expect("should unset aggregation bit")
    }

    fn mutate_attestation_block_root(a: &mut Attestation<E>, block_root: Hash256) {
        a.data.beacon_block_root = block_root
    }

    fn mutate_attestation_slot(a: &mut Attestation<E>, slot: Slot) {
        a.data.slot = slot
    }

    fn attestation_block_root_comparator(a: &Attestation<E>, block_root:Hash256) -> bool {
        a.data.beacon_block_root == block_root
    }

    fn key_from_attestation(a: &Attestation<E>) -> AttestationData {
        a.data.clone()
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

    fn sync_contribution_block_root_comparator(a: &SyncCommitteeContribution<E>, block_root:Hash256) -> bool {
        a.beacon_block_root == block_root
    }

    fn key_from_sync_contribution(a: &SyncCommitteeContribution<E>) -> SyncContributionData {
        SyncContributionData::from_contribution(&a)
    }

    macro_rules! test_suite {
        ($mod_name: ident, $get_method_name: ident, $sign_method_name: ident, $unset_method_name: ident, $block_root_mutator: ident, $slot_mutator: ident, $block_root_comparator: ident, $key_getter: ident, $map_type: ident, $item_limit: ident) => {
            #[cfg(test)]
            mod $mod_name {
                use super::*;

                #[test]
                fn single_item() {
                    let mut a = $get_method_name(Slot::new(0));

                    let mut pool: NaiveAggregationPool<$map_type<E>> =
                        NaiveAggregationPool::default();

                    assert_eq!(
                        pool.insert(&a),
                        Err(Error::NoAggregationBitsSet),
                        "should not accept item without any signatures"
                    );

                    $sign_method_name(&mut a, 0, Hash256::random());

                    assert_eq!(
                        pool.insert(&a),
                        Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                        "should accept new item"
                    );
                    assert_eq!(
                        pool.insert(&a),
                        Ok(InsertOutcome::SignatureAlreadyKnown { committee_index: 0 }),
                        "should acknowledge duplicate signature"
                    );

                    let retrieved = pool
                        .get(&$key_getter(&a))
                        .expect("should not error while getting item");
                    assert_eq!(retrieved, a, "retrieved item should equal the one inserted");

                    $sign_method_name(&mut a, 1, Hash256::random());

                    assert_eq!(
                        pool.insert(&a),
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
                        NaiveAggregationPool::default();

                    assert_eq!(
                        pool.insert(&a_0),
                        Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                        "should accept a_0"
                    );
                    assert_eq!(
                        pool.insert(&a_1),
                        Ok(InsertOutcome::SignatureAggregated { committee_index: 1 }),
                        "should accept a_1"
                    );

                    let retrieved = pool
                        .get(&$key_getter(&a_0))
                        .expect("should not error while getting attestation");

                    let mut a_01 = a_0.clone();
                    a_01.aggregate(&a_1);

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
                        pool.insert(&a_different),
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
                        NaiveAggregationPool::default();

                    for i in 0..SLOTS_RETAINED * 2 {
                        let slot = Slot::from(i);
                        let mut a = base.clone();
                        $slot_mutator(&mut a, slot);

                        assert_eq!(
                            pool.insert(&a),
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
                        NaiveAggregationPool::default();

                    for i in 0..=$item_limit {
                        let mut a = base.clone();
                        $block_root_mutator(&mut a, Hash256::from_low_u64_be(i as u64));

                        if i < $item_limit {
                            assert_eq!(
                                pool.insert(&a),
                                Ok(InsertOutcome::NewItemInserted { committee_index: 0 }),
                                "should accept item below limit"
                            );
                        } else {
                            assert_eq!(
                                pool.insert(&a),
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
        attestation_tests, get_attestation, sign_attestation, unset_attestation_bit, mutate_attestation_block_root, mutate_attestation_slot, attestation_block_root_comparator, key_from_attestation, AggregatedAttestationMap, MAX_ATTESTATIONS_PER_SLOT
    }
    test_suite! {
        sync_contribution_tests, get_sync_contribution, sign_sync_contribution, unset_sync_contribution_bit, mutate_sync_contribution_block_root, mutate_sync_contribution_slot, sync_contribution_block_root_comparator, key_from_sync_contribution, SyncContributionAggregateMap, MAX_SYNC_CONTRIBUTIONS_PER_SLOT
    }
}
