//! Provides two structs that help us filter out attestation gossip from validators that have
//! already published attestations:
//!
//! - `ObservedAttesters`: allows filtering unaggregated attestations from the same validator in
//!   the same epoch.
//! - `ObservedAggregators`: allows filtering aggregated attestations from the same aggregators in
//!   the same epoch

use bitvec::vec::BitVec;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::{Attestation, Epoch, EthSpec, Unsigned};
use ssz_derive::{Decode, Encode};
use ssz::{Decode as DecodeTrait, Encode as EncodeTrait};

pub type ObservedAttesters<E> = AutoPruningContainer<EpochBitfield, SszEpochBitfield, E>;
pub type ObservedAggregators<E> = AutoPruningContainer<EpochHashSet, SszEpochHashSet, E>;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochTooLow {
        epoch: Epoch,
        lowest_permissible_epoch: Epoch,
    },
    /// We have reached the maximum number of unique `Attestation` that can be observed in a slot.
    /// This is a DoS protection function.
    ReachedMaxObservationsPerSlot(usize),
    /// The function to obtain a set index failed, this is an internal error.
    ValidatorIndexTooHigh(usize),
}

/// Implemented on an item in an `AutoPruningContainer`.
pub trait Item {
    /// Instantiate `Self` with the given `capacity`.
    fn with_capacity(capacity: usize) -> Self;

    /// The default capacity for self. Used when we can't guess a reasonable size.
    fn default_capacity() -> usize;

    /// Returns the allocated size of `self`, measured by validator indices.
    fn len(&self) -> usize;

    /// Returns the number of validators that have been observed by `self`.
    fn validator_count(&self) -> usize;

    /// Store `validator_index` in `self`.
    fn insert(&mut self, validator_index: usize) -> bool;

    /// Returns `true` if `validator_index` has been stored in `self`.
    fn contains(&self, validator_index: usize) -> bool;
}

pub trait SszConverter {
    type Output;

    fn to_ssz_container(&self) -> Self::Output;
    fn from_ssz_container(ssz_container: &Self::Output) -> Result<Self, Error> where Self: std::marker::Sized;
}

/// Stores a `BitVec` that represents which validator indices have attested during an epoch.
#[derive(Encode, Decode, Clone, Debug)]
pub struct SszEpochBitfield {
    bitfield: Vec<bool>,
}
#[derive(Debug)]
pub struct EpochBitfield {
    bitfield: BitVec,
}

impl SszConverter for EpochBitfield {
    type Output = SszEpochBitfield;
    /// Returns a `SszEpochBitfield`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    fn to_ssz_container(&self) -> SszEpochBitfield {
        let bitfield = self
            .bitfield
            .as_slice()
            .to_vec() //suprinsingly BitVec returns a Vec<usize>
            .iter()
            .map(|item| *item != 0) //this converts it to a Vec<bool>, more concise in bytes
            .collect();
        
        SszEpochBitfield {
            bitfield,
        }
    }

    /// Creates a new `Self` from the given `SszEpochBitfield`, restoring `Self` to the same state of
    /// the `Self` that created the `SszEpochBitfield`.
    fn from_ssz_container(ssz_container: &SszEpochBitfield) -> Result<Self, Error> {
        let usize_vec = ssz_container
            .bitfield
            .iter()
            .map(|item| *item as usize)
            .collect();

        let bitfield = BitVec::from_vec(usize_vec);

        Ok(Self { bitfield })
    }
}

impl Item for EpochBitfield {
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

    fn insert(&mut self, validator_index: usize) -> bool {
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

    fn contains(&self, validator_index: usize) -> bool {
        self.bitfield.get(validator_index).map_or(false, |bit| *bit)
    }
}

/// Stores a `HashSet` of which validator indices have created an aggregate attestation during an
/// epoch.
#[derive(Encode,Decode,Clone,Debug)]
pub struct SszEpochHashSet {
    set_capacity: usize,
    set: Vec<usize>,
}
#[derive(Debug)]
pub struct EpochHashSet {    
    set: HashSet<usize>,
}

impl SszConverter for EpochHashSet {
    type Output = SszEpochHashSet;
    /// Returns a `SszEpochHashSet`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    fn to_ssz_container(&self) -> SszEpochHashSet {
        let set_capacity = self.set.capacity();

        use std::iter::FromIterator;
        let set = Vec::from_iter(self.set.clone());

        SszEpochHashSet {
            set_capacity,
            set
        }
    }

    /// Creates a new `Self` from the given `SszEpochHashSet`, restoring `Self` to the same state of
    /// the `Self` that created the `SszEpochHashSet`.
    fn from_ssz_container(ssz_container: &SszEpochHashSet) -> Result<Self, Error> {
        let mut set = HashSet::with_capacity(ssz_container.set_capacity);
        for hash in &ssz_container.set {
            set.insert(*hash);
        }

        Ok(Self { set })
    }
}

impl Item for EpochHashSet {
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
    fn insert(&mut self, validator_index: usize) -> bool {
        !self.set.insert(validator_index)
    }

    /// Returns `true` if the `validator_index` is in the set.
    fn contains(&self, validator_index: usize) -> bool {
        self.set.contains(&validator_index)
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
#[derive(Encode,Decode,Clone)]
pub struct SszAutoPruningContainer<S: EncodeTrait + DecodeTrait> {
    lowest_permissible_epoch: Epoch,
    items_keys: Vec<Epoch>,
    items_values: Vec<S>
}

#[derive(Debug)]
pub struct AutoPruningContainer<T, S, E> 
    where 
     T: Item + SszConverter + SszConverter<Output = S>,
     S: EncodeTrait+DecodeTrait+Clone, 
     E: EthSpec 
{
    lowest_permissible_epoch: RwLock<Epoch>,
    items: RwLock<HashMap<Epoch, T>>,
    _phantom: PhantomData<E>,
    _ssz_phantom: PhantomData<S>,
}

impl<T, S, E> Default for AutoPruningContainer<T, S, E>
    where 
     T: Item + SszConverter + SszConverter<Output = S>,
     S: EncodeTrait+DecodeTrait+Clone, 
     E: EthSpec 
{
    fn default() -> Self {
        Self {
            lowest_permissible_epoch: RwLock::new(Epoch::new(0)),
            items: RwLock::new(HashMap::new()),
            _phantom: PhantomData,
            _ssz_phantom: PhantomData,
        }
    }
}

impl<T, S, E> AutoPruningContainer<T, S, E> 
    where 
     T: Item + SszConverter + SszConverter<Output = S>,
     S: EncodeTrait+DecodeTrait+Clone, 
     E: EthSpec 
{
    /// Observe that `validator_index` has produced attestation `a`. Returns `Ok(true)` if `a` has
    /// previously been observed for `validator_index`.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `a.data.target.slot` is earlier than `self.earliest_permissible_slot`.
    pub fn observe_validator(
        &self,
        a: &Attestation<E>,
        validator_index: usize,
    ) -> Result<bool, Error> {
        self.sanitize_request(a, validator_index)?;

        let epoch = a.data.target.epoch;

        self.prune(epoch);

        let mut items = self.items.write();

        if let Some(item) = items.get_mut(&epoch) {
            Ok(item.insert(validator_index))
        } else {
            // To avoid re-allocations, try and determine a rough initial capacity for the new item
            // by obtaining the mean size of all items in earlier epoch.
            let (count, sum) = items
                .iter()
                // Only include epochs that are less than the given slot in the average. This should
                // generally avoid including recent epochs that are still "filling up".
                .filter(|(item_epoch, _item)| **item_epoch < epoch)
                .map(|(_epoch, item)| item.len())
                .fold((0, 0), |(count, sum), len| (count + 1, sum + len));

            let initial_capacity = sum.checked_div(count).unwrap_or_else(T::default_capacity);

            let mut item = T::with_capacity(initial_capacity);
            item.insert(validator_index);
            items.insert(epoch, item);

            Ok(false)
        }
    }

    /// Returns `Ok(true)` if the `validator_index` has produced an attestation conflicting with
    /// `a`.
    ///
    /// ## Errors
    ///
    /// - `validator_index` is higher than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `a.data.target.slot` is earlier than `self.earliest_permissible_slot`.
    pub fn validator_has_been_observed(
        &self,
        a: &Attestation<E>,
        validator_index: usize,
    ) -> Result<bool, Error> {
        self.sanitize_request(a, validator_index)?;

        let exists = self
            .items
            .read()
            .get(&a.data.target.epoch)
            .map_or(false, |item| item.contains(validator_index));

        Ok(exists)
    }

    /// Returns the number of validators that have been observed at the given `epoch`. Returns
    /// `None` if `self` does not have a cache for that epoch.
    pub fn observed_validator_count(&self, epoch: Epoch) -> Option<usize> {
        self.items
            .read()
            .get(&epoch)
            .map(|item| item.validator_count())
    }

    fn sanitize_request(&self, a: &Attestation<E>, validator_index: usize) -> Result<(), Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        let epoch = a.data.target.epoch;
        let lowest_permissible_epoch: Epoch = *self.lowest_permissible_epoch.read();
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
        // The current epoch and the previous epoch. This is sufficient whilst
        // GOSSIP_CLOCK_DISPARITY is 1/2 a slot or less:
        //
        // https://github.com/ethereum/eth2.0-specs/pull/1706#issuecomment-610151808
        2
    }

    /// Updates `self` with the current epoch, removing all attestations that become expired
    /// relative to `Self::max_capacity`.
    ///
    /// Also sets `self.lowest_permissible_epoch` with relation to `current_epoch` and
    /// `Self::max_capacity`.
    pub fn prune(&self, current_epoch: Epoch) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_epoch = current_epoch - (self.max_capacity().saturating_sub(1));

        *self.lowest_permissible_epoch.write() = lowest_permissible_epoch;

        self.items
            .write()
            .retain(|epoch, _item| *epoch >= lowest_permissible_epoch);
    }

    /// Returns a `SszAutoPruningContainer`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    pub fn to_ssz_container(&self) -> SszAutoPruningContainer<S> {
        let lowest_permissible_epoch = *self.lowest_permissible_epoch.read();

        let items_keys: Vec<Epoch> = self.items.read().keys().cloned().collect();

        let items_values: Vec<S> = self
            .items
            .read()
            .values()
            .map(|item| item.to_ssz_container())
            .collect();

        SszAutoPruningContainer::<S> {
            lowest_permissible_epoch,
            items_keys,
            items_values,
        }
    }

    /// Creates a new `Self` from the given `SszAutoPruningContainer`, restoring `Self` to the same state of
    /// the `Self` that created the `SszAutoPruningContainer`.
    pub fn from_ssz_container(ssz_container: &SszAutoPruningContainer<S>) -> Result<Self, Error>  {
        let lowest_permissible_epoch = RwLock::new(ssz_container.lowest_permissible_epoch);

        let keys = ssz_container.items_keys.clone();

        let translated_values = ssz_container.items_values
            .clone()
            .iter()
            .map(|item| <T>::from_ssz_container(item))
            .collect();

        let values: Vec<T> = match translated_values {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let items: HashMap<Epoch, T> = 
            keys.into_iter().zip(values.into_iter()).collect();

        Ok(Self {
            lowest_permissible_epoch,
            items: RwLock::new(items),
            _phantom: PhantomData,
            _ssz_phantom: PhantomData,
        })
    }
}

impl<T,S,E: EthSpec> PartialEq<AutoPruningContainer<T,S,E>> for AutoPruningContainer<T,S,E> 
    where 
    T: Item + SszConverter + SszConverter<Output = S>,
    S: EncodeTrait+DecodeTrait+Clone, 
    E: EthSpec 
{
    fn eq(&self, other: &AutoPruningContainer<T,S,E>) -> bool {
        (*self.lowest_permissible_epoch.read() == *other.lowest_permissible_epoch.read())
            && ((*self.items.read()).keys().len() == (*other.items.read()).keys().len())
            && ((*self.items.read()).values().len() == (*other.items.read()).values().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_suite {
        ($mod_name: ident, $type: ident) => {
            #[cfg(test)]
            mod $mod_name {
                use super::*;
                use types::test_utils::test_random_instance;

                type E = types::MainnetEthSpec;

                fn get_attestation(epoch: Epoch) -> Attestation<E> {
                    let mut a: Attestation<E> = test_random_instance();
                    a.data.target.epoch = epoch;
                    a
                }

                fn single_epoch_test(store: &$type<E>, epoch: Epoch) {
                    let attesters = [0, 1, 2, 3, 5, 6, 7, 18, 22];
                    let a = &get_attestation(epoch);

                    for &i in &attesters {
                        assert_eq!(
                            store.validator_has_been_observed(a, i),
                            Ok(false),
                            "should indicate an unknown attestation is unknown"
                        );
                        assert_eq!(
                            store.observe_validator(a, i),
                            Ok(false),
                            "should observe new attestation"
                        );
                    }

                    for &i in &attesters {
                        assert_eq!(
                            store.validator_has_been_observed(a, i),
                            Ok(true),
                            "should indicate a known attestation is known"
                        );
                        assert_eq!(
                            store.observe_validator(a, i),
                            Ok(true),
                            "should acknowledge an existing attestation"
                        );
                    }
                }

                #[test]
                fn single_epoch_multiple_attesters_round_trip() {
                    let store = $type::default();
                    let epoch = Epoch::new(0);
                    for i in 1..5 {
                        let attestation = &get_attestation(epoch);
                        store.observe_validator(attestation, i).expect("should accept attestation");
                    }
                    
                    let bytes = store.to_ssz_container().as_ssz_bytes();

                    assert_eq!(
                        Ok(store),
                        $type::from_ssz_container(
                            &SszAutoPruningContainer::from_ssz_bytes(&bytes).expect("should decode")
                        ),
                        "should encode/decode to/from SSZ container/bytes"
                    )
                }

                #[test]
                fn single_epoch() {
                    let store = $type::default();

                    single_epoch_test(&store, Epoch::new(0));

                    assert_eq!(
                        store.items.read().len(),
                        1,
                        "should have a single bitfield stored"
                    );
                }

                #[test]
                fn mulitple_contiguous_epochs() {
                    let store = $type::default();
                    let max_cap = store.max_capacity();

                    for i in 0..max_cap * 3 {
                        let epoch = Epoch::new(i);

                        single_epoch_test(&store, epoch);

                        /*
                         * Ensure that the number of sets is correct.
                         */

                        if i < max_cap {
                            assert_eq!(
                                store.items.read().len(),
                                i as usize + 1,
                                "should have a {} items stored",
                                i + 1
                            );
                        } else {
                            assert_eq!(
                                store.items.read().len(),
                                max_cap as usize,
                                "should have max_capacity items stored"
                            );
                        }

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_epochs = store
                            .items
                            .read()
                            .iter()
                            .map(|(epoch, _set)| *epoch)
                            .collect::<Vec<_>>();

                        assert!(
                            store_epochs.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        store_epochs.sort_unstable();

                        let expected_epochs = (i.saturating_sub(max_cap - 1)..=i)
                            .map(Epoch::new)
                            .collect::<Vec<_>>();

                        assert_eq!(expected_epochs, store_epochs, "should have expected slots");
                    }
                }

                #[test]
                fn mulitple_non_contiguous_epochs() {
                    let store = $type::default();
                    let max_cap = store.max_capacity();

                    let to_skip = vec![1_u64, 3, 4, 5];
                    let epochs = (0..max_cap * 3)
                        .into_iter()
                        .filter(|i| !to_skip.contains(i))
                        .collect::<Vec<_>>();

                    for &i in &epochs {
                        if to_skip.contains(&i) {
                            continue;
                        }

                        let epoch = Epoch::from(i);

                        single_epoch_test(&store, epoch);

                        /*
                         *  Ensure that all the sets have the expected slots
                         */

                        let mut store_epochs = store
                            .items
                            .read()
                            .iter()
                            .map(|(epoch, _)| *epoch)
                            .collect::<Vec<_>>();

                        store_epochs.sort_unstable();

                        assert!(
                            store_epochs.len() <= store.max_capacity() as usize,
                            "store size should not exceed max"
                        );

                        let lowest = store.lowest_permissible_epoch.read().as_u64();
                        let highest = epoch.as_u64();
                        let expected_epochs = (lowest..=highest)
                            .filter(|i| !to_skip.contains(i))
                            .map(Epoch::new)
                            .collect::<Vec<_>>();

                        assert_eq!(
                            expected_epochs,
                            &store_epochs[..],
                            "should have expected epochs"
                        );
                    }
                }
            }
        };
    }

    test_suite!(observed_attesters, ObservedAttesters);
    test_suite!(observed_aggregators, ObservedAggregators);
}
