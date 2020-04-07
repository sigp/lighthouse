use bitvec::vec::BitVec;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::marker::PhantomData;
use types::{Attestation, Epoch, EthSpec, Unsigned};

pub type ObservedAttesters<E> = AutoPruningContainer<EpochBitfield, E>;
pub type ObservedAggregators<E> = AutoPruningContainer<EpochHashSet, E>;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochTooLow {
        epoch: Epoch,
        lowest_permissible_epoch: Epoch,
    },
    /// The function to obtain a set index failed, this is an internal error.
    InvalidBitfieldIndex(usize),
    /// We have reached the maximum number of unique `Attestation` that can be observed in a slot.
    /// This is a DoS protection function.
    ReachedMaxObservationsPerSlot(usize),
    /// The function to obtain a set index failed, this is an internal error.
    ValidatorIndexTooHigh(usize),
}

pub trait Item {
    fn with_capacity(epoch: Epoch, capacity: usize) -> Self;

    fn epoch(&self) -> Epoch;

    fn len(&self) -> usize;

    fn insert(&mut self, validator_index: usize) -> bool;

    fn contains(&self, validator_index: usize) -> bool;
}

pub struct EpochBitfield {
    bitfield: BitVec,
    epoch: Epoch,
}

impl Item for EpochBitfield {
    fn with_capacity(epoch: Epoch, capacity: usize) -> Self {
        Self {
            epoch,
            bitfield: BitVec::with_capacity(capacity),
        }
    }

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn len(&self) -> usize {
        self.bitfield.len()
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
                self.bitfield
                    .get_mut(validator_index)
                    .map(|mut bit| *bit = true);
                false
            })
    }

    fn contains(&self, validator_index: usize) -> bool {
        self.bitfield.get(validator_index).map_or(false, |bit| *bit)
    }
}

pub struct EpochHashSet {
    set: HashSet<usize>,
    epoch: Epoch,
}

impl Item for EpochHashSet {
    fn with_capacity(epoch: Epoch, capacity: usize) -> Self {
        Self {
            epoch,
            set: HashSet::with_capacity(capacity),
        }
    }

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn insert(&mut self, validator_index: usize) -> bool {
        !self.set.insert(validator_index)
    }

    fn contains(&self, validator_index: usize) -> bool {
        self.set.contains(&validator_index)
    }
}

pub struct AutoPruningContainer<T, E: EthSpec> {
    lowest_permissible_epoch: RwLock<Epoch>,
    items: RwLock<Vec<T>>,
    _phantom: PhantomData<E>,
}

impl<T, E: EthSpec> Default for AutoPruningContainer<T, E> {
    fn default() -> Self {
        Self {
            lowest_permissible_epoch: RwLock::new(Epoch::new(0)),
            items: RwLock::new(vec![]),
            _phantom: PhantomData,
        }
    }
}

impl<T: Item, E: EthSpec> AutoPruningContainer<T, E> {
    pub fn observe_validator(
        &self,
        a: &Attestation<E>,
        validator_index: usize,
    ) -> Result<bool, Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        let index = self.get_bitfield_index(a.data.target.epoch)?;

        self.items
            .write()
            .get_mut(index)
            .ok_or_else(|| Error::InvalidBitfieldIndex(index))
            .map(|item| item.insert(validator_index))
    }

    pub fn validator_has_been_observed(
        &self,
        a: &Attestation<E>,
        validator_index: usize,
    ) -> Result<bool, Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        let index = self.get_bitfield_index(a.data.target.epoch)?;

        self.items
            .read()
            .get(index)
            .ok_or_else(|| Error::InvalidBitfieldIndex(index))
            .map(|item| item.contains(validator_index))
    }

    fn max_capacity(&self) -> u64 {
        // The current epoch and the previous epoch. This is sufficient whilst
        // GOSSIP_CLOCK_DISPARITY is 1/2 a slot or less:
        //
        // https://github.com/ethereum/eth2.0-specs/pull/1706#issuecomment-610151808
        2
    }

    pub fn prune(&self, current_epoch: Epoch) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_epoch = current_epoch - (self.max_capacity().saturating_sub(1));

        self.items
            .write()
            .retain(|bitfield| bitfield.epoch() >= lowest_permissible_epoch);

        *self.lowest_permissible_epoch.write() = lowest_permissible_epoch;
    }

    fn get_bitfield_index(&self, epoch: Epoch) -> Result<usize, Error> {
        let lowest_permissible_epoch: Epoch = *self.lowest_permissible_epoch.read();

        if epoch < lowest_permissible_epoch {
            return Err(Error::EpochTooLow {
                epoch,
                lowest_permissible_epoch,
            });
        }

        // Prune the pool if this attestation indicates that the current slot has advanced.
        if lowest_permissible_epoch + self.max_capacity() < epoch + 1 {
            self.prune(epoch)
        }

        let mut items = self.items.write();

        if let Some(index) = items.iter().position(|item| item.epoch() == epoch) {
            return Ok(index);
        }

        // To avoid re-allocations, try and determine a rough initial capacity for the new bitfield
        // by obtaining the mean size of all items in earlier epoch.
        let (count, sum) = items
            .iter()
            // Only include slots that are less than the given slot in the average. This should
            // generally avoid including recent slots that are still "filling up".
            .filter(|item| item.epoch() < epoch)
            .map(|item| item.len())
            .fold((0, 0), |(count, sum), len| (count + 1, sum + len));
        // If we are unable to determine an average, just choose 16k as this is the amount of eth2
        // genesis validators.
        let initial_capacity = sum.checked_div(count).unwrap_or(128);
        let new_item = T::with_capacity(epoch, initial_capacity);

        if items.len() < self.max_capacity() as usize || items.is_empty() {
            let index = items.len();
            items.push(new_item);
            return Ok(index);
        }

        let index = items
            .iter()
            .enumerate()
            .min_by_key(|(_i, b)| b.epoch())
            .map(|(i, _)| i)
            .expect("items cannot be empty due to previous .is_empty() check");

        items[index] = new_item;

        Ok(index)
    }
}

/*
pub struct ObservedAttesters<E: EthSpec> {
    lowest_permissible_epoch: RwLock<Epoch>,
    bitfields: RwLock<Vec<EpochBitfield<E>>>,
}

impl<E: EthSpec> Default for ObservedAttesters<E> {
    fn default() -> Self {
        Self {
            lowest_permissible_epoch: RwLock::new(Epoch::new(0)),
            bitfields: RwLock::new(vec![]),
        }
    }
}

impl<E: EthSpec> ObservedAttesters<E> {
    pub fn observe_attesting_validator(
        &self,
        a: &Attestation<E>,
        validator_index: usize,
    ) -> Result<bool, Error> {
        let index = self.get_bitfield_index(a.data.target.epoch)?;

        self.bitfields
            .write()
            .get_mut(index)
            .ok_or_else(|| Error::InvalidBitfieldIndex(index))
            .and_then(|bitfield| bitfield.observe_attesting_validator(validator_index))
    }

    pub fn has_attested(&self, a: &Attestation<E>, validator_index: usize) -> Result<bool, Error> {
        let index = self.get_bitfield_index(a.data.target.epoch)?;

        self.bitfields
            .read()
            .get(index)
            .ok_or_else(|| Error::InvalidBitfieldIndex(index))
            .and_then(|bitfield| bitfield.has_attested(validator_index))
    }

    fn max_capacity(&self) -> u64 {
        // The current epoch and the previous epoch. This is sufficient whilst
        // GOSSIP_CLOCK_DISPARITY is 1/2 a slot or less:
        //
        // https://github.com/ethereum/eth2.0-specs/pull/1706#issuecomment-610151808
        2
    }

    pub fn prune(&self, current_epoch: Epoch) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_epoch = current_epoch - (self.max_capacity().saturating_sub(1));

        self.bitfields
            .write()
            .retain(|bitfield| bitfield.epoch >= lowest_permissible_epoch);

        *self.lowest_permissible_epoch.write() = lowest_permissible_epoch;
    }

    fn get_bitfield_index(&self, epoch: Epoch) -> Result<usize, Error> {
        let lowest_permissible_epoch: Epoch = *self.lowest_permissible_epoch.read();

        if epoch < lowest_permissible_epoch {
            return Err(Error::EpochTooLow {
                epoch,
                lowest_permissible_epoch,
            });
        }

        // Prune the pool if this attestation indicates that the current slot has advanced.
        if lowest_permissible_epoch + self.max_capacity() < epoch + 1 {
            self.prune(epoch)
        }

        let mut bitfields = self.bitfields.write();

        if let Some(index) = bitfields.iter().position(|b| b.epoch == epoch) {
            return Ok(index);
        }

        // To avoid re-allocations, try and determine a rough initial capacity for the new bitfield
        // by obtaining the mean size of all bitfields in earlier epoch.
        let (count, sum) = bitfields
            .iter()
            // Only include slots that are less than the given slot in the average. This should
            // generally avoid including recent slots that are still "filling up".
            .filter(|b| b.epoch < epoch)
            .map(|b| b.len())
            .fold((0, 0), |(count, sum), len| (count + 1, sum + len));
        // If we are unable to determine an average, just choose 16k as this is the amount of eth2
        // genesis validators.
        let initial_capacity = sum.checked_div(count).unwrap_or(128);

        if bitfields.len() < self.max_capacity() as usize || bitfields.is_empty() {
            let index = bitfields.len();
            bitfields.push(EpochBitfield::new(epoch, initial_capacity));
            return Ok(index);
        }

        let index = bitfields
            .iter()
            .enumerate()
            .min_by_key(|(_i, b)| b.epoch)
            .map(|(i, _)| i)
            .expect("bitfields cannot be empty due to previous .is_empty() check");

        bitfields[index] = EpochBitfield::new(epoch, initial_capacity);

        Ok(index)
    }
}
*/

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
                            .map(|set| set.epoch)
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
                            .map(|b| b.epoch())
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
