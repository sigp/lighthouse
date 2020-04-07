use bitvec::vec::BitVec;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{Attestation, Epoch, EthSpec, Hash256, Slot, Unsigned};

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

struct EpochBitfield<E: EthSpec> {
    bitfield: BitVec,
    epoch: Epoch,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> EpochBitfield<E> {
    pub fn new(epoch: Epoch, initial_capacity: usize) -> Self {
        Self {
            epoch,
            bitfield: BitVec::with_capacity(std::cmp::min(
                initial_capacity,
                E::ValidatorRegistryLimit::to_usize(),
            )),
            _phantom: PhantomData,
        }
    }

    pub fn observe_attesting_validator(&mut self, validator_index: usize) -> Result<bool, Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        self.bitfield
            .get_mut(validator_index)
            .map(|mut bit| {
                if *bit {
                    Ok(true)
                } else {
                    *bit = true;
                    Ok(false)
                }
            })
            .unwrap_or_else(|| {
                self.bitfield
                    .resize(validator_index.saturating_add(1), false);
                self.bitfield
                    .get_mut(validator_index)
                    .map(|mut bit| *bit = true);
                Ok(false)
            })
    }

    pub fn has_attested(&self, validator_index: usize) -> Result<bool, Error> {
        if validator_index > E::ValidatorRegistryLimit::to_usize() {
            return Err(Error::ValidatorIndexTooHigh(validator_index));
        }

        Ok(self.bitfield.get(validator_index).map_or(false, |bit| *bit))
    }

    pub fn len(&self) -> usize {
        self.bitfield.len()
    }
}

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

/*
#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;
    use types::{test_utils::test_random_instance, Hash256};

    type E = types::MainnetEthSpec;

    const NUM_ELEMENTS: usize = 8;

    fn get_attestation(slot: Slot, beacon_block_root: u64) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.data.beacon_block_root = Hash256::from_low_u64_be(beacon_block_root);
        a
    }

    fn single_slot_test(store: &ObservedAttestations<E>, slot: Slot) {
        let attestations = (0..NUM_ELEMENTS as u64)
            .map(|i| get_attestation(slot, i))
            .collect::<Vec<_>>();

        for a in &attestations {
            assert_eq!(
                store.is_known(a, a.tree_hash_root()),
                Ok(false),
                "should indicate an unknown attestation is unknown"
            );
            assert_eq!(
                store.observe_attestation(a, None),
                Ok(ObserveOutcome::New),
                "should observe new attestation"
            );
        }

        for a in &attestations {
            assert_eq!(
                store.is_known(a, a.tree_hash_root()),
                Ok(true),
                "should indicate a known attestation is known"
            );
            assert_eq!(
                store.observe_attestation(a, Some(a.tree_hash_root())),
                Ok(ObserveOutcome::AlreadyKnown),
                "should acknowledge an existing attestation"
            );
        }
    }

    #[test]
    fn single_slot() {
        let store = ObservedAttestations::default();

        single_slot_test(&store, Slot::new(0));

        assert_eq!(
            store.sets.read().len(),
            1,
            "should have a single set stored"
        );
        assert_eq!(
            store.sets.read()[0].len(),
            NUM_ELEMENTS,
            "set should have NUM_ELEMENTS elements"
        );
    }

    #[test]
    fn mulitple_contiguous_slots() {
        let store = ObservedAttestations::default();
        let max_cap = store.max_capacity();

        for i in 0..max_cap * 3 {
            let slot = Slot::new(i);

            single_slot_test(&store, slot);

            /*
             * Ensure that the number of sets is correct.
             */

            if i < max_cap {
                assert_eq!(
                    store.sets.read().len(),
                    i as usize + 1,
                    "should have a {} sets stored",
                    i + 1
                );
            } else {
                assert_eq!(
                    store.sets.read().len(),
                    max_cap as usize,
                    "should have max_capacity sets stored"
                );
            }

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets.read()[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store
                .sets
                .read()
                .iter()
                .map(|set| set.slot)
                .collect::<Vec<_>>();

            assert!(
                store_slots.len() <= store.max_capacity() as usize,
                "store size should not exceed max"
            );

            store_slots.sort_unstable();

            let expected_slots = (i.saturating_sub(max_cap - 1)..=i)
                .map(Slot::new)
                .collect::<Vec<_>>();

            assert_eq!(expected_slots, store_slots, "should have expected slots");
        }
    }

    #[test]
    fn mulitple_non_contiguous_slots() {
        let store = ObservedAttestations::default();
        let max_cap = store.max_capacity();

        let to_skip = vec![1_u64, 2, 3, 5, 6, 29, 30, 31, 32, 64];
        let slots = (0..max_cap * 3)
            .into_iter()
            .filter(|i| !to_skip.contains(i))
            .collect::<Vec<_>>();

        for &i in &slots {
            if to_skip.contains(&i) {
                continue;
            }

            let slot = Slot::from(i);

            single_slot_test(&store, slot);

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets.read()[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store
                .sets
                .read()
                .iter()
                .map(|set| set.slot)
                .collect::<Vec<_>>();

            store_slots.sort_unstable();

            assert!(
                store_slots.len() <= store.max_capacity() as usize,
                "store size should not exceed max"
            );

            let lowest = store.lowest_permissible_slot.read().as_u64();
            let highest = slot.as_u64();
            let expected_slots = (lowest..=highest)
                .filter(|i| !to_skip.contains(i))
                .map(Slot::new)
                .collect::<Vec<_>>();

            assert_eq!(
                expected_slots,
                &store_slots[..],
                "should have expected slots"
            );
        }
    }
}
*/
