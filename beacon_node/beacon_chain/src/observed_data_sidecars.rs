//! Provides the `ObservedBlobSidecars` struct which allows for rejecting `BlobSidecar`s
//! that we have already seen over the gossip network.
//! Only `BlobSidecar`s that have completed proposer signature verification can be added
//! to this cache to reduce DoS risks.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BlobSidecar, ChainSpec, DataColumnSidecar, EthSpec, Hash256, SignedBeaconBlock, Slot};

type ValidatorIndex = u64;
type BeaconBlockRoot = Hash256;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided `ObservableDataSidecar` is prior to finalization and should not have been provided
    /// to this function. This is an internal error.
    FinalizedDataSidecar {
        slot: Slot,
        finalized_slot: Slot,
    },
    /// The data sidecar contains an invalid index, the data sidecar is invalid.
    /// Note: The invalid data should have been caught and flagged as an error much before reaching
    /// here.
    InvalidDataIndex(u64),

    // An unexpected data sidecar variant was received
    UnexpectedVariant,
}

pub trait ObservableDataSidecar {
    fn slot(&self) -> Slot;
    fn index(&self) -> u64;
    fn proposer_index(&self) -> Option<ValidatorIndex>;
    fn beacon_block_root(&self) -> BeaconBlockRoot;
    fn max_num_of_items(spec: &ChainSpec, slot: Slot) -> usize;
}

impl<E: EthSpec> ObservableDataSidecar for BlobSidecar<E> {
    fn slot(&self) -> Slot {
        self.slot()
    }

    fn index(&self) -> u64 {
        self.index
    }

    fn proposer_index(&self) -> Option<ValidatorIndex> {
        Some(self.block_proposer_index())
    }

    fn beacon_block_root(&self) -> BeaconBlockRoot {
        self.block_root()
    }

    fn max_num_of_items(spec: &ChainSpec, slot: Slot) -> usize {
        spec.max_blobs_per_block(slot.epoch(E::slots_per_epoch())) as usize
    }
}

impl<E: EthSpec> ObservableDataSidecar for DataColumnSidecar<E> {
    fn slot(&self) -> Slot {
        self.slot()
    }

    fn index(&self) -> u64 {
        *self.index()
    }

    fn proposer_index(&self) -> Option<ValidatorIndex> {
        self.as_fulu().map(|d| d.block_proposer_index()).ok()
    }

    fn beacon_block_root(&self) -> BeaconBlockRoot {
        self.block_root()
    }

    fn max_num_of_items(_spec: &ChainSpec, _slot: Slot) -> usize {
        E::number_of_columns()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ObservationKey {
    ProposerKey((ValidatorIndex, Slot)),
    BlockRootKey((BeaconBlockRoot, Slot)),
}

impl ObservationKey {
    pub fn new<T: ObservableDataSidecar, E: EthSpec>(
        sidecar: &T,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let slot = sidecar.slot();

        if spec.fork_name_at_slot::<E>(slot).gloas_enabled() {
            Ok(Self::new_block_root_key(sidecar.beacon_block_root(), slot))
        } else if let Some(proposer_index) = sidecar.proposer_index() {
            Ok(Self::new_proposer_key(proposer_index, slot))
        } else {
            Err(Error::UnexpectedVariant)
        }
    }

    pub fn from_block<E: EthSpec>(
        block: &SignedBeaconBlock<E>,
        block_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let slot = block.slot();

        if spec.fork_name_at_slot::<E>(slot).gloas_enabled() {
            Self::new_block_root_key(block_root, slot)
        } else {
            Self::new_proposer_key(block.message().proposer_index(), slot)
        }
    }

    pub fn new_proposer_key(proposer_index: ValidatorIndex, slot: Slot) -> Self {
        Self::ProposerKey((proposer_index, slot))
    }

    pub fn new_block_root_key(beacon_block_root: BeaconBlockRoot, slot: Slot) -> Self {
        Self::BlockRootKey((beacon_block_root, slot))
    }

    pub fn slot(&self) -> Slot {
        match self {
            ObservationKey::ProposerKey((_, slot)) => *slot,
            ObservationKey::BlockRootKey((_, slot)) => *slot,
        }
    }
}

/// Maintains a cache of seen `ObservableDataSidecar`s that are received over gossip
/// and have been gossip verified.
///
/// The cache supports pruning based upon the finalized epoch. It does not automatically prune, you
/// must call `Self::prune` manually.
///
/// Note: To prevent DoS attacks, this cache must include only items that have received some DoS resistance
/// like checking the proposer signature.
pub struct ObservedDataSidecars<T: ObservableDataSidecar, E: EthSpec> {
    finalized_slot: Slot,
    /// Stores all received data indices for a given `ObservationKey`.
    items: HashMap<ObservationKey, HashSet<u64>>,
    spec: Arc<ChainSpec>,
    _phantom: PhantomData<(T, E)>,
}

impl<T: ObservableDataSidecar, E: EthSpec> ObservedDataSidecars<T, E> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    pub fn new(spec: Arc<ChainSpec>) -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashMap::new(),
            spec,
            _phantom: PhantomData,
        }
    }

    /// Observe the `data_sidecar` at `ObservationKey`.
    /// Observes the sidecar, returning `Some(key)` if it was already known, `None` if newly added.
    ///
    /// This will update `self` so future calls indicate that this `data_sidecar` is known.
    pub fn observe_sidecar(&mut self, data_sidecar: &T) -> Result<Option<ObservationKey>, Error> {
        self.sanitize_data_sidecar(data_sidecar)?;

        let observation_key = ObservationKey::new::<T, E>(data_sidecar, &self.spec)?;

        let data_indices = self
            .items
            .entry(observation_key.clone())
            .or_insert_with(|| {
                HashSet::with_capacity(T::max_num_of_items(&self.spec, data_sidecar.slot()))
            });
        let did_not_exist = data_indices.insert(data_sidecar.index());

        Ok((!did_not_exist).then_some(observation_key))
    }

    /// Returns `Some(key)` if the sidecar has already been observed, `None` otherwise.
    pub fn observation_key_is_known(
        &self,
        data_sidecar: &T,
    ) -> Result<Option<ObservationKey>, Error> {
        self.sanitize_data_sidecar(data_sidecar)?;

        let observation_key = ObservationKey::new::<T, E>(data_sidecar, &self.spec)?;

        let is_known = self
            .items
            .get(&observation_key)
            .is_some_and(|indices| indices.contains(&data_sidecar.index()));

        Ok(is_known.then_some(observation_key))
    }

    pub fn known_for_observation_key(
        &self,
        observation_key: &ObservationKey,
    ) -> Option<&HashSet<u64>> {
        self.items.get(observation_key)
    }

    fn sanitize_data_sidecar(&self, data_sidecar: &T) -> Result<(), Error> {
        if data_sidecar.index() >= T::max_num_of_items(&self.spec, data_sidecar.slot()) as u64 {
            return Err(Error::InvalidDataIndex(data_sidecar.index()));
        }
        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && data_sidecar.slot() <= finalized_slot {
            return Err(Error::FinalizedDataSidecar {
                slot: data_sidecar.slot(),
                finalized_slot,
            });
        }

        Ok(())
    }

    /// Prune `data_sidecar` observations for slots less than or equal to the given slot.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|k, _| k.slot() > finalized_slot);
    }
}

/// Abstraction to control "observation" of gossip messages (currently just blobs and data columns).
///
/// If a type returns `false` for `observe` then the message will not be immediately added to its
/// respective gossip observation cache. Unobserved messages should usually be observed later.
pub trait ObservationStrategy {
    fn observe() -> bool;
}

/// Type for messages that are observed immediately.
pub struct Observe;
/// Type for messages that have not been observed.
#[derive(Debug)]
pub struct DoNotObserve;

impl ObservationStrategy for Observe {
    fn observe() -> bool {
        true
    }
}

impl ObservationStrategy for DoNotObserve {
    fn observe() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::test_spec;

    use super::*;
    use bls::{FixedBytesExtended, Signature};
    use std::sync::Arc;
    use types::{
        BeaconBlockHeader, DataColumnSidecarFulu, DataColumnSidecarGloas, ForkName, MainnetEthSpec,
        SignedBeaconBlockHeader,
    };

    type E = MainnetEthSpec;

    /// Creates a Fulu DataColumnSidecar for testing.
    /// Keyed by (proposer_index, slot) in the observation cache.
    fn get_data_column_sidecar_fulu(
        slot: u64,
        proposer_index: u64,
        index: u64,
    ) -> Arc<DataColumnSidecar<E>> {
        let signed_block_header = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: slot.into(),
                proposer_index,
                parent_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
                // Use proposer_index as a simple way to generate different block roots
                body_root: Hash256::from_low_u64_be(proposer_index),
            },
            signature: Signature::empty(),
        };
        Arc::new(DataColumnSidecar::Fulu(DataColumnSidecarFulu {
            index,
            column: vec![].try_into().unwrap(),
            kzg_commitments: vec![].try_into().unwrap(),
            kzg_proofs: vec![].try_into().unwrap(),
            signed_block_header,
            kzg_commitments_inclusion_proof: vec![
                Hash256::ZERO;
                E::kzg_commitments_inclusion_proof_depth()
            ]
            .try_into()
            .unwrap(),
        }))
    }

    /// Creates a Gloas DataColumnSidecar for testing.
    /// Keyed by (beacon_block_root, slot) in the observation cache.
    fn get_data_column_sidecar_gloas(
        slot: u64,
        beacon_block_root: Hash256,
        index: u64,
    ) -> Arc<DataColumnSidecar<E>> {
        Arc::new(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index,
            column: vec![].try_into().unwrap(),
            kzg_commitments: vec![].try_into().unwrap(),
            kzg_proofs: vec![].try_into().unwrap(),
            slot: slot.into(),
            beacon_block_root,
        }))
    }

    fn get_sidecar(
        slot: u64,
        key: u64,
        index: u64,
        fork_name: ForkName,
    ) -> Arc<DataColumnSidecar<E>> {
        if fork_name.gloas_enabled() {
            get_data_column_sidecar_gloas(slot, Hash256::from_low_u64_be(key), index)
        } else {
            get_data_column_sidecar_fulu(slot, key, index)
        }
    }

    #[test]
    fn pruning() {
        let spec = Arc::new(test_spec::<E>());
        let fork_name = spec.fork_name_at_slot::<E>(Slot::new(0));

        let mut cache = ObservedDataSidecars::<DataColumnSidecar<E>, E>::new(spec.clone());

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 0, "no slots should be present");

        // Slot 0, index 0
        let key_a = 420;
        let sidecar_a = get_sidecar(0, key_a, 0, fork_name);

        assert_eq!(
            cache
                .observe_sidecar(sidecar_a.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can observe sidecar, indicates sidecar unobserved"
        );

        /*
         * Preconditions.
         */

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(
            cache.items.len(),
            1,
            "only one observation key should be present"
        );

        let observation_key =
            &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_a.as_ref(), &spec).unwrap();

        let cached_indices = cache
            .items
            .get(observation_key)
            .expect("slot zero should be present");
        assert_eq!(cached_indices.len(), 1, "only one index should be present");

        /*
         * Check that a prune at the genesis slot does nothing.
         */

        cache.prune(Slot::new(0));

        let observation_key =
            ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_a.as_ref(), &spec).unwrap();

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_indices = cache
            .items
            .get(&observation_key)
            .expect("slot zero should be present");
        assert_eq!(cached_indices.len(), 1, "only one index should be present");

        /*
         * Check that a prune empties the cache
         */

        cache.prune(E::slots_per_epoch().into());
        assert_eq!(
            cache.finalized_slot,
            Slot::from(E::slots_per_epoch()),
            "finalized slot is updated"
        );
        assert_eq!(cache.items.len(), 0, "no items left");

        /*
         * Check that we can't insert a finalized sidecar
         */

        // First slot of finalized epoch
        let sidecar_b = get_sidecar(E::slots_per_epoch(), 419, 0, fork_name);

        assert_eq!(
            cache.observe_sidecar(sidecar_b.as_ref()),
            Err(Error::FinalizedDataSidecar {
                slot: E::slots_per_epoch().into(),
                finalized_slot: E::slots_per_epoch().into(),
            }),
            "cant insert finalized sidecar"
        );

        assert_eq!(cache.items.len(), 0, "sidecar was not added");

        /*
         * Check that we _can_ insert a non-finalized sidecar
         */

        let three_epochs = E::slots_per_epoch() * 3;

        let key_b = 421;
        let sidecar_b = get_sidecar(three_epochs, key_b, 0, fork_name);

        assert_eq!(
            cache
                .observe_sidecar(sidecar_b.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can insert non-finalized sidecar"
        );

        let observation_key =
            ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_b.as_ref(), &spec).unwrap();

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_indices = cache
            .items
            .get(&observation_key)
            .expect("the three epochs slot should be present");
        assert_eq!(cached_indices.len(), 1, "only one index should be present");

        /*
         * Check that a prune doesnt wipe later sidecars
         */

        let two_epochs = E::slots_per_epoch() * 2;
        cache.prune(two_epochs.into());

        assert_eq!(
            cache.finalized_slot,
            Slot::from(two_epochs),
            "finalized slot is updated"
        );

        let observation_key =
            ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_b.as_ref(), &spec).unwrap();

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_indices = cache
            .items
            .get(&observation_key)
            .expect("the three epochs slot should be present");
        assert_eq!(cached_indices.len(), 1, "only one index should be present");
    }

    #[test]
    fn simple_observations() {
        let spec = Arc::new(test_spec::<E>());
        let fork_name = spec.fork_name_at_slot::<E>(Slot::new(0));

        let mut cache = ObservedDataSidecars::<DataColumnSidecar<E>, E>::new(spec.clone());

        // Slot 0, index 0
        let key_a = 420;
        let sidecar_a = get_sidecar(0, key_a, 0, fork_name);

        assert_eq!(
            cache
                .observation_key_is_known(sidecar_a.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "no observation in empty cache"
        );

        assert_eq!(
            cache
                .observe_sidecar(sidecar_a.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can observe sidecar, indicates sidecar unobserved"
        );

        assert_eq!(
            cache
                .observation_key_is_known(sidecar_a.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observed sidecar is indicated as true"
        );

        assert_eq!(
            cache
                .observe_sidecar(sidecar_a.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observing again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_indices = cache
            .items
            .get(
                &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_a.as_ref(), &spec).unwrap(),
            )
            .expect("slot zero should be present");
        assert_eq!(cached_indices.len(), 1, "only one index should be present");

        // Slot 1, different key

        let key_b = 421;
        let sidecar_b = get_sidecar(1, key_b, 0, fork_name);

        assert_eq!(
            cache
                .observation_key_is_known(sidecar_b.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "no observation for new slot"
        );
        assert_eq!(
            cache
                .observe_sidecar(sidecar_b.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can observe sidecar for new slot, indicates sidecar unobserved"
        );
        assert_eq!(
            cache
                .observation_key_is_known(sidecar_b.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observed sidecar in slot 1 is indicated as true"
        );
        assert_eq!(
            cache
                .observe_sidecar(sidecar_b.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observing slot 1 again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 2, "two slots should be present");
        let cached_indices = cache
            .items
            .get(
                &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_a.as_ref(), &spec).unwrap(),
            )
            .expect("slot zero should be present");
        assert_eq!(
            cached_indices.len(),
            1,
            "only one index should be present in slot 0"
        );
        let cached_indices = cache
            .items
            .get(
                &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_b.as_ref(), &spec).unwrap(),
            )
            .expect("slot one should be present");
        assert_eq!(
            cached_indices.len(),
            1,
            "only one index should be present in slot 1"
        );

        // Slot 0, index 1 (same key as sidecar_a)
        let sidecar_c = get_sidecar(0, key_a, 1, fork_name);

        assert_eq!(
            cache
                .observation_key_is_known(sidecar_c.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "no observation for new index"
        );
        assert_eq!(
            cache
                .observe_sidecar(sidecar_c.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can observe new index, indicates sidecar unobserved for new index"
        );
        assert_eq!(
            cache
                .observation_key_is_known(sidecar_c.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observed new sidecar is indicated as true"
        );
        assert_eq!(
            cache
                .observe_sidecar(sidecar_c.as_ref())
                .map(|o| o.is_some()),
            Ok(true),
            "observing new sidecar again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 2, "two slots should be present");
        let cached_indices = cache
            .items
            .get(
                &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_a.as_ref(), &spec).unwrap(),
            )
            .expect("slot zero should be present");
        assert_eq!(
            cached_indices.len(),
            2,
            "two indices should be present in slot 0"
        );

        // Create a sidecar with a different key at the same slot
        // For Fulu: different proposer_index creates a different observation key
        // For Gloas: different block_root creates a different observation key
        let key_c = 422;
        let sidecar_d = get_sidecar(0, key_c, 0, fork_name);
        assert_eq!(
            cache
                .observation_key_is_known(sidecar_d.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "no observation for new key"
        );
        assert_eq!(
            cache
                .observe_sidecar(sidecar_d.as_ref())
                .map(|o| o.is_some()),
            Ok(false),
            "can observe sidecar, indicates sidecar unobserved for new key"
        );
        let cached_indices = cache
            .items
            .get(
                &ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_d.as_ref(), &spec).unwrap(),
            )
            .expect("sidecar_d's observation key should be present");
        assert_eq!(
            cached_indices.len(),
            1,
            "one index should be present for sidecar_d's observation key"
        );

        // Try adding an out of bounds index
        let invalid_index = E::number_of_columns() as u64;
        let sidecar_e = get_sidecar(0, key_a, invalid_index, fork_name);
        assert_eq!(
            cache.observe_sidecar(sidecar_e.as_ref()),
            Err(Error::InvalidDataIndex(invalid_index)),
            "cannot add an index >= NUMBER_OF_COLUMNS"
        );
    }

    /// Test that sidecars with the same observation key but different indices
    /// are tracked correctly.
    #[test]
    fn multiple_indices_same_key() {
        let spec = Arc::new(test_spec::<E>());
        let fork_name = spec.fork_name_at_slot::<E>(Slot::new(0));

        let mut cache = ObservedDataSidecars::<DataColumnSidecar<E>, E>::new(spec.clone());

        let key = 420;

        // Add multiple indices for the same observation key
        for index in 0..5 {
            let sidecar = get_sidecar(0, key, index, fork_name);
            assert_eq!(
                cache.observe_sidecar(sidecar.as_ref()).map(|o| o.is_some()),
                Ok(false),
                "index {index} should be new"
            );
        }

        // Verify all indices are tracked under one observation key
        assert_eq!(cache.items.len(), 1, "only one observation key");

        let sidecar_for_key = get_sidecar(0, key, 0, fork_name);
        let observation_key =
            ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar_for_key.as_ref(), &spec)
                .unwrap();
        let cached_indices = cache.items.get(&observation_key).unwrap();
        assert_eq!(cached_indices.len(), 5, "five indices should be tracked");

        // Re-observing should indicate they're already known
        for index in 0..5 {
            let sidecar = get_sidecar(0, key, index, fork_name);
            assert_eq!(
                cache.observe_sidecar(sidecar.as_ref()).map(|o| o.is_some()),
                Ok(true),
                "index {index} should already be known"
            );
        }
    }

    /// Test the known_for_observation_key method
    #[test]
    fn known_for_observation_key() {
        let spec = Arc::new(test_spec::<E>());
        let fork_name = spec.fork_name_at_slot::<E>(Slot::new(0));

        let mut cache = ObservedDataSidecars::<DataColumnSidecar<E>, E>::new(spec.clone());

        let key = 420;
        let sidecar = get_sidecar(0, key, 0, fork_name);
        let observation_key =
            ObservationKey::new::<DataColumnSidecar<E>, E>(sidecar.as_ref(), &spec).unwrap();

        // Before observation, should return None
        assert!(cache.known_for_observation_key(&observation_key).is_none());

        // After observation, should return the set of indices
        cache.observe_sidecar(sidecar.as_ref()).unwrap();
        let known = cache
            .known_for_observation_key(&observation_key)
            .expect("should be known");
        assert!(known.contains(&0));
        assert_eq!(known.len(), 1);

        // Add more indices
        let sidecar_1 = get_sidecar(0, key, 1, fork_name);
        let sidecar_2 = get_sidecar(0, key, 2, fork_name);
        cache.observe_sidecar(sidecar_1.as_ref()).unwrap();
        cache.observe_sidecar(sidecar_2.as_ref()).unwrap();

        let known = cache
            .known_for_observation_key(&observation_key)
            .expect("should be known");
        assert!(known.contains(&0));
        assert!(known.contains(&1));
        assert!(known.contains(&2));
        assert_eq!(known.len(), 3);
    }
}
