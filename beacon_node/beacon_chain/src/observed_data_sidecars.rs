//! Provides the `ObservedBlobSidecars` struct which allows for rejecting `BlobSidecar`s
//! that we have already seen over the gossip network.
//! Only `BlobSidecar`s that have completed proposer signature verification can be added
//! to this cache to reduce DoS risks.

use crate::observed_block_producers::ProposalKey;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BlobSidecar, ChainSpec, DataColumnSidecar, EthSpec, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided `ObservableDataSidecar` is prior to finalization and should not have been provided
    /// to this function. This is an internal error.
    FinalizedDataSidecar { slot: Slot, finalized_slot: Slot },
    /// The data sidecar contains an invalid index, the data sidecar is invalid.
    /// Note: The invalid data should have been caught and flagged as an error much before reaching
    /// here.
    InvalidDataIndex(u64),
}

pub trait ObservableDataSidecar {
    fn slot(&self) -> Slot;
    fn block_proposer_index(&self) -> u64;
    fn index(&self) -> u64;
    fn max_num_of_items(spec: &ChainSpec) -> usize;
}

impl<E: EthSpec> ObservableDataSidecar for BlobSidecar<E> {
    fn slot(&self) -> Slot {
        self.slot()
    }

    fn block_proposer_index(&self) -> u64 {
        self.block_proposer_index()
    }

    fn index(&self) -> u64 {
        self.index
    }

    fn max_num_of_items(_spec: &ChainSpec) -> usize {
        E::max_blobs_per_block()
    }
}

impl<E: EthSpec> ObservableDataSidecar for DataColumnSidecar<E> {
    fn slot(&self) -> Slot {
        self.slot()
    }

    fn block_proposer_index(&self) -> u64 {
        self.block_proposer_index()
    }

    fn index(&self) -> u64 {
        self.index
    }

    fn max_num_of_items(spec: &ChainSpec) -> usize {
        spec.number_of_columns
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
pub struct ObservedDataSidecars<T: ObservableDataSidecar> {
    finalized_slot: Slot,
    /// Stores all received data indices for a given `(ValidatorIndex, Slot)` tuple.
    items: HashMap<ProposalKey, HashSet<u64>>,
    spec: Arc<ChainSpec>,
    _phantom: PhantomData<T>,
}

impl<T: ObservableDataSidecar> ObservedDataSidecars<T> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    pub fn new(spec: Arc<ChainSpec>) -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashMap::new(),
            spec,
            _phantom: PhantomData,
        }
    }

    /// Observe the `data_sidecar` at (`data_sidecar.block_proposer_index, data_sidecar.slot`).
    /// This will update `self` so future calls to it indicate that this `data_sidecar` is known.
    ///
    /// The supplied `data_sidecar` **MUST** have completed proposer signature verification.
    pub fn observe_sidecar(&mut self, data_sidecar: &T) -> Result<bool, Error> {
        self.sanitize_data_sidecar(data_sidecar)?;

        let data_indices = self
            .items
            .entry(ProposalKey {
                slot: data_sidecar.slot(),
                proposer: data_sidecar.block_proposer_index(),
            })
            .or_insert_with(|| HashSet::with_capacity(T::max_num_of_items(&self.spec)));
        let did_not_exist = data_indices.insert(data_sidecar.index());

        Ok(!did_not_exist)
    }

    /// Returns `true` if the `data_sidecar` has already been observed in the cache within the prune window.
    pub fn proposer_is_known(&self, data_sidecar: &T) -> Result<bool, Error> {
        self.sanitize_data_sidecar(data_sidecar)?;
        let is_known = self
            .items
            .get(&ProposalKey {
                slot: data_sidecar.slot(),
                proposer: data_sidecar.block_proposer_index(),
            })
            .map_or(false, |indices| indices.contains(&data_sidecar.index()));
        Ok(is_known)
    }

    fn sanitize_data_sidecar(&self, data_sidecar: &T) -> Result<(), Error> {
        if data_sidecar.index() >= T::max_num_of_items(&self.spec) as u64 {
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
        self.items.retain(|k, _| k.slot > finalized_slot);
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
    use super::*;
    use crate::test_utils::test_spec;
    use bls::Hash256;
    use std::sync::Arc;
    use types::MainnetEthSpec;

    type E = MainnetEthSpec;

    fn get_blob_sidecar(slot: u64, proposer_index: u64, index: u64) -> Arc<BlobSidecar<E>> {
        let mut blob_sidecar = BlobSidecar::empty();
        blob_sidecar.signed_block_header.message.slot = slot.into();
        blob_sidecar.signed_block_header.message.proposer_index = proposer_index;
        blob_sidecar.index = index;
        Arc::new(blob_sidecar)
    }

    #[test]
    fn pruning() {
        let spec = Arc::new(test_spec::<E>());
        let mut cache = ObservedDataSidecars::<BlobSidecar<E>>::new(spec);

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 0, "no slots should be present");

        // Slot 0, index 0
        let proposer_index_a = 420;
        let sidecar_a = get_blob_sidecar(0, proposer_index_a, 0);

        assert_eq!(
            cache.observe_sidecar(&sidecar_a),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );

        /*
         * Preconditions.
         */

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(
            cache.items.len(),
            1,
            "only one (validator_index, slot) tuple should be present"
        );

        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune at the genesis slot does nothing.
         */

        cache.prune(Slot::new(0));

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present"
        );

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
        let block_b = get_blob_sidecar(E::slots_per_epoch(), 419, 0);

        assert_eq!(
            cache.observe_sidecar(&block_b),
            Err(Error::FinalizedDataSidecar {
                slot: E::slots_per_epoch().into(),
                finalized_slot: E::slots_per_epoch().into(),
            }),
            "cant insert finalized sidecar"
        );

        assert_eq!(cache.items.len(), 0, "sidecar was not added");

        /*
         * Check that we _can_ insert a non-finalized block
         */

        let three_epochs = E::slots_per_epoch() * 3;

        // First slot of finalized epoch
        let proposer_index_b = 421;
        let block_b = get_blob_sidecar(three_epochs, proposer_index_b, 0);

        assert_eq!(
            cache.observe_sidecar(&block_b),
            Ok(false),
            "can insert non-finalized block"
        );

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_b, Slot::new(three_epochs)))
            .expect("the three epochs slot should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune doesnt wipe later blocks
         */

        let two_epochs = E::slots_per_epoch() * 2;
        cache.prune(two_epochs.into());

        assert_eq!(
            cache.finalized_slot,
            Slot::from(two_epochs),
            "finalized slot is updated"
        );

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_b, Slot::new(three_epochs)))
            .expect("the three epochs slot should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present"
        );
    }

    #[test]
    fn simple_observations() {
        let spec = Arc::new(test_spec::<E>());
        let mut cache = ObservedDataSidecars::<BlobSidecar<E>>::new(spec);

        // Slot 0, index 0
        let proposer_index_a = 420;
        let sidecar_a = get_blob_sidecar(0, proposer_index_a, 0);

        assert_eq!(
            cache.proposer_is_known(&sidecar_a),
            Ok(false),
            "no observation in empty cache"
        );

        assert_eq!(
            cache.observe_sidecar(&sidecar_a),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );

        assert_eq!(
            cache.proposer_is_known(&sidecar_a),
            Ok(true),
            "observed block is indicated as true"
        );

        assert_eq!(
            cache.observe_sidecar(&sidecar_a),
            Ok(true),
            "observing again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present"
        );

        // Slot 1, proposer 0

        let proposer_index_b = 421;
        let sidecar_b = get_blob_sidecar(1, proposer_index_b, 0);

        assert_eq!(
            cache.proposer_is_known(&sidecar_b),
            Ok(false),
            "no observation for new slot"
        );
        assert_eq!(
            cache.observe_sidecar(&sidecar_b),
            Ok(false),
            "can observe proposer for new slot, indicates proposer unobserved"
        );
        assert_eq!(
            cache.proposer_is_known(&sidecar_b),
            Ok(true),
            "observed block in slot 1 is indicated as true"
        );
        assert_eq!(
            cache.observe_sidecar(&sidecar_b),
            Ok(true),
            "observing slot 1 again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 2, "two slots should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present in slot 0"
        );
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_b, Slot::new(1)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            1,
            "only one proposer should be present in slot 1"
        );

        // Slot 0, index 1
        let sidecar_c = get_blob_sidecar(0, proposer_index_a, 1);

        assert_eq!(
            cache.proposer_is_known(&sidecar_c),
            Ok(false),
            "no observation for new index"
        );
        assert_eq!(
            cache.observe_sidecar(&sidecar_c),
            Ok(false),
            "can observe new index, indicates sidecar unobserved for new index"
        );
        assert_eq!(
            cache.proposer_is_known(&sidecar_c),
            Ok(true),
            "observed new sidecar is indicated as true"
        );
        assert_eq!(
            cache.observe_sidecar(&sidecar_c),
            Ok(true),
            "observing new sidecar again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 2, "two slots should be present");
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            2,
            "two blob indices should be present in slot 0"
        );

        // Create a sidecar sharing slot and proposer but with a different block root.
        let mut sidecar_d: BlobSidecar<E> = BlobSidecar {
            index: sidecar_c.index,
            blob: sidecar_c.blob.clone(),
            kzg_commitment: sidecar_c.kzg_commitment,
            kzg_proof: sidecar_c.kzg_proof,
            signed_block_header: sidecar_c.signed_block_header.clone(),
            kzg_commitment_inclusion_proof: sidecar_c.kzg_commitment_inclusion_proof.clone(),
        };
        sidecar_d.signed_block_header.message.body_root = Hash256::repeat_byte(7);
        assert_eq!(
            cache.proposer_is_known(&sidecar_d),
            Ok(true),
            "there has been an observation for this proposer index"
        );
        assert_eq!(
            cache.observe_sidecar(&sidecar_d),
            Ok(true),
            "indicates sidecar proposer was observed"
        );
        let cached_blob_indices = cache
            .items
            .get(&ProposalKey::new(proposer_index_a, Slot::new(0)))
            .expect("slot zero should be present");
        assert_eq!(
            cached_blob_indices.len(),
            2,
            "two blob indices should be present in slot 0"
        );

        // Try adding an out of bounds index
        let invalid_index = E::max_blobs_per_block() as u64;
        let sidecar_d = get_blob_sidecar(0, proposer_index_a, invalid_index);
        assert_eq!(
            cache.observe_sidecar(&sidecar_d),
            Err(Error::InvalidDataIndex(invalid_index)),
            "cannot add an index > MaxBlobsPerBlock"
        );
    }
}
