//! Provides the `ObservedBlobSidecars` struct which allows for rejecting `BlobSidecar`s
//! that we have already seen over the gossip network.
//! Only `BlobSidecar`s that have completed proposer signature verification can be added
//! to this cache to reduce DoS risks.

use crate::observed_block_producers::ProposalKey;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::{BlobSidecar, EthSpec, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided `BlobSidecar` is prior to finalization and should not have been provided
    /// to this function. This is an internal error.
    FinalizedBlob { slot: Slot, finalized_slot: Slot },
    /// The blob sidecar contains an invalid blob index, the blob sidecar is invalid.
    /// Note: The invalid blob should have been caught and flagged as an error much before reaching
    /// here.
    InvalidBlobIndex(u64),
}

/// Maintains a cache of seen `BlobSidecar`s that are received over gossip
/// and have been gossip verified.
///
/// The cache supports pruning based upon the finalized epoch. It does not automatically prune, you
/// must call `Self::prune` manually.
///
/// Note: To prevent DoS attacks, this cache must include only items that have received some DoS resistance
/// like checking the proposer signature.
pub struct ObservedBlobSidecars<E: EthSpec> {
    finalized_slot: Slot,
    /// Stores all received blob indices for a given `(ValidatorIndex, Slot)` tuple.
    items: HashMap<ProposalKey, HashSet<u64>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedBlobSidecars<E> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    fn default() -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedBlobSidecars<E> {
    /// Observe the `blob_sidecar` at (`blob_sidecar.block_proposer_index, blob_sidecar.slot`).
    /// This will update `self` so future calls to it indicate that this `blob_sidecar` is known.
    ///
    /// The supplied `blob_sidecar` **MUST** have completed proposer signature verification.
    pub fn observe_sidecar(&mut self, blob_sidecar: &BlobSidecar<E>) -> Result<bool, Error> {
        self.sanitize_blob_sidecar(blob_sidecar)?;

        let blob_indices = self
            .items
            .entry(ProposalKey {
                slot: blob_sidecar.slot(),
                proposer: blob_sidecar.block_proposer_index(),
            })
            .or_insert_with(|| HashSet::with_capacity(E::max_blobs_per_block()));
        let did_not_exist = blob_indices.insert(blob_sidecar.index);

        Ok(!did_not_exist)
    }

    /// Returns `true` if the `blob_sidecar` has already been observed in the cache within the prune window.
    pub fn proposer_is_known(&self, blob_sidecar: &BlobSidecar<E>) -> Result<bool, Error> {
        self.sanitize_blob_sidecar(blob_sidecar)?;
        let is_known = self
            .items
            .get(&ProposalKey {
                slot: blob_sidecar.slot(),
                proposer: blob_sidecar.block_proposer_index(),
            })
            .map_or(false, |blob_indices| {
                blob_indices.contains(&blob_sidecar.index)
            });
        Ok(is_known)
    }

    fn sanitize_blob_sidecar(&self, blob_sidecar: &BlobSidecar<E>) -> Result<(), Error> {
        if blob_sidecar.index >= E::max_blobs_per_block() as u64 {
            return Err(Error::InvalidBlobIndex(blob_sidecar.index));
        }
        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && blob_sidecar.slot() <= finalized_slot {
            return Err(Error::FinalizedBlob {
                slot: blob_sidecar.slot(),
                finalized_slot,
            });
        }

        Ok(())
    }

    /// Prune `blob_sidecar` observations for slots less than or equal to the given slot.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|k, _| k.slot > finalized_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut cache = ObservedBlobSidecars::default();

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
            Err(Error::FinalizedBlob {
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
        let mut cache = ObservedBlobSidecars::default();

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
            Err(Error::InvalidBlobIndex(invalid_index)),
            "cannot add an index > MaxBlobsPerBlock"
        );
    }
}
