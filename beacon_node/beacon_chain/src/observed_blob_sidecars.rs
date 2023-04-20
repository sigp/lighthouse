//! Provides the `ObservedBlobSidecars` struct which allows for rejecting `BlobSidecar`s
//! that we have already seen over the gossip network.
//! Only `BlobSidecar`s that have completed proposer signature verification can be added
//! to this cache to reduce DoS risks.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BlobSidecar, EthSpec, Hash256, Slot};

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
pub struct ObservedBlobSidecars<T: EthSpec> {
    finalized_slot: Slot,
    /// Stores all received blob indices for a given `(Root, Slot)` tuple.
    items: HashMap<(Hash256, Slot), HashSet<u64>>,
    _phantom: PhantomData<T>,
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

impl<T: EthSpec> ObservedBlobSidecars<T> {
    /// Observe the `blob_sidecar` at (`blob_sidecar.block_root, blob_sidecar.slot`).
    /// This will update `self` so future calls to it indicate that this `blob_sidecar` is known.
    ///
    /// The supplied `blob_sidecar` **MUST** have completed proposer signature verification.
    pub fn observe_sidecar(&mut self, blob_sidecar: &Arc<BlobSidecar<T>>) -> Result<bool, Error> {
        self.sanitize_blob_sidecar(blob_sidecar)?;

        let did_not_exist = self
            .items
            .entry((blob_sidecar.block_root, blob_sidecar.slot))
            .or_insert_with(|| HashSet::with_capacity(T::max_blobs_per_block()))
            .insert(blob_sidecar.index);

        Ok(!did_not_exist)
    }

    /// Returns `true` if the `blob_sidecar` has already been observed in the cache within the prune window.
    pub fn is_known(&self, blob_sidecar: &Arc<BlobSidecar<T>>) -> Result<bool, Error> {
        self.sanitize_blob_sidecar(blob_sidecar)?;
        let is_known = self
            .items
            .get(&(blob_sidecar.block_root, blob_sidecar.slot))
            .map_or(false, |set| set.contains(&blob_sidecar.index));
        Ok(is_known)
    }

    fn sanitize_blob_sidecar(&self, blob_sidecar: &Arc<BlobSidecar<T>>) -> Result<(), Error> {
        if blob_sidecar.index >= T::max_blobs_per_block() as u64 {
            return Err(Error::InvalidBlobIndex(blob_sidecar.index));
        }
        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && blob_sidecar.slot <= finalized_slot {
            return Err(Error::FinalizedBlob {
                slot: blob_sidecar.slot,
                finalized_slot,
            });
        }

        Ok(())
    }

    /// Prune all values earlier than the given slot.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|k, _| k.1 > finalized_slot);
    }
}
