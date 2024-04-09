use crate::data_availability_checker::AvailabilityView;
use ssz_types::FixedVector;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use types::beacon_block_body::KzgCommitmentOpts;
use types::{EthSpec, Hash256, SignedBeaconBlock};

/// This cache is used only for gossip blocks/blobs and single block/blob lookups, to give req/resp
/// a view of what we have and what we require. This cache serves a slightly different purpose than
/// gossip caches because it allows us to process duplicate blobs that are valid in gossip.
/// See `AvailabilityView`'s trait definition.
#[derive(Default)]
pub struct ProcessingCache<E: EthSpec> {
    processing_cache: HashMap<Hash256, ProcessingComponents<E>>,
}

impl<E: EthSpec> ProcessingCache<E> {
    pub fn get(&self, block_root: &Hash256) -> Option<&ProcessingComponents<E>> {
        self.processing_cache.get(block_root)
    }
    pub fn entry(&mut self, block_root: Hash256) -> Entry<'_, Hash256, ProcessingComponents<E>> {
        self.processing_cache.entry(block_root)
    }
    pub fn remove(&mut self, block_root: &Hash256) {
        self.processing_cache.remove(block_root);
    }
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.processing_cache
            .get(block_root)
            .map_or(false, |b| b.block_exists())
    }
    pub fn len(&self) -> usize {
        self.processing_cache.len()
    }
}

#[derive(Default, Debug, Clone)]
pub struct ProcessingComponents<E: EthSpec> {
    /// Blobs required for a block can only be known if we have seen the block. So `Some` here
    /// means we've seen it, a `None` means we haven't. The `kzg_commitments` value helps us figure
    /// out whether incoming blobs actually match the block.
    pub block: Option<Arc<SignedBeaconBlock<E>>>,
    /// `KzgCommitments` for blobs are always known, even if we haven't seen the block. See
    /// `AvailabilityView`'s trait definition for more details.
    pub blob_commitments: KzgCommitmentOpts<E>,
    // TODO(das): `KzgCommitments` are available in every data column sidecar, hence it may not be useful to store them
    // again here and a `()` may be sufficient to indicate what we have.
    pub data_column_opts: FixedVector<Option<()>, E::DataColumnCount>,
}

impl<E: EthSpec> ProcessingComponents<E> {
    pub fn new() -> Self {
        Self::default()
    }
}

// Not safe for use outside of tests as this always required a slot.
#[cfg(test)]
impl<E: EthSpec> ProcessingComponents<E> {
    pub fn empty(_block_root: Hash256) -> Self {
        Self {
            block: None,
            blob_commitments: KzgCommitmentOpts::<E>::default(),
            data_column_opts: FixedVector::default(),
        }
    }
}
