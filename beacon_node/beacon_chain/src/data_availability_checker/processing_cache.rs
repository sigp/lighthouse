use crate::data_availability_checker::AvailabilityView;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use types::beacon_block_body::{KzgCommitmentOpts, KzgCommitments};
use types::{EthSpec, Hash256, Slot};

/// This cache is used only for gossip blocks/blobs and single block/blob lookups, to give req/resp
/// a view of what we have and what we require. This cache serves a slightly different purpose than
/// gossip caches because it allows us to process duplicate blobs that are valid in gossip.
/// See `AvailabilityView`'s trait definition.
#[derive(Default)]
pub struct ProcessingCache<E: EthSpec> {
    processing_cache: HashMap<Hash256, ProcessingView<E>>,
}

impl<E: EthSpec> ProcessingCache<E> {
    pub fn get(&self, block_root: &Hash256) -> Option<&ProcessingView<E>> {
        self.processing_cache.get(block_root)
    }
    pub fn entry(&mut self, block_root: Hash256) -> Entry<'_, Hash256, ProcessingView<E>> {
        self.processing_cache.entry(block_root)
    }
    pub fn remove(&mut self, block_root: &Hash256) {
        self.processing_cache.remove(block_root);
    }
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.processing_cache
            .get(block_root)
            .map_or(false, |b| b.kzg_commitments.is_some())
    }
    pub fn blocks_with_missing_components(&self, slot: Slot) -> Vec<Hash256> {
        let mut roots_missing_components = vec![];
        for (&block_root, info) in self.processing_cache.iter() {
            if info.slot == slot && !info.is_available() {
                roots_missing_components.push(block_root);
            }
        }
        roots_missing_components
    }
}

#[derive(Debug, Clone)]
pub struct ProcessingView<E: EthSpec> {
    slot: Slot,
    /// Blobs required for a block can only be known if we have seen the block. So `Some` here
    /// means we've seen it, a `None` means we haven't. The `kzg_commitments` value helps us figure
    /// out whether incoming blobs actually match the block.
    pub kzg_commitments: Option<KzgCommitments<E>>,
    /// On insertion, a collision at an index here when `required_blobs` is
    /// `None` means we need to construct an entirely new `Data` entry. This is because we have
    /// no way of knowing which blob is the correct one until we see the block.
    pub processing_blobs: KzgCommitmentOpts<E>,
}

impl<E: EthSpec> ProcessingView<E> {
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            kzg_commitments: None,
            processing_blobs: KzgCommitmentOpts::<E>::default(),
        }
    }

    #[cfg(test)]
    pub fn default() -> Self {
        Self {
            slot: Slot::new(0),
            kzg_commitments: None,
            processing_blobs: KzgCommitmentOpts::<E>::default(),
        }
    }
}
