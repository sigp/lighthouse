use crate::data_availability_checker::AvailabilityView;
use ssz_types::FixedVector;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use types::beacon_block_body::{KzgCommitmentOpts, KzgCommitments};
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::signed_beacon_block::get_missing_blob_ids;
use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};

/// This cache is used only for gossip blocks/blobs and single block/blob lookups, to give req/resp
/// a view of what we have and what we require. This cache serves a slightly different purpose than
/// gossip caches because it allows us to process duplicate blobs that are valid in gossip.
/// See `AvailabilityView`'s trait definition.
#[derive(Default)]
pub struct ProcessingCache<E: EthSpec> {
    processing_cache: HashMap<Hash256, ProcessingInfo<E>>,
}

impl<E: EthSpec> ProcessingCache<E> {
    pub fn get(&self, block_root: &Hash256) -> Option<&ProcessingInfo<E>> {
        self.processing_cache.get(block_root)
    }
    pub fn entry(&mut self, block_root: Hash256) -> Entry<'_, Hash256, ProcessingInfo<E>> {
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

#[derive(Default)]
pub struct ProcessingInfo<E: EthSpec> {
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

impl<E: EthSpec> ProcessingInfo<E> {
    pub fn from_parts(
        block: Option<&Arc<SignedBeaconBlock<E>>>,
        blobs: &FixedBlobSidecarList<E>,
    ) -> Option<Self> {
        let block_slot = block.map(|block| block.message().slot());
        let blob_slot = blobs.iter().find_map(|b| b.as_ref()).map(|b| b.slot);
        let slot = block_slot.or(blob_slot)?;
        let block_commitments = block.map(|block| {
            block
                .message()
                .body()
                .blob_kzg_commitments()
                .cloned()
                .unwrap_or_default()
        });
        let blobs = blobs
            .iter()
            .map(|blob_opt| blob_opt.as_ref().map(|blob| blob.kzg_commitment))
            .collect::<Vec<_>>();
        Some(Self {
            slot,
            kzg_commitments: block_commitments,
            processing_blobs: FixedVector::new(blobs).ok()?,
        })
    }
    pub fn get_missing_blob_ids(&self, block_root: Hash256) -> Vec<BlobIdentifier> {
        get_missing_blob_ids::<E>(
            block_root,
            self.kzg_commitments.as_ref(),
            &self.processing_blobs,
        )
    }
}
