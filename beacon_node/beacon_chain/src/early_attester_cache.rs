use crate::{
    attester_cache::{CommitteeLengths, Error},
    metrics,
};
use parking_lot::RwLock;
use proto_array::Block as ProtoBlock;
use std::sync::Arc;
use store::signed_block_and_blobs::BlockWrapper;
use types::*;

pub struct CacheItem<E: EthSpec> {
    /*
     * Values used to create attestations.
     */
    epoch: Epoch,
    committee_lengths: CommitteeLengths,
    beacon_block_root: Hash256,
    source: Checkpoint,
    target: Checkpoint,
    /*
     * Values used to make the block available.
     */
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Option<Arc<BlobsSidecar<E>>>,
    proto_block: ProtoBlock,
}

/// Provides a single-item cache which allows for attesting to blocks before those blocks have
/// reached the database.
///
/// This cache stores enough information to allow Lighthouse to:
///
/// - Produce an attestation without using `chain.canonical_head`.
/// - Verify that a block root exists (i.e., will be imported in the future) during attestation
///     verification.
/// - Provide a block which can be sent to peers via RPC.
#[derive(Default)]
pub struct EarlyAttesterCache<E: EthSpec> {
    item: RwLock<Option<CacheItem<E>>>,
}

impl<E: EthSpec> EarlyAttesterCache<E> {
    /// Removes the cached item, meaning that all future calls to `Self::try_attest` will return
    /// `None` until a new cache item is added.
    pub fn clear(&self) {
        *self.item.write() = None
    }

    /// Updates the cache item, so that `Self::try_attest` with return `Some` when given suitable
    /// parameters.
    pub fn add_head_block(
        &self,
        beacon_block_root: Hash256,
        block: BlockWrapper<E>,
        proto_block: ProtoBlock,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let epoch = state.current_epoch();
        let committee_lengths = CommitteeLengths::new(state, spec)?;
        let source = state.current_justified_checkpoint();
        let target_slot = epoch.start_slot(E::slots_per_epoch());
        let target = Checkpoint {
            epoch,
            root: if state.slot() <= target_slot {
                beacon_block_root
            } else {
                *state.get_block_root(target_slot)?
            },
        };

        let (block, blobs) = block.deconstruct(Some(beacon_block_root));
        let item = CacheItem {
            epoch,
            committee_lengths,
            beacon_block_root,
            source,
            target,
            block,
            blobs: blobs.map_err(|_| Error::MissingBlobs)?,
            proto_block,
        };

        *self.item.write() = Some(item);

        Ok(())
    }

    /// Will return `Some(attestation)` if all the following conditions are met:
    ///
    /// - There is a cache `item` present.
    /// - If `request_slot` is in the same epoch as `item.epoch`.
    /// - If `request_index` does not exceed `item.committee_count`.
    pub fn try_attest(
        &self,
        request_slot: Slot,
        request_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<Option<Attestation<E>>, Error> {
        let lock = self.item.read();
        let item = if let Some(item) = lock.as_ref() {
            item
        } else {
            return Ok(None);
        };

        let request_epoch = request_slot.epoch(E::slots_per_epoch());
        if request_epoch != item.epoch {
            return Ok(None);
        }

        if request_slot < item.block.slot() {
            return Ok(None);
        }

        let committee_count = item
            .committee_lengths
            .get_committee_count_per_slot::<E>(spec)?;
        if request_index >= committee_count as u64 {
            return Ok(None);
        }

        let committee_len =
            item.committee_lengths
                .get_committee_length::<E>(request_slot, request_index, spec)?;

        let attestation = Attestation {
            aggregation_bits: BitList::with_capacity(committee_len)
                .map_err(BeaconStateError::from)?,
            data: AttestationData {
                slot: request_slot,
                index: request_index,
                beacon_block_root: item.beacon_block_root,
                source: item.source,
                target: item.target,
            },
            signature: AggregateSignature::empty(),
        };

        metrics::inc_counter(&metrics::BEACON_EARLY_ATTESTER_CACHE_HITS);

        Ok(Some(attestation))
    }

    /// Returns `true` if `block_root` matches the cached item.
    pub fn contains_block(&self, block_root: Hash256) -> bool {
        self.item
            .read()
            .as_ref()
            .map_or(false, |item| item.beacon_block_root == block_root)
    }

    /// Returns the block, if `block_root` matches the cached item.
    pub fn get_block(&self, block_root: Hash256) -> Option<Arc<SignedBeaconBlock<E>>> {
        self.item
            .read()
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| item.block.clone())
    }

    /// Returns the blobs, if `block_root` matches the cached item.
    pub fn get_blobs(&self, block_root: Hash256) -> Option<Arc<BlobsSidecar<E>>> {
        self.item
            .read()
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| item.blobs.clone())
            .flatten()
    }

    /// Returns the proto-array block, if `block_root` matches the cached item.
    pub fn get_proto_block(&self, block_root: Hash256) -> Option<ProtoBlock> {
        self.item
            .read()
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| item.proto_block.clone())
    }
}
