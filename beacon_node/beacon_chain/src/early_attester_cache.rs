use crate::{
    attester_cache::{CommitteeLengths, Error},
    metrics,
};
use parking_lot::RwLock;
use proto_array::Block as ProtoBlock;
use types::*;

pub struct CacheItem<E: EthSpec> {
    /*
     * Attesting details
     */
    epoch: Epoch,
    committee_lengths: CommitteeLengths,
    beacon_block_root: Hash256,
    source: Checkpoint,
    target: Checkpoint,
    /*
     * Cached values
     */
    block: SignedBeaconBlock<E>,
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
        block: SignedBeaconBlock<E>,
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

        let item = CacheItem {
            epoch,
            committee_lengths,
            beacon_block_root,
            source,
            target,
            block,
            proto_block,
        };

        *self.item.write() = Some(item);

        Ok(())
    }

    /// Will return `Some(attestation)` if:
    ///
    /// - There is a cache `item` present.
    /// - If `request_slot` is in the same epoch as `item.epoch`.
    /// - If `request_index` does not exceed `item.comittee_count`.
    pub fn try_attest(
        &self,
        request_slot: Slot,
        request_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Option<Attestation<E>> {
        let lock = self.item.read();
        let item = lock.as_ref()?;

        let request_epoch = request_slot.epoch(E::slots_per_epoch());
        if request_epoch != item.epoch {
            return None;
        }

        let committee_count = item
            .committee_lengths
            .get_committee_count_per_slot::<E>(spec)
            .ok()?;
        if request_index >= committee_count as u64 {
            return None;
        }

        let committee_len = item
            .committee_lengths
            .get_committee_length::<E>(request_slot, request_index, spec)
            .ok()?;

        metrics::inc_counter(&metrics::BEACON_EARLY_ATTESTER_CACHE_HITS);

        Some(Attestation {
            aggregation_bits: BitList::with_capacity(committee_len).ok()?,
            data: AttestationData {
                slot: request_slot,
                index: request_index,
                beacon_block_root: item.beacon_block_root,
                source: item.source,
                target: item.target,
            },
            signature: AggregateSignature::empty(),
        })
    }

    /// Returns `true` if `block_root` matches the cached item.
    pub fn contains_block(&self, block_root: Hash256) -> bool {
        self.item
            .read()
            .as_ref()
            .map_or(false, |item| item.beacon_block_root == block_root)
    }

    /// Returns the block, if `block_root` matches the cached item.
    pub fn get_block(&self, block_root: Hash256) -> Option<SignedBeaconBlock<E>> {
        self.item
            .read()
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| item.block.clone())
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
