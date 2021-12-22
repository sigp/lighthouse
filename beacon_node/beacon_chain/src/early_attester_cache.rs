use proto_array::Block as ProtoBlock;
use types::*;

pub struct CacheItem<E: EthSpec> {
    /*
     * Attesting details
     */
    epoch: Epoch,
    committee_len: usize,
    committee_count: u64,
    beacon_block_root: Hash256,
    source: Checkpoint,
    target: Checkpoint,
    /*
     * Cached values
     */
    block: SignedBeaconBlock<E>,
    proto_block: ProtoBlock,
}

#[derive(Default)]
pub struct EarlyAttesterCache<E: EthSpec> {
    item: Option<CacheItem<E>>,
}

impl<E: EthSpec> EarlyAttesterCache<E> {
    pub fn clear(&mut self) {
        self.item = None
    }

    pub fn add_head_block(
        &mut self,
        beacon_block_root: Hash256,
        block: SignedBeaconBlock<E>,
        proto_block: ProtoBlock,
        state: &BeaconState<E>,
    ) -> Result<(), BeaconStateError> {
        let epoch = state.current_epoch();
        let committee_len = state.get_beacon_committee(state.slot(), 0)?.committee.len();
        let committee_count = state.get_epoch_committee_count(RelativeEpoch::Current)?;
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
            committee_len,
            committee_count,
            beacon_block_root,
            source,
            target,
            block,
            proto_block,
        };

        self.item = Some(item);

        Ok(())
    }

    pub fn try_attest(
        &self,
        request_slot: Slot,
        request_index: CommitteeIndex,
    ) -> Option<Attestation<E>> {
        let item = self.item.as_ref()?;
        let request_epoch = request_slot.epoch(E::slots_per_epoch());

        if request_epoch != item.epoch {
            return None;
        }

        if request_index >= item.committee_count {
            return None;
        }

        Some(Attestation {
            aggregation_bits: BitList::with_capacity(item.committee_len).ok()?,
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

    pub fn get_block(&self, block_root: Hash256) -> Option<&SignedBeaconBlock<E>> {
        self.item
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| &item.block)
    }

    pub fn get_proto_block(&self, block_root: Hash256) -> Option<&ProtoBlock> {
        self.item
            .as_ref()
            .filter(|item| item.beacon_block_root == block_root)
            .map(|item| &item.proto_block)
    }
}
