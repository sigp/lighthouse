use attester::{
    BeaconNode as AttesterBeaconNode, BeaconNodeError as NodeError,
    PublishOutcome as AttestationPublishOutcome,
};
use beacon_chain::BeaconChain;
use block_proposer::{
    BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError,
    PublishOutcome as BlockPublishOutcome,
};
use db::ClientDB;
use fork_choice::ForkChoice;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{AttestationData, BeaconBlock, FreeAttestation, Signature, Slot};

// mod attester;
// mod producer;

/// Connect directly to a borrowed `BeaconChain` instance so an attester/producer can request/submit
/// blocks/attestations.
///
/// `BeaconBlock`s and `FreeAttestation`s are not actually published to the `BeaconChain`, instead
/// they are stored inside this struct. This is to allow one to benchmark the submission of the
/// block/attestation directly, or modify it before submission.
pub struct DirectBeaconNode<T: ClientDB, U: SlotClock, F: ForkChoice> {
    beacon_chain: Arc<BeaconChain<T, U, F>>,
    published_blocks: RwLock<Vec<BeaconBlock>>,
    published_attestations: RwLock<Vec<FreeAttestation>>,
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> DirectBeaconNode<T, U, F> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U, F>>) -> Self {
        Self {
            beacon_chain,
            published_blocks: RwLock::new(vec![]),
            published_attestations: RwLock::new(vec![]),
        }
    }

    /// Get the last published block (if any).
    pub fn last_published_block(&self) -> Option<BeaconBlock> {
        Some(self.published_blocks.read().last()?.clone())
    }

    /// Get the last published attestation (if any).
    pub fn last_published_free_attestation(&self) -> Option<FreeAttestation> {
        Some(self.published_attestations.read().last()?.clone())
    }
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> AttesterBeaconNode for DirectBeaconNode<T, U, F> {
    fn produce_attestation(
        &self,
        _slot: Slot,
        shard: u64,
    ) -> Result<Option<AttestationData>, NodeError> {
        match self.beacon_chain.produce_attestation(shard) {
            Ok(attestation_data) => Ok(Some(attestation_data)),
            Err(e) => Err(NodeError::RemoteFailure(format!("{:?}", e))),
        }
    }

    fn publish_attestation(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<AttestationPublishOutcome, NodeError> {
        self.published_attestations.write().push(free_attestation);
        Ok(AttestationPublishOutcome::ValidAttestation)
    }
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> BeaconBlockNode for DirectBeaconNode<T, U, F> {
    /// Requests a new `BeaconBlock from the `BeaconChain`.
    fn produce_beacon_block(
        &self,
        slot: Slot,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconBlockNodeError> {
        let (block, _state) = self
            .beacon_chain
            .produce_block(randao_reveal.clone())
            .map_err(|e| {
                BeaconBlockNodeError::RemoteFailure(format!("Did not produce block: {:?}", e))
            })?;

        if block.slot == slot {
            Ok(Some(block))
        } else {
            Err(BeaconBlockNodeError::RemoteFailure(
                "Unable to produce at non-current slot.".to_string(),
            ))
        }
    }

    /// A block is not _actually_ published to the `BeaconChain`, instead it is stored in the
    /// `published_block_vec` and a successful `ValidBlock` is returned to the caller.
    ///
    /// The block may be retrieved and then applied to the `BeaconChain` manually, potentially in a
    /// benchmarking scenario.
    fn publish_beacon_block(
        &self,
        block: BeaconBlock,
    ) -> Result<BlockPublishOutcome, BeaconBlockNodeError> {
        self.published_blocks.write().push(block);
        Ok(BlockPublishOutcome::ValidBlock)
    }
}
