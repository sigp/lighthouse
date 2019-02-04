use super::DirectBeaconNode;
use block_producer::{
    BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError, PublishOutcome,
};
use db::ClientDB;
use slot_clock::SlotClock;
use types::{BeaconBlock, PublicKey, Signature};

impl<T: ClientDB, U: SlotClock> BeaconBlockNode for DirectBeaconNode<T, U> {
    /// Requests the `proposer_nonce` from the `BeaconChain`.
    fn proposer_nonce(&self, pubkey: &PublicKey) -> Result<u64, BeaconBlockNodeError> {
        let validator_index = self
            .beacon_chain
            .validator_index(pubkey)
            .ok_or_else(|| BeaconBlockNodeError::RemoteFailure("pubkey unknown.".to_string()))?;

        self.beacon_chain
            .proposer_slots(validator_index)
            .ok_or_else(|| {
                BeaconBlockNodeError::RemoteFailure("validator_index unknown.".to_string())
            })
    }

    /// Requests a new `BeaconBlock from the `BeaconChain`.
    fn produce_beacon_block(
        &self,
        slot: u64,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconBlockNodeError> {
        let (block, _state) = self
            .beacon_chain
            .produce_block(randao_reveal.clone())
            .ok_or_else(|| {
                BeaconBlockNodeError::RemoteFailure(format!("Did not produce block."))
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
    ) -> Result<PublishOutcome, BeaconBlockNodeError> {
        self.published_blocks.write().push(block);
        Ok(PublishOutcome::ValidBlock)
    }
}
