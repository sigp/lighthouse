use beacon_chain::block_processing::{Error as ProcessingError, Outcome as ProcessingOutcome};
use beacon_chain::{block_production::Error as BlockProductionError, BeaconChain};
use block_producer::{
    BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError, PublishOutcome,
};
use db::ClientDB;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{BeaconBlock, PublicKey, Signature};

pub struct DirectBeaconNode<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
}

impl<T: ClientDB, U: SlotClock> DirectBeaconNode<T, U> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self { beacon_chain }
    }
}

impl<T: ClientDB, U: SlotClock> BeaconBlockNode for DirectBeaconNode<T, U>
where
    BlockProductionError: From<<U>::Error>,
    ProcessingError: From<<U as SlotClock>::Error>,
{
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

    fn produce_beacon_block(
        &self,
        slot: u64,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconBlockNodeError>
where {
        let (block, _state) = self
            .beacon_chain
            .produce_block(randao_reveal.clone())
            .map_err(|e| BeaconBlockNodeError::RemoteFailure(format!("{:?}", e)))?;

        if block.slot == slot {
            Ok(Some(block))
        } else {
            Err(BeaconBlockNodeError::RemoteFailure(
                "Unable to produce at non-current slot.".to_string(),
            ))
        }
    }

    fn publish_beacon_block(
        &self,
        block: BeaconBlock,
    ) -> Result<PublishOutcome, BeaconBlockNodeError> {
        match self.beacon_chain.process_block(block) {
            Ok(ProcessingOutcome::ValidBlock(_)) => Ok(PublishOutcome::ValidBlock),
            Ok(ProcessingOutcome::InvalidBlock(reason)) => {
                Ok(PublishOutcome::InvalidBlock(format!("{:?}", reason)))
            }
            Err(error) => Err(BeaconBlockNodeError::RemoteFailure(format!("{:?}", error))),
        }
    }
}
