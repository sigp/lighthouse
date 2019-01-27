use beacon_chain::block_processing::{Error as ProcessingError, Outcome as ProcessingOutcome};
use beacon_chain::{block_production::Error as BlockProductionError, BeaconChain};
use block_producer::{
    BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError, PublishOutcome,
};
use db::ClientDB;
use slot_clock::SlotClock;
use std::sync::{Arc, RwLock};
use types::{BeaconBlock, PublicKey, Signature};

pub struct BenchingBeaconNode<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
    published_blocks: RwLock<Vec<BeaconBlock>>,
}

impl<T: ClientDB, U: SlotClock> BenchingBeaconNode<T, U> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self {
            beacon_chain,
            published_blocks: RwLock::new(vec![]),
        }
    }

    pub fn last_published_block(&self) -> Option<BeaconBlock> {
        Some(
            self.published_blocks
                .read()
                .expect("Unable to unlock `published_blocks` for reading.")
                .last()?
                .clone(),
        )
    }
}

impl<T: ClientDB, U: SlotClock> BeaconBlockNode for BenchingBeaconNode<T, U>
where
    BlockProductionError: From<<U>::Error>,
    ProcessingError: From<<U as SlotClock>::Error>,
{
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

    /// A block is not _actually_ published to the `BeaconChain`, instead it is stored in the
    /// `published_block_vec` and a successful `ValidBlock` is returned to the caller.
    ///
    /// The block may be retrieved and then applied to the `BeaconChain` manually, potentially in a
    /// benchmarking scenario.
    fn publish_beacon_block(
        &self,
        block: BeaconBlock,
    ) -> Result<PublishOutcome, BeaconBlockNodeError> {
        self.published_blocks
            .write()
            .expect("Unable to unlock `published_blocks` for writing.")
            .push(block);
        Ok(PublishOutcome::ValidBlock)
    }
}
