use beacon_chain::{block_production::Error as BlockProductionError, BeaconChain};
use block_producer::{BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError};
use db::ClientDB;
use slot_clock::SlotClock;
use types::{BeaconBlock, PublicKey, Signature};

pub struct DirectBeaconNode<'a, T: ClientDB, U: SlotClock> {
    beacon_chain: &'a BeaconChain<T, U>,
}

impl<'a, T: ClientDB, U: SlotClock> DirectBeaconNode<'a, T, U> {
    pub fn new(beacon_chain: &'a BeaconChain<T, U>) -> Self {
        Self { beacon_chain }
    }
}

impl<'a, T: ClientDB, U: SlotClock> BeaconBlockNode for DirectBeaconNode<'a, T, U>
where
    BlockProductionError: From<<U>::Error>,
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

    /// Returns the value specified by the `set_next_publish_result`.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconBlockNodeError> {
        Err(BeaconBlockNodeError::DecodeFailure)
    }
}
