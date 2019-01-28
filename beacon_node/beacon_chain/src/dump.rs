use super::{BeaconChain, ClientDB, DBError, SlotClock};
use serde_derive::Serialize;
use types::{BeaconBlock, BeaconState, Hash256};

#[derive(Debug, Clone, Serialize)]
pub struct SlotDump {
    pub beacon_block: BeaconBlock,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState,
    pub beacon_state_root: Hash256,
}

#[derive(Debug, Clone)]
pub enum Error {
    DBError(String),
    MissingBlock(Hash256),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn chain_dump(&self) -> Result<Vec<SlotDump>, Error> {
        let mut dump = vec![];

        let mut last_slot = SlotDump {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root;

            if beacon_block_root == self.spec.zero_hash {
                // Genesis has been reached.
                break;
            }

            let beacon_block = self
                .block_store
                .get_deserialized(&beacon_block_root)?
                .ok_or_else(|| Error::MissingBlock(beacon_block_root))?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self
                .state_store
                .get_deserialized(&beacon_state_root)?
                .ok_or_else(|| Error::MissingBlock(beacon_state_root))?;

            let slot = SlotDump {
                beacon_block,
                beacon_block_root,
                beacon_state,
                beacon_state_root,
            };

            dump.push(slot.clone());
            last_slot = slot;
        }

        Ok(dump)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}
