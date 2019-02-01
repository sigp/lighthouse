use super::{BeaconChain, CheckPoint, ClientDB, DBError, SlotClock};
use types::Hash256;

#[derive(Debug, Clone)]
pub enum Error {
    /// There was an error reading from the database. This is an internal error.
    DBError(String),
    /// There is a missing (or invalid) block in the database. This is an internal error.
    MissingBlock(Hash256),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, Error> {
        let mut dump = vec![];

        let mut last_slot = CheckPoint {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root;

            if beacon_block_root == self.spec.zero_hash {
                break; // Genesis has been reached.
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

            let slot = CheckPoint {
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
