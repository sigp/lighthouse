use crate::blockprint::Error as BlockprintError;
use crate::database::Error as DbError;
use beacon_node::beacon_chain::BeaconChainError;
use eth2::{Error as Eth2Error, SensitiveError};
use std::fmt;

#[derive(Debug)]
pub enum Error {
    BeaconChain(BeaconChainError),
    Eth2(Eth2Error),
    SensitiveUrl(SensitiveError),
    Database(DbError),
    Blockprint(BlockprintError),
    UnableToGetRemoteHead,
    BeaconNodeSyncing,
    NotEnabled(String),
    NoValidatorsFound,
    BeaconNodeNotCompatible(String),
    InvalidConfig(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChain(e)
    }
}

impl From<Eth2Error> for Error {
    fn from(e: Eth2Error) -> Self {
        Error::Eth2(e)
    }
}

impl From<SensitiveError> for Error {
    fn from(e: SensitiveError) -> Self {
        Error::SensitiveUrl(e)
    }
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        Error::Database(e)
    }
}

impl From<BlockprintError> for Error {
    fn from(e: BlockprintError) -> Self {
        Error::Blockprint(e)
    }
}
