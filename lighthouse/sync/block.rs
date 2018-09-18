use std::sync::Arc;
use super::db::ClientDB;
use slog::Logger;

pub enum BlockStatus {
    Valid,
    AlreadyKnown,
    TooOld,
    TimeInvalid,
    UnknownPoWHash,
    NoAttestations,
    InvalidAttestation,
    NotProposerSigned,
}

pub fn process_unverified_blocks(
    _serialized_block: &[u8],
    _db: Arc<ClientDB>,
    _log: Logger)
{
    //
}


