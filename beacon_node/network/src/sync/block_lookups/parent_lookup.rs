use lighthouse_network::PeerId;
use store::{EthSpec, Hash256, SignedBeaconBlock};

use crate::sync::manager::Id;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
pub(crate) struct ParentLookup<T: EthSpec> {
    /// The root of the block triggering this parent request.
    chain_hash: Hash256,

    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,

    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,

    /// The peer who last submitted a block. If the chain ends or fails, this is the peer that is
    /// penalized.
    last_submitted_peer: PeerId,

    /// The request ID of this lookup is in progress.
    pending: Option<Id>,
}
