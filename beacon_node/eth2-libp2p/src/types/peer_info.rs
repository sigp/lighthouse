//NOTE: This should be removed in favour of the PeerManager PeerInfo, once built.

use types::{BitVector, EthSpec, SubnetId};

#[allow(type_alias_bounds)]
pub type EnrBitfield<T: EthSpec> = BitVector<T::SubnetBitfieldLength>;

/// Information about a given connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo<T: EthSpec> {
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    pub syncing_state: Option<PeerSyncingState>,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    pub enr_bitfield: Option<EnrBitfield<T>>,
}

#[derive(Debug, Clone)]
pub enum PeerSyncingState {
    /// At the current state as our node.
    Synced,
    /// The peer is further ahead than our node and useful for block downloads.
    Ahead,
    /// Is behind our current head and not useful for block downloads.
    Behind,
}

impl<T: EthSpec> PeerInfo<T> {
    /// Creates a new PeerInfo, specifying it's
    pub fn new() -> Self {
        PeerInfo {
            syncing_state: None,
            enr_bitfield: None,
        }
    }

    /// Returns if the peer is subscribed to a given `SubnetId`
    pub fn on_subnet(&self, subnet_id: SubnetId) -> bool {
        if let Some(bitfield) = &self.enr_bitfield {
            return bitfield.get(*subnet_id as usize).unwrap_or_else(|_| false);
        }
        false
    }
}
