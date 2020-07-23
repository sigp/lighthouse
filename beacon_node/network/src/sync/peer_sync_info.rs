use super::manager::SLOT_IMPORT_TOLERANCE;
use crate::router::processor::status_message;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::*;
use eth2_libp2p::SyncInfo;
use std::ops::Sub;
use std::sync::Arc;
use types::{Epoch, Hash256, Slot};

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    pub fork_digest: [u8; 4],
    pub finalized_root: Hash256,
    pub finalized_epoch: Epoch,
    pub head_root: Hash256,
    pub head_slot: Slot,
}

/// The type of peer relative to our current state.
pub enum PeerSyncType {
    /// The peer is on our chain and is fully synced with respect to our chain.
    FullySynced,
    /// The peer has a greater knowledge of the chain than us that warrants a full sync.
    Advanced,
    /// A peer is behind in the sync and not useful to us for downloading blocks.
    Behind,
}

impl From<StatusMessage> for PeerSyncInfo {
    fn from(status: StatusMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            fork_digest: status.fork_digest,
            finalized_root: status.finalized_root,
            finalized_epoch: status.finalized_epoch,
            head_root: status.head_root,
            head_slot: status.head_slot,
        }
    }
}

impl Into<SyncInfo> for PeerSyncInfo {
    fn into(self) -> SyncInfo {
        SyncInfo {
            status_head_slot: self.head_slot,
            status_head_root: self.head_root,
            status_finalized_epoch: self.finalized_epoch,
            status_finalized_root: self.finalized_root,
        }
    }
}

impl PeerSyncInfo {
    /// Derives the peer sync information from a beacon chain.
    pub fn from_chain<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>) -> Option<PeerSyncInfo> {
        Some(Self::from(status_message(chain)?))
    }

    /// Given another peer's `PeerSyncInfo` this will determine how useful that peer is to us in
    /// regards to syncing. This returns the peer sync type that can then be handled by the
    /// `SyncManager`.
    pub fn peer_sync_type(&self, remote_peer_sync_info: &PeerSyncInfo) -> PeerSyncType {
        // check if the peer is fully synced with our current chain
        if self.is_fully_synced_peer(remote_peer_sync_info) {
            PeerSyncType::FullySynced
        }
        // if not, check if the peer is ahead of our chain
        else if self.is_advanced_peer(remote_peer_sync_info) {
            PeerSyncType::Advanced
        } else {
            // the peer must be behind and not useful
            PeerSyncType::Behind
        }
    }

    /// Determines if another peer is fully synced with the current peer.
    ///
    /// A fully synced peer is a peer whose finalized epoch and hash match our own and their
    /// head is within SLOT_IMPORT_TOLERANCE of our own.
    /// In this case we ignore any batch/range syncing.
    fn is_fully_synced_peer(&self, remote: &PeerSyncInfo) -> bool {
        // ensure we are on the same chain, with minor differing heads
        if remote.finalized_epoch == self.finalized_epoch
            && remote.finalized_root == self.finalized_root
        {
            // that we are within SLOT_IMPORT_TOLERANCE of our two heads
            if (self.head_slot >= remote.head_slot
                && self.head_slot.sub(remote.head_slot).as_usize() <= SLOT_IMPORT_TOLERANCE)
                || (self.head_slot < remote.head_slot)
                    && remote.head_slot.sub(self.head_slot).as_usize() <= SLOT_IMPORT_TOLERANCE
            {
                return true;
            }
        }
        false
    }

    /// Determines if a peer has more knowledge about the current chain than we do.
    ///
    /// There are two conditions here.
    /// 1) The peer could have a head slot that is greater
    /// than SLOT_IMPORT_TOLERANCE of our current head.
    /// 2) The peer has a greater finalized slot/epoch than our own.
    fn is_advanced_peer(&self, remote: &PeerSyncInfo) -> bool {
        remote.head_slot.sub(self.head_slot).as_usize() > SLOT_IMPORT_TOLERANCE
            || self.finalized_epoch < remote.finalized_epoch
    }
}
