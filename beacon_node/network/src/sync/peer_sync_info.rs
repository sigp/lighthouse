use super::manager::SLOT_IMPORT_TOLERANCE;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{SyncInfo, SyncStatus as PeerSyncStatus};
use std::cmp::Ordering;

/// The type of peer relative to our current state.
pub enum PeerSyncType {
    /// The peer is on our chain and is fully synced with respect to our chain.
    FullySynced,
    /// The peer has a greater knowledge of the chain than us that warrants a full sync.
    Advanced,
    /// A peer is behind in the sync and not useful to us for downloading blocks.
    Behind,
}

impl PeerSyncType {
    pub fn as_sync_status(&self, info: &SyncInfo) -> PeerSyncStatus {
        match self {
            PeerSyncType::FullySynced => PeerSyncStatus::Synced { info: info.clone() },
            PeerSyncType::Behind => PeerSyncStatus::Behind { info: info.clone() },
            PeerSyncType::Advanced => PeerSyncStatus::Advanced { info: info.clone() },
        }
    }
}

pub fn remote_sync_type<T: BeaconChainTypes>(
    local: &SyncInfo,
    remote: &SyncInfo,
    chain: &BeaconChain<T>,
) -> PeerSyncType {
    // auxiliary variables for clarity: Inclusive boundaries of the range in which we consider a peer's
    // head "near" ours.
    let near_range_start = local.head_slot - SLOT_IMPORT_TOLERANCE as u64;
    let near_range_end = local.head_slot + SLOT_IMPORT_TOLERANCE as u64;

    match remote.finalized_epoch.cmp(&local.finalized_epoch) {
        Ordering::Less => {
            // The node has a lower finalized epoch, their chain is not useful to us. There are two
            // cases where a node can have a lower finalized epoch:
            //
            // ## The node is on the same chain
            //
            // If a node is on the same chain but has a lower finalized epoch, their head must be
            // lower than ours. Therefore, we have nothing to request from them.
            //
            // ## The node is on a fork
            //
            // If a node is on a fork that has a lower finalized epoch, switching to that fork would
            // cause us to revert a finalized block. This is not permitted, therefore we have no
            // interest in their blocks.
            //
            // We keep these peers to allow them to sync from us.
            PeerSyncType::Behind
        }
        Ordering::Equal => {
            // NOTE: if a peer has our same `finalized_epoch` with a different `finalized_root`
            // they are not considered relevant and won't be propagated to sync.
            // Check if the peer is the peer is inside the tolerance range to be considered synced.
            if remote.head_slot < near_range_start {
                PeerSyncType::Behind
            } else if remote.head_slot > near_range_end
                && !chain.fork_choice.read().contains_block(&remote.head_root)
            {
                // This peer has a head ahead enough of ours and we have no knowledge of their best
                // block.
                PeerSyncType::Advanced
            } else {
                // This peer is either in the tolerance range, or ahead us with an already rejected
                // block.
                PeerSyncType::FullySynced
            }
        }
        Ordering::Greater => {
            if (local.finalized_epoch + 1 == remote.finalized_epoch
                && near_range_start <= remote.head_slot
                && remote.head_slot <= near_range_end)
                || chain.fork_choice.read().contains_block(&remote.head_root)
            {
                // This peer is near enough to us to be considered synced, or
                // we have already synced up to this peer's head
                PeerSyncType::FullySynced
            } else {
                PeerSyncType::Advanced
            }
        }
    }
}
