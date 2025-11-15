use super::manager::SLOT_IMPORT_TOLERANCE;
use crate::status::ToStatusMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{SyncInfo, SyncStatus as PeerSyncStatus};
use std::cmp::Ordering;
use types::{Epoch, EthSpec, Hash256, Slot};

/// The type of peer relative to our current state.
pub enum PeerSyncType {
    /// The peer is on our chain and is fully synced with respect to our chain.
    FullySynced,
    /// The peer has a greater knowledge of the chain than us that warrants a full sync.
    Advanced(PeerSyncTypeAdvanced),
    /// A peer is behind in the sync and not useful to us for downloading blocks.
    Behind,
}

impl PeerSyncType {
    pub fn as_sync_status(&self, info: &SyncInfo) -> PeerSyncStatus {
        match self {
            PeerSyncType::FullySynced => PeerSyncStatus::Synced { info: info.clone() },
            PeerSyncType::Behind => PeerSyncStatus::Behind { info: info.clone() },
            PeerSyncType::Advanced(_) => PeerSyncStatus::Advanced { info: info.clone() },
        }
    }
}

pub enum PeerSyncTypeAdvanced {
    Finalized {
        target_slot: Slot,
        target_root: Hash256,
        start_epoch: Epoch,
    },
    Head {
        target_slot: Slot,
        target_root: Hash256,
        start_epoch: Epoch,
    },
}

#[derive(Clone)]
pub(crate) struct LocalSyncInfo {
    pub head_slot: Slot,
    pub finalized_epoch: Epoch,
    pub local_irreversible_epoch: Epoch,
}

impl LocalSyncInfo {
    pub fn new<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Self {
        let status = chain.status_message();
        // Max with the store in case the node has triggered manual finalization
        let local_irreversible_epoch = std::cmp::max(
            chain.head().finalized_checkpoint().epoch,
            chain
                .store
                .get_split_slot()
                .epoch(T::EthSpec::slots_per_epoch()),
        );
        Self {
            head_slot: *status.head_slot(),
            finalized_epoch: *status.finalized_epoch(),
            local_irreversible_epoch,
        }
    }
}

pub fn remote_sync_type<T: BeaconChainTypes>(
    local: &LocalSyncInfo,
    remote: &SyncInfo,
    chain: &BeaconChain<T>,
) -> PeerSyncType {
    // auxiliary variables for clarity: Inclusive boundaries of the range in which we consider a peer's
    // head "near" ours.
    let near_range_start = local.head_slot.saturating_sub(SLOT_IMPORT_TOLERANCE);
    let near_range_end = local.head_slot.saturating_add(SLOT_IMPORT_TOLERANCE);

    // With the remote peer's status message let's figure out if there are enough blocks to discover
    // that we trigger sync from them. We don't want to sync any blocks from epochs prior to the
    // local irreversible epoch. Our finalized epoch may be less than the local irreversible epoch.

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
                && !chain.block_is_known_to_fork_choice(&remote.head_root)
            {
                // This peer has a head ahead enough of ours and we have no knowledge of their best
                // block.
                PeerSyncType::Advanced(PeerSyncTypeAdvanced::Head {
                    target_root: remote.head_root,
                    target_slot: remote.head_slot,
                    start_epoch: local.local_irreversible_epoch,
                })
            } else {
                // This peer is either in the tolerance range, or ahead us with an already rejected
                // block.
                PeerSyncType::FullySynced
            }
        }
        Ordering::Greater => {
            if chain.block_is_known_to_fork_choice(&remote.head_root) {
                // We have already synced up to this peer's head
                PeerSyncType::FullySynced
            } else {
                let finality_advanced = remote.finalized_epoch > local.finalized_epoch + 1;
                let head_advanced = remote.head_slot > near_range_end;
                let finality_ahead_local_irreversible =
                    remote.finalized_epoch > local.local_irreversible_epoch;

                if finality_advanced {
                    if finality_ahead_local_irreversible {
                        PeerSyncType::Advanced(PeerSyncTypeAdvanced::Finalized {
                            target_root: remote.finalized_root,
                            target_slot: remote
                                .finalized_epoch
                                .start_slot(T::EthSpec::slots_per_epoch()),
                            start_epoch: local.local_irreversible_epoch,
                        })
                    } else if head_advanced {
                        PeerSyncType::Advanced(PeerSyncTypeAdvanced::Head {
                            target_root: remote.head_root,
                            target_slot: remote.head_slot,
                            start_epoch: local.local_irreversible_epoch,
                        })
                    } else {
                        PeerSyncType::FullySynced
                    }
                } else if head_advanced {
                    PeerSyncType::Advanced(PeerSyncTypeAdvanced::Head {
                        target_root: remote.head_root,
                        target_slot: remote.head_slot,
                        start_epoch: local.local_irreversible_epoch,
                    })
                } else {
                    // This peer is near enough to us to be considered synced
                    PeerSyncType::FullySynced
                }
            }
        }
    }
}
