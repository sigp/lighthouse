use super::manager::SLOT_IMPORT_TOLERANCE;
use crate::router::processor::status_message as local_status;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::{rpc::StatusMessage, SyncInfo};
use slot_clock::SlotClock;
use std::ops::Sub;
use types::{Epoch, EthSpec, Hash256, Slot};

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

type IrrelevantPeerReason = String;

/// The type of peer relative to our current state.
pub enum PeerSyncType {
    /// The peer is on our chain and is fully synced with respect to our chain.
    FullySynced,
    /// The peer has a greater knowledge of the chain than us that warrants a full sync.
    AdvancedHead,
    /// TODO: docs
    AdvancedFinalized,
    /// A peer is behind in the sync and not useful to us for downloading blocks.
    Behind,
}

pub fn remote_sync_status<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    remote: StatusMessage,
) -> Result<Result<(SyncInfo, PeerSyncType), IrrelevantPeerReason>, BeaconChainError> {
    let local = local_status(chain)?;

    if let Some(irrelevant_reason) = remote_irrelevant_reason(&local, &remote, chain)? {
        return Ok(Err(irrelevant_reason));
    }

    // at this point we are sure that the peer has either a finalized epoch ahead of ours or a
    // finalized epoch less of equal than ours for which we agree on the root
    let sync_type = if is_synced_peer(&local, &remote, chain) {
        PeerSyncType::FullySynced
    } else if is_advanced_peer(&local, &remote) {
        PeerSyncType::AdvancedFinalized
    } else {
        PeerSyncType::Behind
    };

    let sync_info = SyncInfo {
        status_head_slot: remote.head_slot,
        status_head_root: remote.head_root,
        status_finalized_epoch: remote.finalized_epoch,
        status_finalized_root: remote.finalized_root,
    };

    Ok(Ok((sync_info, sync_type)))
}

/// Verify that a peer is relevant to
pub fn remote_irrelevant_reason<T: BeaconChainTypes>(
    local: &StatusMessage,
    remote: &StatusMessage,
    chain: &BeaconChain<T>,
) -> Result<Option<IrrelevantPeerReason>, BeaconChainError> {
    let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

    let reason = if local.fork_digest != remote.fork_digest {
        // The node is on a different network/fork
        Some(format!(
            "Incompatible forks: ours:{} theirs:{}",
            hex::encode(local.fork_digest),
            hex::encode(remote.fork_digest)
        ))
    } else if remote.head_slot
        > chain
            .slot()
            .unwrap_or_else(|_| chain.slot_clock.genesis_slot())
            + FUTURE_SLOT_TOLERANCE
    {
        // The remotes head is on a slot that is significantly ahead of what we consider the
        // current slot. This could be because they are using a different genesis time, or that
        // theirs or our systems' clock is incorrect.
        Some("Different system clocks or genesis time".to_string())
    } else if remote.finalized_epoch <= local.finalized_epoch
        && remote.finalized_root != Hash256::zero()
        && local.finalized_root != Hash256::zero()
        && chain
            .root_at_slot(start_slot(remote.finalized_epoch))
            .map(|root_opt| root_opt != Some(remote.finalized_root))?
    {
        // The remotes finalized epoch is less than or equal to ours, but the block root is
        // different to the one in our chain. Therefore, the node is on a different chain and we
        // should not communicate with them.
        Some("Different finalized chain".to_string())
    } else {
        None
    };

    Ok(reason)
}

fn is_inside_tolerance_range(local: &Slot, remote: &Slot) -> bool {
    // Either we are slightly ahead of this peer
    (local >= remote
     && local.sub(*remote) <= SLOT_IMPORT_TOLERANCE as u64)
    // Or this peer is slightly ahead of us
    || (local < remote
        && remote.sub(*local) <= SLOT_IMPORT_TOLERANCE as u64)
}

fn is_synced_peer<T: BeaconChainTypes>(
    local: &StatusMessage,
    remote: &StatusMessage,
    chain: &BeaconChain<T>,
) -> bool {
    // we consider synced a peer that is near our head or for which we have already synced their
    // best slot

    // CASE 1: The peer shares our finalized info and is near our head
    if local.finalized_epoch == remote.finalized_epoch
        && local.finalized_root == remote.finalized_root
        && is_inside_tolerance_range(&local.head_slot, &remote.head_slot)
    {
        return true;
    }

    // CASE 2: The peer is ahead of us by just 1 epoch but still near enough to our head
    if local.finalized_epoch + 1 == remote.finalized_epoch
        && is_inside_tolerance_range(&local.head_slot, &remote.head_slot)
    {
        return true;
    }

    // CASE 3: The peer is ahead of us, but we have already synced this peer's best block and fork
    // choice has rejected their version of the chain. We have nothing to sync from them
    if is_advanced_peer(local, remote) && chain.fork_choice.read().contains_block(&remote.head_root)
    {
        return true;
    }

    false
}

fn is_advanced_peer(local: &StatusMessage, remote: &StatusMessage) -> bool {
    // CASE 1: The peer could have a head slot that is greater than SLOT_IMPORT_TOLERANCE of our
    // current head.
    // CASE 2: The peer has a greater finalized slot/epoch than our own.
    remote.head_slot.sub(local.head_slot) > SLOT_IMPORT_TOLERANCE as u64
        || (remote.finalized_epoch > local.finalized_epoch)
}
