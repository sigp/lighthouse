use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::rpc::StatusMessage;
use eth2_libp2p::{
    MessageId, NetworkGlobals, PeerAction, PeerId, PeerRequestId, Request, Response, SyncInfo,
};

use crate::beacon_processor::worker::FUTURE_SLOT_TOLERANCE;
use crate::service::NetworkMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::rpc::*;
use eth2_libp2p::{
    MessageId, NetworkGlobals, PeerAction, PeerId, PeerRequestId, Request, Response, SyncInfo,
};
use itertools::process_results;
use slog::{debug, error, o, trace, warn};
use slot_clock::SlotClock;
use std::cmp;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, ChainSpec, Epoch, EthSpec, Hash256, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit, Slot, SubnetId,
};

/// Trait to produce a `StatusMessage`
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError>;
}

impl<T: BeaconChainTypes> ToStatusMessage for BeaconChain<T> {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError> {
        let head_info = self.head_info()?;
        let genesis_validators_root = self.genesis_validators_root;

        let fork_digest =
            ChainSpec::compute_fork_digest(head_info.fork.current_version, genesis_validators_root);

        Ok(StatusMessage {
            fork_digest,
            finalized_root: head_info.finalized_checkpoint.root,
            finalized_epoch: head_info.finalized_checkpoint.epoch,
            head_root: head_info.block_root,
            head_slot: head_info.slot,
        })
    }
}

pub fn process_status<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    peer_id: PeerId,
    remote: StatusMessage,
) {
    let local = chain.status_message()?;
    let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

    let irrelevant_reason = if local.fork_digest != remote.fork_digest {
        // The node is on a different network/fork
        Some(format!(
            "Incompatible forks Ours:{} Theirs:{}",
            hex::encode(local.fork_digest),
            hex::encode(remote.fork_digest)
        ))
    } else if remote.head_slot
        > chain
            .slot()
            .unwrap_or_else(|_| chain.slot_clock.genesis_slot())
            + FUTURE_SLOT_TOLERANCE
    {
        // The remote's head is on a slot that is significantly ahead of what we consider the
        // current slot. This could be because they are using a different genesis time, or that
        // their or our system's clock is incorrect.
        Some("Different system clocks or genesis time".to_string())
    } else if remote.finalized_epoch <= local.finalized_epoch
        && remote.finalized_root != Hash256::zero()
        && local.finalized_root != Hash256::zero()
        && chain
            .root_at_slot(start_slot(remote.finalized_epoch))
            .map(|root_opt| root_opt != Some(remote.finalized_root))?
    {
        // The remote's finalized epoch is less than or equal to ours, but the block root is
        // different to the one in our chain. Therefore, the node is on a different chain and we
        // should not communicate with them.
        Some("Different finalized chain".to_string())
    } else {
        None
    };

    if let Some(irrelevant_reason) = irrelevant_reason {
        debug!(self.log, "Handshake Failure"; "peer" => %peer_id, "reason" => irrelevant_reason);
        self.network
            .goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
    } else {
        let info = SyncInfo {
            head_slot: remote.head_slot,
            head_root: remote.head_root,
            finalized_epoch: remote.finalized_epoch,
            finalized_root: remote.finalized_root,
        };
        self.send_to_sync(SyncMessage::AddPeer(peer_id, info));
    }

    Ok(())
}
