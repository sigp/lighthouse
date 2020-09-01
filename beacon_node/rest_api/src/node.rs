use crate::{ApiError, Context};
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::types::SyncState;
use rest_types::{SyncingResponse, SyncingStatus};
use std::sync::Arc;
use types::Slot;

/// Returns a syncing status.
pub fn syncing<T: BeaconChainTypes>(ctx: Arc<Context<T>>) -> Result<SyncingResponse, ApiError> {
    let current_slot = ctx
        .beacon_chain
        .head_info()
        .map_err(|e| ApiError::ServerError(format!("Unable to read head slot: {:?}", e)))?
        .slot;

    let (starting_slot, highest_slot) = match ctx.network_globals.sync_state() {
        SyncState::SyncingFinalized {
            start_slot,
            head_slot,
            ..
        }
        | SyncState::SyncingHead {
            start_slot,
            head_slot,
        } => (start_slot, head_slot),
        SyncState::Synced | SyncState::Stalled => (Slot::from(0u64), current_slot),
    };

    let sync_status = SyncingStatus {
        starting_slot,
        current_slot,
        highest_slot,
    };

    Ok(SyncingResponse {
        is_syncing: ctx.network_globals.is_syncing(),
        sync_status,
    })
}
