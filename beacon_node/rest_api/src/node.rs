use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult};
use eth2_libp2p::{types::SyncState, NetworkGlobals};
use hyper::{Body, Request};
use lighthouse_version::version_with_platform;
use rest_types::{Health, SyncingResponse, SyncingStatus};
use std::sync::Arc;
use types::{EthSpec, Slot};

/// Read the version string from the current Lighthouse build.
pub fn get_version(req: Request<Body>) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&version_with_platform())
}

pub fn syncing<T: EthSpec>(
    req: Request<Body>,
    network: Arc<NetworkGlobals<T>>,
    current_slot: Slot,
) -> ApiResult {
    let (starting_slot, highest_slot) = match network.sync_state() {
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

    ResponseBuilder::new(&req)?.body(&SyncingResponse {
        is_syncing: network.is_syncing(),
        sync_status,
    })
}

pub fn get_health(req: Request<Body>) -> ApiResult {
    let health = Health::observe().map_err(ApiError::ServerError)?;

    ResponseBuilder::new(&req)?.body_no_ssz(&health)
}
