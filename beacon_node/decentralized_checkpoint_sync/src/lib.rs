//! Transport-independent verification primitives for decentralized checkpoint sync.
//!
//! This crate deliberately has no networking, storage or `BeaconChain` dependencies. Untrusted
//! transport values enter as ordinary data and must pass the verification functions exported here
//! before they can affect trusted checkpoint-sync state.

mod bootstrap;
mod error;
mod fork;
mod header;
mod merkle;
mod partial_update;
mod store;
mod update;
mod verified;

pub use bootstrap::initialize_light_client_store;
pub use error::LightClientSyncError;
pub use fork::LightClientStoreSchema;
pub use header::{beacon_header, validate_light_client_header};
pub use partial_update::{
    process_light_client_finality_update, process_light_client_optimistic_update,
};
pub use store::{
    LightClientStore, process_light_client_store_force_update, process_light_client_update,
};
pub use update::{ValidatedLightClientUpdate, validate_light_client_update};
pub use verified::VerifiedFinalizedHeader;
