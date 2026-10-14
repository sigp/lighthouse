//! Transport-independent verification primitives for decentralized checkpoint sync.
//!
//! This crate deliberately has no networking, storage or `BeaconChain` dependencies. Untrusted
//! transport values enter as ordinary data and must pass the verification functions exported here
//! before they can affect trusted checkpoint-sync state.
//!
//! Checkpoint acquisition uses a strict policy: callers must not invoke
//! [`process_light_client_store_force_update`] to recover from stalled synchronization. Recovery
//! requires a recent finalized block root obtained through an independent trusted source, followed
//! by [`initialize_light_client_store`] to build a replacement store. Obtaining that root and
//! scheduling recovery belong to the caller. The force-update primitive remains available for
//! consensus-spec conformance; it does not establish a verified checkpoint.

mod bootstrap;
mod error;
mod fork;
mod header;
mod merkle;
mod partial_update;
mod store;
mod update;
mod upgrade;
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
    upgrade_light_client_store,
};
pub use update::{ValidatedLightClientUpdate, validate_light_client_update};
pub use upgrade::{
    upgrade_light_client_bootstrap, upgrade_light_client_header, upgrade_light_client_update,
};
pub use verified::VerifiedFinalizedHeader;
