//! Transport-independent verification primitives for decentralized checkpoint sync.
//!
//! This crate deliberately has no networking, storage or `BeaconChain` dependencies. Untrusted
//! transport values enter as ordinary data and must pass the verification functions exported here
//! before they can affect trusted checkpoint-sync state.

mod bootstrap;
mod error;
mod fork;
mod header;
mod store;
mod verified;

pub use bootstrap::initialize_light_client_store;
pub use error::LightClientSyncError;
pub use fork::LightClientStoreSchema;
pub use header::{beacon_header, validate_light_client_header};
pub use store::LightClientStore;
pub use verified::VerifiedFinalizedHeader;
