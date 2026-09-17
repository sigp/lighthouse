//! Data-source contracts and policy for fetching light-client checkpoint data.
//!
//! Sources return untrusted light-client objects, not authenticated headers. The
//! `decentralized_checkpoint_sync` core is responsible for cryptographic verification.
//! This crate does not yet implement HTTP transport or a synchronization driver.
//!
//! A future startup caller must supply a trusted finalized root, the network's chain spec and
//! genesis validators root, and a slot clock initialized from trusted genesis time. The source
//! does not provide these trust inputs and does not require an existing `BeaconChain` or its own
//! Tokio runtime. Policy is explicit: provider-reported head/finality cannot define freshness.

mod error;
mod policy;
mod source;

pub use error::{PolicyError, SourceError, SourceErrorKind};
pub use policy::{RequestLimits, SyncPolicy, UpdateRange};
pub use source::{LightClientData, LightClientDataSource, SourceResponse, SourceResult};
