//! Data-source contracts and policy for fetching light-client checkpoint data.
//!
//! Sources return untrusted light-client objects, not authenticated headers. The
//! `decentralized_checkpoint_sync` core is responsible for cryptographic verification.
//! Bootstrap acquisition and bounded update-range steps call that core verifier before returning
//! a store. HTTP transport and whole-task retry/freshness orchestration are not implemented yet.
//!
//! A startup caller must supply a trusted finalized root, the network's chain spec and
//! genesis validators root, and a slot clock initialized from trusted genesis time. The source
//! does not provide these trust inputs and does not require an existing `BeaconChain` or its own
//! Tokio runtime. Policy is explicit: provider-reported head/finality cannot define freshness.

mod error;
mod policy;
mod source;
mod sync;
mod updates;

pub use error::{
    BootstrapError, ConsumerError, PolicyError, SourceError, SourceErrorKind, UpdateRangeError,
};
pub use policy::{RequestLimits, SyncPolicy, UpdateRange};
pub use source::{LightClientData, LightClientDataSource, SourceResponse, SourceResult};
pub use sync::{BootstrappedStore, bootstrap_light_client_store};
pub use updates::{ProcessedUpdateRange, next_update_range, process_next_update_range};
