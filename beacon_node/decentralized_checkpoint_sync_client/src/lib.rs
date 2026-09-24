//! Data-source contracts and policy for fetching light-client checkpoint data.
//!
//! Sources return untrusted light-client objects, not authenticated headers. The
//! `decentralized_checkpoint_sync` core is responsible for cryptographic verification.
//! Bootstrap, update-range and finality steps call that core verifier before returning a store.
//! Checkpoint freshness is evaluated against the local clock, independently of processing.
//! The whole-task driver enforces retry, resource and no-progress limits. [`HttpLightClientDataSource`]
//! supplies bounded JSON REST reads; a provider's successful response never bypasses core verification.
//!
//! A startup caller must supply a trusted finalized root, the network's chain spec and
//! genesis validators root, and a slot clock initialized from trusted genesis time. The source
//! does not provide these trust inputs and does not require an existing `BeaconChain` or its own
//! Tokio runtime. Policy is explicit: provider-reported head/finality cannot define freshness.

mod driver;
mod error;
mod finality;
mod http;
mod managed_source;
mod policy;
mod source;
mod sync;
mod updates;

pub use driver::{SyncOutcome, SyncUsage, sync_verified_finalized_header};
pub use error::{
    BootstrapError, ConsumerError, PolicyError, SourceError, SourceErrorKind, SyncBudget,
    SyncError, UpdateRangeError,
};
pub use finality::{ProcessedFinalityUpdate, process_finality_update, recent_checkpoint_header};
pub use http::HttpLightClientDataSource;
pub use policy::{RequestLimits, SyncPolicy, UpdateRange};
pub use source::{LightClientData, LightClientDataSource, SourceResponse, SourceResult};
pub use sync::{BootstrappedStore, bootstrap_light_client_store};
pub use updates::{ProcessedUpdateRange, next_update_range, process_next_update_range};
