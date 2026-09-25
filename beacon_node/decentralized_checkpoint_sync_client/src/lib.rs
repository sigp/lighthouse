#![doc = include_str!("../README.md")]

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
