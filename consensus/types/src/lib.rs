//! Ethereum Consensus types
// Clippy lint set up
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::disallowed_methods,
        clippy::indexing_slicing
    )
)]

#[macro_use]
pub mod test_utils;

pub mod attestation;
pub mod block;
pub mod builder;
pub mod consolidation;
pub mod core;
pub mod data;
pub mod deposit;
pub mod execution;
pub mod exit;
pub mod fork;
pub mod kzg_ext;
pub mod light_client;
pub mod slashing;
pub mod state;
pub mod sync_committee;
pub mod validator;
pub mod withdrawal;

// Temporary root level exports to maintain backwards compatibility for Lighthouse.
pub use attestation::*;
pub use block::*;
pub use builder::*;
pub use consolidation::*;
pub use core::{consts, *};
pub use data::*;
pub use deposit::*;
pub use execution::*;
pub use exit::*;
pub use fork::*;
pub use kzg_ext::*;
pub use light_client::*;
pub use slashing::*;
pub use state::*;
pub use sync_committee::*;
pub use validator::*;
pub use withdrawal::*;

pub mod graffiti {
    pub use crate::core::{GRAFFITI_BYTES_LEN, Graffiti, GraffitiString};
}
