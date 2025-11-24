//! Utilities for lean consensus genesis generation
//!
//! This crate provides utilities for parsing and managing configuration files
//! used with PK's eth-beacon-genesis Docker tool.
//!
//! **Note**: Genesis state generation is handled by PK's Docker tool
//! (`ethpandaops/eth-beacon-genesis:pk910-leanchain`). See `scripts/lean-quickstart/generate-genesis.sh`
//! for the complete genesis generation workflow.

mod config;
mod node_config;
mod validator_config;

pub use config::*;
pub use node_config::*;
pub use validator_config::*;
