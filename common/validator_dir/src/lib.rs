//! Provides:
//!
//! - `ValidatorDir`: manages a directory containing validator keypairs, deposit info and other
//! things.
//! - `Manager`: manages a directory that contains multiple `ValidatorDir`.
//!
//! This crate is intended to be used by the account manager to create validators and the validator
//! client to load those validators.

mod builder;
pub mod insecure_keys;
mod manager;
mod validator_dir;

pub use crate::validator_dir::{Error, Eth1DepositData, ValidatorDir, ETH1_DEPOSIT_TX_HASH_FILE};
pub use builder::{
    Builder, Error as BuilderError, ETH1_DEPOSIT_DATA_FILE, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE,
};
pub use manager::{Error as ManagerError, Manager};
