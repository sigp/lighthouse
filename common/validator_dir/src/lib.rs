//! Provides:
//!
//! - `ValidatorDir`: manages a directory containing validator keypairs, deposit info and other
//!   things.
//!
//! This crate is intended to be used by the account manager to create validators and the validator
//! client to load those validators.

mod builder;
pub mod insecure_keys;
mod validator_dir;

pub use crate::validator_dir::{
    ETH1_DEPOSIT_TX_HASH_FILE, Error, Eth1DepositData, ValidatorDir,
    unlock_keypair_from_password_path,
};
pub use builder::{
    Builder, ETH1_DEPOSIT_DATA_FILE, Error as BuilderError, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE, keystore_password_path,
};
