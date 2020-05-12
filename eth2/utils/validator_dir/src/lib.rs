mod builder;
pub mod insecure_keys;
pub mod unencrypted_keys;
mod validator_dir;

pub use crate::validator_dir::{Error, ValidatorDir};
pub use builder::{
    Builder, Error as BuilderError, ETH1_DEPOSIT_DATA_FILE, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE,
};
