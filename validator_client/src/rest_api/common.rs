use super::errors::ApiError;
use eth2_wallet_manager::WalletManager;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub use eth2_wallet::PlainText;

/// The `Alphanumeric` crate only generates a-z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

pub fn wallet_manager(wallet_dir: &PathBuf) -> Result<WalletManager, ApiError> {
    WalletManager::open(&wallet_dir).map_err(|e| {
        ApiError::ServerError(format!(
            "Unable to open wallet directory {:?}: {:?}",
            wallet_dir, e
        ))
    })
}
