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

/// Creates a file with `600 (-rw-------)` permissions.
// TODO: move to password_utils crate.
pub fn create_with_600_perms<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), io::Error> {
    let path = path.as_ref();

    let mut file = File::create(&path)?;

    let mut perm = file.metadata()?.permissions();

    perm.set_mode(0o600);

    file.set_permissions(perm)?;

    file.write_all(bytes)?;

    Ok(())
}

// TODO: move to password_utils crate.
pub fn random_password() -> PlainText {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .collect::<String>()
        .into_bytes()
        .into()
}

/// Remove any number of newline or carriage returns from the end of a vector of bytes.
pub fn strip_off_newlines(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut strip_off = 0;
    for (i, byte) in bytes.iter().rev().enumerate() {
        if *byte == b'\n' || *byte == b'\r' {
            strip_off = i + 1;
        } else {
            break;
        }
    }
    bytes.truncate(bytes.len() - strip_off);
    bytes
}
