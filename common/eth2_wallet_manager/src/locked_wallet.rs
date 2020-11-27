use crate::{
    filesystem::{read, update},
    Error,
};
use eth2_wallet::{Uuid, ValidatorKeystores, Wallet};
use lockfile::Lockfile;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = ".lock";

/// Represents a `Wallet` in a `wallet_dir`.
///
/// For example:
///
/// ```ignore
/// <wallet_dir>
/// └── .lock
/// └── <wallet-json>
/// ```
///
/// Provides the following functionality:
///
/// - Control over the `.lock` file to prevent concurrent access.
/// - A `next_validator` function which wraps `Wallet::next_validator`, ensuring that the wallet is
///     persisted to disk (as JSON) between each consecutive call.
pub struct LockedWallet {
    wallet_dir: PathBuf,
    wallet: Wallet,
    _lockfile: Lockfile,
}

impl LockedWallet {
    /// Opens a wallet with the `uuid` from a `base_dir`.
    ///
    /// ```ignore
    /// <base-dir>
    /// ├── <uuid (directory)>
    ///     └── <uuid (json file)>
    /// ```
    ///
    /// ## Errors
    ///
    /// - If the wallet does not exist.
    /// - There is file-system or parsing error.
    /// - The lock-file already exists.
    pub(crate) fn open<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> Result<Self, Error> {
        let wallet_dir = base_dir.as_ref().join(format!("{}", uuid));

        if !wallet_dir.exists() {
            return Err(Error::MissingWalletDir(wallet_dir));
        }

        let _lockfile = Lockfile::new(wallet_dir.join(LOCK_FILE))?;

        Ok(Self {
            wallet: read(&wallet_dir, uuid)?,
            wallet_dir,
            _lockfile,
        })
    }

    /// Returns a reference to the underlying wallet.
    ///
    /// Note: this does not read from the file-system on each call. It assumes that the wallet does
    /// not change due to the use of a lock-file.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Calls `Wallet::next_validator` on the underlying `wallet`.
    ///
    /// Ensures that the wallet JSON file is updated after each call.
    ///
    /// ## Errors
    ///
    /// - If there is an error generating the validator keys.
    /// - If there is a file-system error.
    pub fn next_validator(
        &mut self,
        wallet_password: &[u8],
        voting_keystore_password: &[u8],
        withdrawal_keystore_password: &[u8],
    ) -> Result<ValidatorKeystores, Error> {
        let keystores = self.wallet.next_validator(
            wallet_password,
            voting_keystore_password,
            withdrawal_keystore_password,
        )?;

        update(&self.wallet_dir, &self.wallet)?;

        Ok(keystores)
    }
}
