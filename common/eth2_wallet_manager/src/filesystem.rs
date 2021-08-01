//! Provides some CRUD functions for wallets on the filesystem.

use eth2_wallet::Error as WalletError;
use eth2_wallet::{Uuid, Wallet};
use std::fs::{copy as copy_file, remove_file, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum Error {
    WalletAlreadyExists(PathBuf),
    WalletDoesNotExist(PathBuf),
    WalletBackupAlreadyExists(PathBuf),
    UnableToCreateBackup(io::Error),
    UnableToRemoveBackup(io::Error),
    UnableToRemoveWallet(io::Error),
    UnableToCreateWallet(io::Error),
    UnableToReadWallet(io::Error),
    JsonWrite(WalletError),
    JsonRead(WalletError),
}

/// Read a wallet with the given `uuid` from the `wallet_dir`.
pub fn read<P: AsRef<Path>>(wallet_dir: P, uuid: &Uuid) -> Result<Wallet, Error> {
    let json_path = wallet_json_path(wallet_dir, uuid);

    if !json_path.exists() {
        Err(Error::WalletDoesNotExist(json_path))
    } else {
        OpenOptions::new()
            .read(true)
            .create(false)
            .open(json_path)
            .map_err(Error::UnableToReadWallet)
            .and_then(|f| Wallet::from_json_reader(f).map_err(Error::JsonRead))
    }
}

/// Update the JSON file in the `wallet_dir` with the given `wallet`.
///
/// Performs a three-step copy:
///
/// 1. Copy the current JSON file to a backup file.
/// 2. Over-write the existing JSON file.
/// 3. Delete the backup file.
pub fn update<P: AsRef<Path>>(wallet_dir: P, wallet: &Wallet) -> Result<(), Error> {
    let wallet_dir = wallet_dir.as_ref();

    let json_path = wallet_json_path(wallet_dir, wallet.uuid());
    let json_backup_path = wallet_json_backup_path(wallet_dir, wallet.uuid());

    // Require that a wallet already exists.
    if !json_path.exists() {
        return Err(Error::WalletDoesNotExist(json_path));
    // Require that there is no existing backup.
    } else if json_backup_path.exists() {
        return Err(Error::WalletBackupAlreadyExists(json_backup_path));
    }

    // Copy the existing wallet to the backup location.
    copy_file(&json_path, &json_backup_path).map_err(Error::UnableToCreateBackup)?;

    // Remove the existing wallet
    remove_file(json_path).map_err(Error::UnableToRemoveWallet)?;

    // Create the new wallet.
    create(wallet_dir, wallet)?;

    // Remove the backup file.
    remove_file(json_backup_path).map_err(Error::UnableToRemoveBackup)?;

    Ok(())
}

/// Writes the `wallet` into the `wallet_dir`, returning an error if it already exists.
pub fn create<P: AsRef<Path>>(wallet_dir: P, wallet: &Wallet) -> Result<(), Error> {
    let json_path = wallet_json_path(wallet_dir, wallet.uuid());

    if json_path.exists() {
        Err(Error::WalletAlreadyExists(json_path))
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(json_path)
            .map_err(Error::UnableToCreateWallet)
            .and_then(|f| wallet.to_json_writer(f).map_err(Error::JsonWrite))
    }
}

fn wallet_json_backup_path<P: AsRef<Path>>(wallet_dir: P, uuid: &Uuid) -> PathBuf {
    wallet_dir.as_ref().join(format!("{}.backup", uuid))
}

fn wallet_json_path<P: AsRef<Path>>(wallet_dir: P, uuid: &Uuid) -> PathBuf {
    wallet_dir.as_ref().join(format!("{}", uuid))
}
