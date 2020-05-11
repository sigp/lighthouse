use crate::filesystem::{create, read, update, Error as FilesystemError};
use eth2_wallet::{
    bip39::Mnemonic, Error as WalletError, Uuid, ValidatorKeystores, Wallet, WalletBuilder,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{create_dir_all, read_dir, remove_file, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

const LOCK_FILE: &str = ".lock";

#[derive(Debug)]
pub enum Error {
    DirectoryDoesNotExist(PathBuf),
    WalletError(WalletError),
    FilesystemError(FilesystemError),
    UnableToReadDir(io::Error),
    UnableToReadWallet(io::Error),
    UnableToReadFilename(OsString),
    NameAlreadyTaken(String),
    WalletNameUnknown(String),
    WalletDirExists(PathBuf),
    IoError(io::Error),
    WalletIsLocked(PathBuf),
    MissingWalletDir(PathBuf),
    UnableToCreateLockfile(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<WalletError> for Error {
    fn from(e: WalletError) -> Error {
        Error::WalletError(e)
    }
}

impl From<FilesystemError> for Error {
    fn from(e: FilesystemError) -> Error {
        Error::FilesystemError(e)
    }
}

/// Defines the type of an EIP-2386 wallet.
///
/// Presently only `Hd` wallets are supported.
pub enum WalletType {
    /// Hierarchical-deterministic.
    Hd,
}

/// Manages a directory containing EIP-2386 wallets.
///
/// Each wallet is stored in a directory with the name of the wallet UUID. Inside each directory a
/// EIP-2386 JSON wallet is also stored using the UUID as the filename.
///
/// In each wallet directory an optional `.lock` exists to prevent concurrent reads and writes from
/// the same wallet.
///
/// Example:
///
/// ```ignore
/// wallets
/// ├── 35c07717-c6f3-45e8-976f-ef5d267e86c9
/// │   └── 35c07717-c6f3-45e8-976f-ef5d267e86c9
/// └── 747ad9dc-e1a1-4804-ada4-0dc124e46c49
///     └── .lock
///     └── 747ad9dc-e1a1-4804-ada4-0dc124e46c49
/// ```
pub struct WalletManager {
    dir: PathBuf,
}

pub struct LockedWallet {
    wallet_dir: PathBuf,
    wallet: Wallet,
}

impl LockedWallet {
    pub fn open<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> Result<Self, Error> {
        let wallet_dir = base_dir.as_ref().join(format!("{}", uuid));

        if !wallet_dir.exists() {
            return Err(Error::MissingWalletDir(wallet_dir));
        }

        let lockfile = wallet_dir.join(LOCK_FILE);
        if lockfile.exists() {
            return Err(Error::WalletIsLocked(wallet_dir));
        } else {
            File::create(lockfile).map_err(Error::UnableToCreateLockfile)?;
        }

        Ok(Self {
            wallet: read(&wallet_dir, uuid)?,
            wallet_dir,
        })
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

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

impl Drop for LockedWallet {
    fn drop(&mut self) {
        let lockfile = self.wallet_dir.clone().join(LOCK_FILE);
        if let Err(e) = remove_file(&lockfile) {
            panic!("Unable to remove {:?}: {:?}", lockfile, e);
        }
    }
}

impl WalletManager {
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir: PathBuf = dir.as_ref().into();

        if dir.exists() {
            Ok(Self { dir })
        } else {
            Err(Error::DirectoryDoesNotExist(dir))
        }
    }

    pub fn wallet_by_name(&self, name: &str) -> Result<LockedWallet, Error> {
        LockedWallet::open(
            self.dir.clone(),
            self.wallets()?
                .get(name)
                .ok_or_else(|| Error::WalletNameUnknown(name.into()))?,
        )
    }

    pub fn create_wallet(
        &self,
        name: String,
        _wallet_type: WalletType,
        mnemonic: &Mnemonic,
        password: &[u8],
    ) -> Result<LockedWallet, Error> {
        if self.wallets()?.contains_key(&name) {
            return Err(Error::NameAlreadyTaken(name));
        }

        let wallet = WalletBuilder::from_mnemonic(mnemonic, password, name)?.build()?;

        let uuid = wallet.uuid().clone();
        let uuid_string = format!("{}", uuid);

        let wallet_dir = self.dir.join(&uuid_string);

        if wallet_dir.exists() {
            return Err(Error::WalletDirExists(wallet_dir));
        }

        create_dir_all(&wallet_dir)?;

        create(&wallet_dir, &wallet)?;

        drop(wallet);

        LockedWallet::open(wallet_dir, &uuid)
    }

    fn wallets(&self) -> Result<HashMap<String, Uuid>, Error> {
        let mut wallets = HashMap::new();

        for f in read_dir(&self.dir).map_err(Error::UnableToReadDir)? {
            let f = f?;

            // Ignore any non-directory objects in the root wallet dir.
            if f.file_type()?.is_dir() {
                let file_name = f
                    .file_name()
                    .into_string()
                    .map_err(Error::UnableToReadFilename)?;

                // Ignore any paths that don't parse as a UUID.
                if let Ok(uuid) = Uuid::parse_str(&file_name) {
                    let wallet_path = f.path().join(format!("{}", uuid));
                    let wallet = OpenOptions::new()
                        .read(true)
                        .create(false)
                        .open(wallet_path)
                        .map_err(Error::UnableToReadWallet)
                        .and_then(|f| Wallet::from_json_reader(f).map_err(Error::WalletError))?;
                    wallets.insert(wallet.name().into(), *wallet.uuid());
                }
            }
        }

        Ok(wallets)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
