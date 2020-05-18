use crate::{
    filesystem::{create, Error as FilesystemError},
    LockedWallet,
};
use eth2_wallet::{bip39::Mnemonic, Error as WalletError, Uuid, Wallet, WalletBuilder};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{create_dir_all, read_dir, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

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
    UuidMismatch((Uuid, Uuid)),
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

impl WalletManager {
    /// Open a directory containing multiple wallets.
    ///
    /// Pass the `wallets` directory as `dir` (see struct-level example).
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir: PathBuf = dir.as_ref().into();

        if dir.exists() {
            Ok(Self { dir })
        } else {
            Err(Error::DirectoryDoesNotExist(dir))
        }
    }

    /// Searches all wallets in `self.dir` and returns the wallet with this name.
    ///
    /// ## Errors
    ///
    /// - If there is no wallet with this name.
    /// - If there is a file-system or parsing error.
    pub fn wallet_by_name(&self, name: &str) -> Result<LockedWallet, Error> {
        LockedWallet::open(
            self.dir.clone(),
            self.wallets()?
                .get(name)
                .ok_or_else(|| Error::WalletNameUnknown(name.into()))?,
        )
    }

    /// Creates a new wallet with the given `name` in `self.dir` with the given `mnemonic` as a
    /// seed, encrypted with `password`.
    ///
    /// ## Errors
    ///
    /// - If a wallet with this name already exists.
    /// - If there is a file-system or parsing error.
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

        let wallet_dir = self.dir.join(format!("{}", uuid));

        if wallet_dir.exists() {
            return Err(Error::WalletDirExists(wallet_dir));
        }

        create_dir_all(&wallet_dir)?;

        create(&wallet_dir, &wallet)?;

        drop(wallet);

        LockedWallet::open(&self.dir, &uuid)
    }

    /// Iterates all wallets in `self.dir` and returns a mapping of their name to their UUID.
    ///
    /// Ignores any items in `self.dir` that:
    ///
    /// - Are files.
    /// - Are directories, but their file-name does not parse as a UUID.
    ///
    /// This function is fairly strict, it will fail if any directory is found that does not obey
    /// the expected structure (e.g., there is a UUID directory that does not contain a valid JSON
    /// keystore with the same UUID).
    pub fn wallets(&self) -> Result<HashMap<String, Uuid>, Error> {
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

                    if *wallet.uuid() != uuid {
                        return Err(Error::UuidMismatch((uuid, *wallet.uuid())));
                    }

                    wallets.insert(wallet.name().into(), *wallet.uuid());
                }
            }
        }

        Ok(wallets)
    }
}

#[cfg(test)]
// These tests are very slow in debug, only test in release.
#[cfg(not(debug_assertions))]
mod tests {
    use super::*;
    use crate::{filesystem::read, locked_wallet::LOCK_FILE};
    use eth2_wallet::bip39::{Language, Mnemonic};
    use tempfile::tempdir;

    const MNEMONIC: &str =
        "enemy fog enlist laundry nurse hungry discover turkey holiday resemble glad discover";
    const WALLET_PASSWORD: &[u8] = &[43; 43];

    fn get_mnemonic() -> Mnemonic {
        Mnemonic::from_phrase(MNEMONIC, Language::English).unwrap()
    }

    fn create_wallet(mgr: &WalletManager, id: usize) -> LockedWallet {
        let wallet = mgr
            .create_wallet(
                format!("{}", id),
                WalletType::Hd,
                &get_mnemonic(),
                WALLET_PASSWORD,
            )
            .expect("should create wallet");

        assert!(
            wallet_dir_path(&mgr.dir, wallet.wallet().uuid()).exists(),
            "should have created wallet dir"
        );
        assert!(
            json_path(&mgr.dir, wallet.wallet().uuid()).exists(),
            "should have created json file"
        );
        assert!(
            lockfile_path(&mgr.dir, wallet.wallet().uuid()).exists(),
            "should have created lockfile"
        );

        wallet
    }

    fn load_wallet_raw<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> Wallet {
        read(wallet_dir_path(base_dir, uuid), uuid).expect("should load raw json")
    }

    fn wallet_dir_path<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> PathBuf {
        let s = format!("{}", uuid);
        base_dir.as_ref().join(&s)
    }

    fn lockfile_path<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> PathBuf {
        let s = format!("{}", uuid);
        base_dir.as_ref().join(&s).join(LOCK_FILE)
    }

    fn json_path<P: AsRef<Path>>(base_dir: P, uuid: &Uuid) -> PathBuf {
        let s = format!("{}", uuid);
        base_dir.as_ref().join(&s).join(&s)
    }

    #[test]
    fn duplicate_names() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path();
        let mgr = WalletManager::open(base_dir).unwrap();
        let name = "cats".to_string();

        mgr.create_wallet(
            name.clone(),
            WalletType::Hd,
            &get_mnemonic(),
            WALLET_PASSWORD,
        )
        .expect("should create first wallet");

        match mgr.create_wallet(
            name.clone(),
            WalletType::Hd,
            &get_mnemonic(),
            WALLET_PASSWORD,
        ) {
            Err(Error::NameAlreadyTaken(_)) => {}
            _ => panic!("expected name error"),
        }
    }

    #[test]
    fn keystore_generation() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path();
        let mgr = WalletManager::open(base_dir).unwrap();
        let name = "cats".to_string();

        let mut w = mgr
            .create_wallet(
                name.clone(),
                WalletType::Hd,
                &get_mnemonic(),
                WALLET_PASSWORD,
            )
            .expect("should create first wallet");

        let uuid = w.wallet().uuid().clone();

        assert_eq!(
            load_wallet_raw(&base_dir, &uuid).nextaccount(),
            0,
            "should start wallet with nextaccount 0"
        );

        for i in 1..3 {
            w.next_validator(WALLET_PASSWORD, &[1], &[0])
                .expect("should create validator");
            assert_eq!(
                load_wallet_raw(&base_dir, &uuid).nextaccount(),
                i,
                "should update wallet with nextaccount {}",
                i
            );
        }

        drop(w);

        // Check that we can open the wallet by name.
        let by_name = mgr.wallet_by_name(&name).unwrap();
        assert_eq!(by_name.wallet().name(), name);

        drop(by_name);

        let wallets = mgr.wallets().unwrap().into_iter().collect::<Vec<_>>();
        assert_eq!(wallets, vec![(name, uuid)]);
    }

    #[test]
    fn locked_wallet_lockfile() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path();
        let mgr = WalletManager::open(base_dir).unwrap();

        let uuid_a = create_wallet(&mgr, 0).wallet().uuid().clone();
        let uuid_b = create_wallet(&mgr, 1).wallet().uuid().clone();

        let locked_a = LockedWallet::open(&base_dir, &uuid_a).expect("should open wallet a");

        assert!(
            lockfile_path(&base_dir, &uuid_a).exists(),
            "lockfile should exist"
        );

        drop(locked_a);

        assert!(
            !lockfile_path(&base_dir, &uuid_a).exists(),
            "lockfile have been cleaned up"
        );

        let locked_a = LockedWallet::open(&base_dir, &uuid_a).expect("should open wallet a");
        let locked_b = LockedWallet::open(&base_dir, &uuid_b).expect("should open wallet b");

        assert!(
            lockfile_path(&base_dir, &uuid_a).exists(),
            "lockfile a should exist"
        );

        assert!(
            lockfile_path(&base_dir, &uuid_b).exists(),
            "lockfile b should exist"
        );

        match LockedWallet::open(&base_dir, &uuid_a) {
            Err(Error::WalletIsLocked(_)) => {}
            _ => panic!("did not get locked error"),
        };

        drop(locked_a);

        LockedWallet::open(&base_dir, &uuid_a)
            .expect("should open wallet a after previous instance is dropped");

        match LockedWallet::open(&base_dir, &uuid_b) {
            Err(Error::WalletIsLocked(_)) => {}
            _ => panic!("did not get locked error"),
        };

        drop(locked_b);

        LockedWallet::open(&base_dir, &uuid_b)
            .expect("should open wallet a after previous instance is dropped");
    }
}
