use crate::builder::{
    keystore_password_path, ETH1_DEPOSIT_AMOUNT_FILE, ETH1_DEPOSIT_DATA_FILE, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE,
};
use deposit_contract::decode_eth1_tx_data;
use derivative::Derivative;
use eth2_keystore::{Error as KeystoreError, Keystore, PlainText};
use lockfile::{Lockfile, LockfileError};
use std::fs::{read, write, File};
use std::io;
use std::path::{Path, PathBuf};
use tree_hash::TreeHash;
use types::{DepositData, Hash256, Keypair};

/// The file used to save the Eth1 transaction hash from a deposit.
pub const ETH1_DEPOSIT_TX_HASH_FILE: &str = "eth1-deposit-tx-hash.txt";

#[derive(Debug)]
pub enum Error {
    DirectoryDoesNotExist(PathBuf),
    LockfileError(LockfileError),
    UnableToOpenKeystore(io::Error),
    UnableToReadKeystore(KeystoreError),
    UnableToOpenPassword(io::Error),
    UnableToReadPassword(PathBuf),
    UnableToDecryptKeypair(KeystoreError),
    UnableToReadDepositData(io::Error),
    DepositDataMissing0xPrefix,
    DepositDataNotUtf8,
    DepositDataInvalidHex(hex::FromHexError),
    DepositAmountDoesNotExist(PathBuf),
    UnableToReadDepositAmount(io::Error),
    UnableToParseDepositAmount(std::num::ParseIntError),
    DepositAmountIsNotUtf8(std::string::FromUtf8Error),
    UnableToParseDepositData(deposit_contract::DecodeError),
    Eth1TxHashExists(PathBuf),
    UnableToWriteEth1TxHash(io::Error),
    /// The deposit root in the deposit data file does not match the one generated locally. This is
    /// generally caused by supplying an `amount` at deposit-time that is different to the one used
    /// at generation-time.
    Eth1DepositRootMismatch,
    #[cfg(feature = "unencrypted_keys")]
    SszKeypairError(String),
}

/// Information required to submit a deposit to the Eth1 deposit contract.
#[derive(Debug, PartialEq)]
pub struct Eth1DepositData {
    /// An RLP encoded Eth1 transaction.
    pub rlp: Vec<u8>,
    /// The deposit data used to generate `self.rlp`.
    pub deposit_data: DepositData,
    /// The root of `self.deposit_data`.
    pub root: Hash256,
}

/// Provides a wrapper around a directory containing validator information.
///
/// Holds a lockfile in `self.dir` to attempt to prevent concurrent access from multiple
/// processes.
#[derive(Debug, Derivative)]
#[derivative(PartialEq)]
pub struct ValidatorDir {
    dir: PathBuf,
    #[derivative(PartialEq = "ignore")]
    _lockfile: Lockfile,
}

impl ValidatorDir {
    /// Open `dir`, obtaining a lockfile to prevent concurrent access.
    ///
    /// ## Errors
    ///
    /// If there is a filesystem error or if the lockfile is locked by another process.
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir: &Path = dir.as_ref();
        let dir: PathBuf = dir.into();

        if !dir.exists() {
            return Err(Error::DirectoryDoesNotExist(dir));
        }

        // Lock the keystore file that *might* be in this directory.
        // This is not ideal, see: https://github.com/sigp/lighthouse/issues/1978
        let lockfile_path = dir.join(format!("{}.lock", VOTING_KEYSTORE_FILE));
        let lockfile = Lockfile::new(lockfile_path).map_err(Error::LockfileError)?;

        Ok(Self {
            dir,
            _lockfile: lockfile,
        })
    }

    /// Returns the `dir` provided to `Self::open`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the path to the voting keystore JSON file.
    pub fn voting_keystore_path(&self) -> PathBuf {
        self.dir.join(VOTING_KEYSTORE_FILE)
    }

    /// Attempts to read the keystore in `self.dir` and decrypt the keypair using a password file
    /// in `password_dir`.
    ///
    /// The password file that is used will be based upon the pubkey value in the keystore.
    ///
    /// ## Errors
    ///
    /// If there is a filesystem error, a password is missing or the password is incorrect.
    pub fn voting_keypair<P: AsRef<Path>>(&self, password_dir: P) -> Result<Keypair, Error> {
        unlock_keypair(&self.dir.join(VOTING_KEYSTORE_FILE), password_dir)
    }

    /// Attempts to read the keystore in `self.dir` and decrypt the keypair using a password file
    /// in `password_dir`.
    ///
    /// The password file that is used will be based upon the pubkey value in the keystore.
    ///
    /// ## Errors
    ///
    /// If there is a file-system error, a password is missing or the password is incorrect.
    pub fn withdrawal_keypair<P: AsRef<Path>>(&self, password_dir: P) -> Result<Keypair, Error> {
        unlock_keypair(&self.dir.join(WITHDRAWAL_KEYSTORE_FILE), password_dir)
    }

    /// Indicates if there is a file containing an eth1 deposit transaction. This can be used to
    /// check if a deposit transaction has been created.
    ///
    /// ## Note
    ///
    /// It's possible to submit an Eth1 deposit without creating this file, so use caution when
    /// relying upon this value.
    pub fn eth1_deposit_tx_hash_exists(&self) -> bool {
        self.dir.join(ETH1_DEPOSIT_TX_HASH_FILE).exists()
    }

    /// Saves the `tx_hash` to a file in `self.dir`. Artificially requires `mut self` to prevent concurrent
    /// calls.
    ///
    /// ## Errors
    ///
    /// If there is a file-system error, or if there is already a transaction hash stored in
    /// `self.dir`.
    pub fn save_eth1_deposit_tx_hash(&mut self, tx_hash: &str) -> Result<(), Error> {
        let path = self.dir.join(ETH1_DEPOSIT_TX_HASH_FILE);

        if path.exists() {
            return Err(Error::Eth1TxHashExists(path));
        }

        write(path, tx_hash.as_bytes()).map_err(Error::UnableToWriteEth1TxHash)
    }

    /// Attempts to read files in `self.dir` and return an `Eth1DepositData` that can be used for
    /// submitting an Eth1 deposit.
    ///
    /// ## Errors
    ///
    /// If there is a file-system error, not all required files exist or the files are
    /// inconsistent.
    pub fn eth1_deposit_data(&self) -> Result<Option<Eth1DepositData>, Error> {
        // Read and parse `ETH1_DEPOSIT_DATA_FILE`.
        let path = self.dir.join(ETH1_DEPOSIT_DATA_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let deposit_data_rlp = read(path)
            .map_err(Error::UnableToReadDepositData)
            .and_then(|hex_bytes| {
                let hex = std::str::from_utf8(&hex_bytes).map_err(|_| Error::DepositDataNotUtf8)?;
                if let Some(stripped) = hex.strip_prefix("0x") {
                    hex::decode(stripped).map_err(Error::DepositDataInvalidHex)
                } else {
                    Err(Error::DepositDataMissing0xPrefix)
                }
            })?;

        // Read and parse `ETH1_DEPOSIT_AMOUNT_FILE`.
        let path = self.dir.join(ETH1_DEPOSIT_AMOUNT_FILE);
        if !path.exists() {
            return Err(Error::DepositAmountDoesNotExist(path));
        }
        let deposit_amount: u64 =
            String::from_utf8(read(path).map_err(Error::UnableToReadDepositAmount)?)
                .map_err(Error::DepositAmountIsNotUtf8)?
                .parse()
                .map_err(Error::UnableToParseDepositAmount)?;

        let (deposit_data, root) = decode_eth1_tx_data(&deposit_data_rlp, deposit_amount)
            .map_err(Error::UnableToParseDepositData)?;

        // This acts as a sanity check to ensure that the amount from `ETH1_DEPOSIT_AMOUNT_FILE`
        // matches the value that `ETH1_DEPOSIT_DATA_FILE` was created with.
        if deposit_data.tree_hash_root() != root {
            return Err(Error::Eth1DepositRootMismatch);
        }

        Ok(Some(Eth1DepositData {
            rlp: deposit_data_rlp,
            deposit_data,
            root,
        }))
    }
}

/// Attempts to load and decrypt a Keypair given path to the keystore.
pub fn unlock_keypair<P: AsRef<Path>>(
    keystore_path: &Path,
    password_dir: P,
) -> Result<Keypair, Error> {
    let keystore = Keystore::from_json_reader(
        &mut File::options()
            .read(true)
            .create(false)
            .open(keystore_path)
            .map_err(Error::UnableToOpenKeystore)?,
    )
    .map_err(Error::UnableToReadKeystore)?;

    let password_path = keystore_password_path(password_dir, &keystore);
    let password: PlainText = read(&password_path)
        .map_err(|_| Error::UnableToReadPassword(password_path))?
        .into();
    keystore
        .decrypt_keypair(password.as_bytes())
        .map_err(Error::UnableToDecryptKeypair)
}

/// Attempts to load and decrypt a Keypair given path to the keystore and the password file.
pub fn unlock_keypair_from_password_path(
    keystore_path: &Path,
    password_path: &Path,
) -> Result<Keypair, Error> {
    let keystore = Keystore::from_json_reader(
        &mut File::options()
            .read(true)
            .create(false)
            .open(keystore_path)
            .map_err(Error::UnableToOpenKeystore)?,
    )
    .map_err(Error::UnableToReadKeystore)?;

    let password: PlainText = read(password_path)
        .map_err(|_| Error::UnableToReadPassword(password_path.into()))?
        .into();
    keystore
        .decrypt_keypair(password.as_bytes())
        .map_err(Error::UnableToDecryptKeypair)
}
