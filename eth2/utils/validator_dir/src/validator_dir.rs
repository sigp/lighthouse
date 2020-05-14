use crate::builder::{
    ETH1_DEPOSIT_AMOUNT_FILE, ETH1_DEPOSIT_DATA_FILE, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE,
};
use deposit_contract::decode_eth1_tx_data;
use eth2_keystore::{Error as KeystoreError, Keystore, PlainText};
use std::fs::{read, remove_file, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use tree_hash::TreeHash;
use types::{DepositData, Hash256, Keypair};

const LOCK_FILE: &str = ".lock";

#[derive(Debug)]
pub enum Error {
    DirectoryDoesNotExist(PathBuf),
    DirectoryLocked(PathBuf),
    UnableToCreateLockfile(io::Error),
    UnableToOpenKeystore(io::Error),
    UnableToReadKeystore(KeystoreError),
    UnableToOpenPassword(io::Error),
    UnableToReadPassword(PathBuf),
    UnableToDecryptKeypair(KeystoreError),
    UnableToReadDepositData(io::Error),
    DepositAmountDoesNotExist(PathBuf),
    UnableToReadDepositAmount(io::Error),
    UnableToParseDepositAmount(std::num::ParseIntError),
    DepositAmountIsNotUtf8(std::string::FromUtf8Error),
    UnableToParseDepositData(deposit_contract::DecodeError),
    Eth1DepositRootMismatch,
    #[cfg(feature = "unencrypted_keys")]
    SszKeypairError(String),
}

pub struct Eth1DepositData {
    pub rlp: Vec<u8>,
    pub deposit_data: DepositData,
    pub root: Hash256,
}

#[derive(Debug, PartialEq)]
pub struct ValidatorDir {
    pub dir: PathBuf,
}

impl ValidatorDir {
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir: &Path = dir.as_ref();
        let dir: PathBuf = dir.into();

        if !dir.exists() {
            return Err(Error::DirectoryDoesNotExist(dir));
        }

        let lockfile = dir.join(LOCK_FILE);
        if lockfile.exists() {
            return Err(Error::DirectoryLocked(dir));
        } else {
            File::create(lockfile).map_err(Error::UnableToCreateLockfile)?;
        }

        Ok(Self { dir })
    }

    pub fn voting_keypair<P: AsRef<Path>>(&self, password_dir: P) -> Result<Keypair, Error> {
        unlock_keypair(&self.dir.clone(), VOTING_KEYSTORE_FILE, password_dir)
    }

    pub fn withdrawal_keypair<P: AsRef<Path>>(&self, password_dir: P) -> Result<Keypair, Error> {
        unlock_keypair(&self.dir.clone(), WITHDRAWAL_KEYSTORE_FILE, password_dir)
    }

    pub fn eth1_deposit_data(&self) -> Result<Option<Eth1DepositData>, Error> {
        // Read and parse `ETH1_DEPOSIT_DATA_FILE`.
        let path = self.dir.join(ETH1_DEPOSIT_DATA_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let deposit_data_rlp = read(path).map_err(Error::UnableToReadDepositData)?;

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

impl Drop for ValidatorDir {
    fn drop(&mut self) {
        let lockfile = self.dir.clone().join(LOCK_FILE);
        if let Err(e) = remove_file(&lockfile) {
            eprintln!(
                "Unable to remove validator lockfile {:?}: {:?}",
                lockfile, e
            );
        }
    }
}

fn unlock_keypair<P: AsRef<Path>>(
    keystore_dir: &PathBuf,
    filename: &str,
    password_dir: P,
) -> Result<Keypair, Error> {
    let keystore = Keystore::from_json_reader(
        &mut OpenOptions::new()
            .read(true)
            .create(false)
            .open(keystore_dir.clone().join(filename))
            .map_err(Error::UnableToOpenKeystore)?,
    )
    .map_err(Error::UnableToReadKeystore)?;

    let password_path = password_dir
        .as_ref()
        .join(format!("0x{}", keystore.pubkey()));
    let password: PlainText = read(&password_path)
        .map_err(|_| Error::UnableToReadPassword(password_path.into()))?
        .into();

    keystore
        .decrypt_keypair(password.as_bytes())
        .map_err(Error::UnableToDecryptKeypair)
}
