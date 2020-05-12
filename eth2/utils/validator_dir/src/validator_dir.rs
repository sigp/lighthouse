use crate::builder::{VOTING_KEYSTORE_FILE, WITHDRAWAL_KEYSTORE_FILE};
use eth2_keystore::{Error as KeystoreError, Keystore, PlainText};
use std::fs::{read, remove_file, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use types::Keypair;

const LOCK_FILE: &str = ".lock";

#[derive(Debug)]
pub enum Error {
    DirectoryDoesNotExist(PathBuf),
    DirectoryLocked(PathBuf),
    UnableToCreateLockfile(io::Error),
    UnableToOpenKeystore(io::Error),
    UnableToReadKeystore(KeystoreError),
    UnableToOpenPassword(io::Error),
    UnableToReadPassword(io::Error),
    UnableToDecryptKeypair(KeystoreError),
    #[cfg(feature = "unencrypted_keys")]
    SszKeypairError(String),
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
}

impl Drop for ValidatorDir {
    fn drop(&mut self) {
        let lockfile = self.dir.clone().join(LOCK_FILE);
        if let Err(e) = remove_file(&lockfile) {
            eprintln!("Unable to remove validator {:?}: {:?}", lockfile, e);
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

    let password: PlainText = read(
        password_dir
            .as_ref()
            .join(format!("0x{}", keystore.pubkey())),
    )
    .map_err(Error::UnableToReadPassword)?
    .into();

    keystore
        .decrypt_keypair(password.as_bytes())
        .map_err(Error::UnableToDecryptKeypair)
}
