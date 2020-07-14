use crate::validator_definitions::ValidatorDefinition;
use account_utils::read_password;
use eth2_keystore::Keystore;
use slog::{warn, Logger};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use types::Keypair;

pub enum Error {
    LockfileExists(PathBuf),
    UnableToCreateLockfile(io::Error),
    UnableToOpenVotingKeystore(io::Error),
    BadVotingKeystorePath(PathBuf),
    UnableToParseVotingKeystore(eth2_keystore::Error),
    UnableToDecryptKeystore(eth2_keystore::Error),
    UnableToReadVotingKeystorePassword(io::Error),
}

pub enum InitializedValidator {
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile_path: PathBuf,
        voting_keystore: Keystore,
        voting_keypair: Keypair,
    },
}

impl InitializedValidator {
    pub fn from_definition(
        def: ValidatorDefinition,
        strict: bool,
        log: &Logger,
    ) -> Result<Self, Error> {
        match def {
            ValidatorDefinition::LocalKeystore {
                voting_keystore_path,
                voting_keystore_password_path,
            } => {
                let keystore_file =
                    File::open(&voting_keystore_path).map_err(Error::UnableToOpenVotingKeystore)?;
                let voting_keystore = Keystore::from_json_reader(keystore_file)
                    .map_err(Error::UnableToParseVotingKeystore)?;
                let password = read_password(voting_keystore_password_path)
                    .map_err(Error::UnableToReadVotingKeystorePassword)?;
                let voting_keypair = voting_keystore
                    .decrypt_keypair(password.as_bytes())
                    .map_err(Error::UnableToDecryptKeystore)?;

                let voting_keystore_lockfile_path = voting_keystore_path
                    .file_name()
                    .ok_or_else(|| Error::BadVotingKeystorePath(voting_keystore_path.clone()))
                    .and_then(|os_str| {
                        os_str.to_str().ok_or_else(|| {
                            Error::BadVotingKeystorePath(voting_keystore_path.clone())
                        })
                    })
                    .map(|filename| {
                        voting_keystore_path
                            .clone()
                            .with_file_name(format!("{}.lock", filename))
                    })?;

                if voting_keystore_lockfile_path.exists() {
                    if strict {
                        return Err(Error::LockfileExists(voting_keystore_lockfile_path));
                    } else {
                        warn!(
                            log,
                            "Ignoring validator lockfile";
                            "file" => format!("{:?}", voting_keystore_lockfile_path)
                        );
                    }
                } else {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&voting_keystore_lockfile_path)
                        .map_err(Error::UnableToCreateLockfile)?;
                }

                Ok(InitializedValidator::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_lockfile_path,
                    voting_keystore,
                    voting_keypair,
                })
            }
        }
    }
}
