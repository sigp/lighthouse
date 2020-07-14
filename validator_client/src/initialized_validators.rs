use crate::validator_definitions::ValidatorDefinition;
use account_utils::read_password;
use eth2_keystore::Keystore;
use slog::{error, warn, Logger};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use types::Keypair;

#[derive(Debug)]
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
        respect_lockfiles: bool,
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
                    if respect_lockfiles {
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

impl Drop for InitializedValidator {
    fn drop(&mut self) {
        match self {
            InitializedValidator::LocalKeystore {
                voting_keystore_lockfile_path,
                ..
            } => {
                if voting_keystore_lockfile_path.exists() {
                    if let Err(e) = fs::remove_file(&voting_keystore_lockfile_path) {
                        eprintln!(
                            "Failed to remove {:?}: {:?}",
                            voting_keystore_lockfile_path, e
                        )
                    }
                } else {
                    eprintln!("Lockfile missing: {:?}", voting_keystore_lockfile_path)
                }
            }
        }
    }
}

#[derive(Default)]
pub struct InitializedValidators {
    validators: Vec<InitializedValidator>,
    known_voting_keystore_paths: HashSet<PathBuf>,
}

impl InitializedValidators {
    pub fn initialize(
        &mut self,
        defs: &[ValidatorDefinition],
        respect_lockfiles: bool,
        log: &Logger,
    ) -> Result<(), Error> {
        for def in defs {
            match def {
                ValidatorDefinition::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_password_path,
                } => {
                    if self
                        .known_voting_keystore_paths
                        .contains(voting_keystore_password_path)
                    {
                        continue;
                    }

                    match InitializedValidator::from_definition(def.clone(), respect_lockfiles, log)
                    {
                        Ok(init) => {
                            self.known_voting_keystore_paths
                                .insert(voting_keystore_path.clone());
                            self.validators.push(init)
                        }
                        Err(e) => error!(
                            log,
                            "Failed to initialize validator";
                            "error" => format!("{:?}", e),
                            "validator" => format!("{:?}", def)
                        ),
                    }
                }
            }
        }
        Ok(())
    }
}
