//! Provides management of "initialized" validators.
//!
//! A validator is "initialized" if it is ready for signing blocks, attestations, etc in this
//! validator client.
//!
//! The `InitializedValidators` struct in this file serves as the source-of-truth of which
//! validators are managed by this validator client.

use crate::validator_definitions::ValidatorDefinition;
use account_utils::read_password;
use eth2_keystore::Keystore;
use slog::{error, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use types::{Keypair, PublicKey};

#[derive(Debug)]
pub enum Error {
    /// Refused to opee a validator with an existing lockfile since that validator may be in-use by
    /// another process.
    LockfileExists(PathBuf),
    /// There was a filesystem error when creating the lockfile.
    UnableToCreateLockfile(io::Error),
    /// There was a filesystem error when opening the keystore.
    UnableToOpenVotingKeystore(io::Error),
    /// The keystore path is not as expected. It should be a file, not `..` or something obscure
    /// like that.
    BadVotingKeystorePath(PathBuf),
    /// The keystore could not be parsed, it is likely bad JSON.
    UnableToParseVotingKeystore(eth2_keystore::Error),
    /// The keystore could not be decrypted. The password might be wrong.
    UnableToDecryptKeystore(eth2_keystore::Error),
    /// There was a filesystem error when reading the keystore password from disk.
    UnableToReadVotingKeystorePassword(io::Error),
}

/// A validator that is ready to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
pub enum InitializedValidator {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile_path: PathBuf,
        voting_keystore: Keystore,
        voting_keypair: Keypair,
    },
}

impl InitializedValidator {
    /// Returns the voting public key for this validator.
    pub fn voting_public_key(&self) -> &PublicKey {
        match self {
            InitializedValidator::LocalKeystore { voting_keypair, .. } => &voting_keypair.pk,
        }
    }

    /// Returns the voting keypair for this validator.
    pub fn voting_keypair(&self) -> &Keypair {
        match self {
            InitializedValidator::LocalKeystore { voting_keypair, .. } => voting_keypair,
        }
    }

    /// Instantiate `self` from a `ValidatorDefinition`.
    ///
    /// ## Errors
    ///
    /// If the validator is unable to be initialized for whatever reason.
    pub fn from_definition(
        def: ValidatorDefinition,
        respect_lockfiles: bool,
        log: &Logger,
    ) -> Result<Self, Error> {
        match def {
            // Load the keystore, password, decrypt the keypair and create a lockfile for a
            // EIP-2335 keystore on the local filesystem.
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

                // Append a `.lock` suffix to the voting keystore.
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
                        // If **not** respecting lockfiles, just raise a warning if the voting
                        // keypair cannot be unlocked.
                        warn!(
                            log,
                            "Ignoring validator lockfile";
                            "file" => format!("{:?}", voting_keystore_lockfile_path)
                        );
                    }
                } else {
                    // Create a new lockfile.
                    OpenOptions::new()
                        // TODO: can remove this write?
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

/// Custom drop implementation to allow for `LocalKeystore` to remove lockfiles.
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

/// A set of `InitializedValidator` objects which can be initialized from a list of
/// `ValidatorDefinition`.
///
/// Forms the fundamental list of validators that are managed by this validator client instance.
#[derive(Default)]
pub struct InitializedValidators {
    /// The canonical set of validators.
    validators: HashMap<PublicKey, InitializedValidator>,
    /// An ancillary set that is used to cheaply detect if a validator keystore is already known.
    known_voting_keystore_paths: HashSet<PathBuf>,
}

impl InitializedValidators {
    /// The count of validators contained in `self`.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Iterate through all voting public keys in `self`.
    pub fn iter_voting_pubkeys(&self) -> impl Iterator<Item = &PublicKey> {
        self.validators.keys()
    }

    /// Returns the voting `Keypair` for a given voting `PublicKey`, if that validator is known to
    /// `self`.
    pub fn voting_keypair(&self, voting_public_key: &PublicKey) -> Option<&Keypair> {
        self.validators
            .get(voting_public_key)
            .map(|v| v.voting_keypair())
    }

    /// Scans `defs` and attempts to initialize and validators which are not already known.
    ///
    /// If a validator is unable to be initialized an `error` log is raised but the function does
    /// not terminate; it will attempt to load more validators.
    ///
    /// ## Notes
    ///
    /// A validator is considered "already known" and skipped if:
    ///
    /// - A `LocalKeystore` validator uses a voting keystore path that is already known.
    /// - A validator with the same voting public key already exists.
    pub fn initialize_definitions(
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
                            // Avoid replacing an existing validator.
                            if self.validators.contains_key(init.voting_public_key()) {
                                continue;
                            }

                            self.validators
                                .insert(init.voting_public_key().clone(), init);
                            self.known_voting_keystore_paths
                                .insert(voting_keystore_path.clone());
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
