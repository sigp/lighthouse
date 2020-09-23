//! Provides management of "initialized" validators.
//!
//! A validator is "initialized" if it is ready for signing blocks, attestations, etc in this
//! validator client.
//!
//! The `InitializedValidators` struct in this file serves as the source-of-truth of which
//! validators are managed by this validator client.

use account_utils::{
    read_password, read_password_from_user,
    validator_definitions::{
        self, SigningDefinition, ValidatorDefinition, ValidatorDefinitions, CONFIG_FILENAME,
    },
};
use eth2_keystore::Keystore;
use slog::{error, info, warn, Logger};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use types::{Keypair, PublicKey};

// Use TTY instead of stdin to capture passwords from users.
const USE_STDIN: bool = false;

#[derive(Debug)]
pub enum Error {
    /// Refused to open a validator with an existing lockfile since that validator may be in-use by
    /// another process.
    LockfileExists(PathBuf),
    /// There was a filesystem error when creating the lockfile.
    UnableToCreateLockfile(io::Error),
    /// The voting public key in the definition did not match the one in the keystore.
    VotingPublicKeyMismatch {
        definition: Box<PublicKey>,
        keystore: Box<PublicKey>,
    },
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
    /// There was an error updating the on-disk validator definitions file.
    UnableToSaveDefinitions(validator_definitions::Error),
    /// It is not legal to try and initialize a disabled validator definition.
    UnableToInitializeDisabledValidator,
    /// There was an error reading from stdin.
    UnableToReadPasswordFromUser(String),
    /// There was an error running a tokio async task.
    TokioJoin(tokio::task::JoinError),
    /// There was a filesystem error when deleting a lockfile.
    UnableToDeleteLockfile(io::Error),
}

/// A method used by a validator to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
pub enum SigningMethod {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile_path: PathBuf,
        voting_keystore: Keystore,
        voting_keypair: Keypair,
    },
}

/// A validator that is ready to sign messages.
pub struct InitializedValidator {
    signing_method: SigningMethod,
}

impl InitializedValidator {
    /// Instantiate `self` from a `ValidatorDefinition`.
    ///
    /// If `stdin.is_some()` any missing passwords will result in a prompt requesting input on
    /// stdin (prompts published to stderr).
    ///
    /// ## Errors
    ///
    /// If the validator is unable to be initialized for whatever reason.
    pub fn from_definition(
        def: ValidatorDefinition,
        delete_lockfiles: bool,
        log: &Logger,
    ) -> Result<Self, Error> {
        if !def.enabled {
            return Err(Error::UnableToInitializeDisabledValidator);
        }

        match def.signing_definition {
            // Load the keystore, password, decrypt the keypair and create a lockfile for a
            // EIP-2335 keystore on the local filesystem.
            SigningDefinition::LocalKeystore {
                voting_keystore_path,
                voting_keystore_password_path,
                voting_keystore_password,
            } => {
                let keystore_file =
                    File::open(&voting_keystore_path).map_err(Error::UnableToOpenVotingKeystore)?;
                let voting_keystore = Keystore::from_json_reader(keystore_file)
                    .map_err(Error::UnableToParseVotingKeystore)?;

                let voting_keypair = match (voting_keystore_password_path, voting_keystore_password)
                {
                    // If the password is supplied, use it and ignore the path (if supplied).
                    (_, Some(password)) => voting_keystore
                        .decrypt_keypair(password.as_ref())
                        .map_err(Error::UnableToDecryptKeystore)?,
                    // If only the path is supplied, use the path.
                    (Some(path), None) => {
                        let password = read_password(path)
                            .map_err(Error::UnableToReadVotingKeystorePassword)?;

                        voting_keystore
                            .decrypt_keypair(password.as_bytes())
                            .map_err(Error::UnableToDecryptKeystore)?
                    }
                    // If there is no password available, maybe prompt for a password.
                    (None, None) => {
                        unlock_keystore_via_stdin_password(&voting_keystore, &voting_keystore_path)?
                    }
                };

                if voting_keypair.pk != def.voting_public_key {
                    return Err(Error::VotingPublicKeyMismatch {
                        definition: Box::new(def.voting_public_key),
                        keystore: Box::new(voting_keypair.pk),
                    });
                }

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
                    if delete_lockfiles {
                        warn!(
                            log,
                            "Deleting validator lockfile";
                            "file" => format!("{:?}", voting_keystore_lockfile_path)
                        );

                        fs::remove_file(&voting_keystore_lockfile_path)
                            .map_err(Error::UnableToDeleteLockfile)?;
                    } else {
                        return Err(Error::LockfileExists(voting_keystore_lockfile_path));
                    }
                } else {
                    // Create a new lockfile.
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&voting_keystore_lockfile_path)
                        .map_err(Error::UnableToCreateLockfile)?;
                }

                Ok(Self {
                    signing_method: SigningMethod::LocalKeystore {
                        voting_keystore_path,
                        voting_keystore_lockfile_path,
                        voting_keystore,
                        voting_keypair,
                    },
                })
            }
        }
    }

    /// Returns the voting public key for this validator.
    pub fn voting_public_key(&self) -> &PublicKey {
        match &self.signing_method {
            SigningMethod::LocalKeystore { voting_keypair, .. } => &voting_keypair.pk,
        }
    }

    /// Returns the voting keypair for this validator.
    pub fn voting_keypair(&self) -> &Keypair {
        match &self.signing_method {
            SigningMethod::LocalKeystore { voting_keypair, .. } => voting_keypair,
        }
    }
}

/// Custom drop implementation to allow for `LocalKeystore` to remove lockfiles.
impl Drop for InitializedValidator {
    fn drop(&mut self) {
        match &self.signing_method {
            SigningMethod::LocalKeystore {
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

/// Try to unlock `keystore` at `keystore_path` by prompting the user via `stdin`.
fn unlock_keystore_via_stdin_password(
    keystore: &Keystore,
    keystore_path: &PathBuf,
) -> Result<Keypair, Error> {
    eprintln!("");
    eprintln!(
        "The {} file does not contain either of the following fields for {:?}:",
        CONFIG_FILENAME, keystore_path
    );
    eprintln!("");
    eprintln!(" - voting_keystore_password");
    eprintln!(" - voting_keystore_password_path");
    eprintln!("");
    eprintln!(
        "You may exit and update {} or enter a password. \
                            If you choose to enter a password now then this prompt \
                            will be raised next time the validator is started.",
        CONFIG_FILENAME
    );
    eprintln!("");
    eprintln!("Enter password (or press Ctrl+c to exit):");

    loop {
        let password =
            read_password_from_user(USE_STDIN).map_err(Error::UnableToReadPasswordFromUser)?;

        eprintln!("");

        match keystore.decrypt_keypair(password.as_ref()) {
            Ok(keystore) => break Ok(keystore),
            Err(eth2_keystore::Error::InvalidPassword) => {
                eprintln!("Invalid password, try again (or press Ctrl+c to exit):");
            }
            Err(e) => return Err(Error::UnableToDecryptKeystore(e)),
        }
    }
}

/// A set of `InitializedValidator` objects which is initialized from a list of
/// `ValidatorDefinition`. The `ValidatorDefinition` file is maintained as `self` is modified.
///
/// Forms the fundamental list of validators that are managed by this validator client instance.
pub struct InitializedValidators {
    /// If `true`, no validator will be opened if a lockfile exists. If `false`, a warning will be
    /// raised for an existing lockfile, but it will ultimately be ignored.
    strict_lockfiles: bool,
    /// A list of validator definitions which can be stored on-disk.
    definitions: ValidatorDefinitions,
    /// The directory that the `self.definitions` will be saved into.
    validators_dir: PathBuf,
    /// The canonical set of validators.
    validators: HashMap<PublicKey, InitializedValidator>,
    /// For logging via `slog`.
    log: Logger,
}

impl InitializedValidators {
    /// Instantiates `Self`, initializing all validators in `definitions`.
    pub async fn from_definitions(
        definitions: ValidatorDefinitions,
        validators_dir: PathBuf,
        strict_lockfiles: bool,
        log: Logger,
    ) -> Result<Self, Error> {
        let mut this = Self {
            strict_lockfiles,
            validators_dir,
            definitions,
            validators: HashMap::default(),
            log,
        };
        this.update_validators().await?;
        Ok(this)
    }

    /// The count of enabled validators contained in `self`.
    pub fn num_enabled(&self) -> usize {
        self.validators.len()
    }

    /// The total count of enabled and disabled validators contained in `self`.
    pub fn num_total(&self) -> usize {
        self.definitions.as_slice().len()
    }

    /// Iterate through all **enabled** voting public keys in `self`.
    pub fn iter_voting_pubkeys(&self) -> impl Iterator<Item = &PublicKey> {
        self.validators.iter().map(|(pubkey, _)| pubkey)
    }

    /// Returns the voting `Keypair` for a given voting `PublicKey`, if that validator is known to
    /// `self` **and** the validator is enabled.
    pub fn voting_keypair(&self, voting_public_key: &PublicKey) -> Option<&Keypair> {
        self.validators
            .get(voting_public_key)
            .map(|v| v.voting_keypair())
    }

    /// Returns a slice of all defined validators (regardless of their enabled state).
    pub fn validator_definitions(&self) -> &[ValidatorDefinition] {
        self.definitions.as_slice()
    }

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `enabled` values.
    ///
    /// ## Notes
    ///
    /// Enabling or disabling a validator will cause `self.definitions` to be updated and saved to
    /// disk. A newly enabled validator will be added to `self.validators`, whilst a newly disabled
    /// validator will be removed from `self.validators`.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    #[allow(dead_code)] // Will be used once VC API is enabled.
    pub async fn set_validator_status(
        &mut self,
        voting_public_key: &PublicKey,
        enabled: bool,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.enabled = enabled;
        }

        self.update_validators().await?;

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Scans `self.definitions` and attempts to initialize and validators which are not already
    /// initialized.
    ///
    /// The function exits early with an error if any enabled validator is unable to be
    /// initialized.
    ///
    /// ## Notes
    ///
    /// A validator is considered "already known" and skipped if the public key is already known.
    /// I.e., if there are two different definitions with the same public key then the second will
    /// be ignored.
    async fn update_validators(&mut self) -> Result<(), Error> {
        for def in self.definitions.as_slice() {
            if def.enabled {
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore { .. } => {
                        if self.validators.contains_key(&def.voting_public_key) {
                            continue;
                        }

                        // Decoding a local keystore can take several seconds, therefore it's best
                        // to keep if off the core executor. This also has the fortunate effect of
                        // interrupting the potentially long-running task during shut down.
                        let inner_def = def.clone();
                        let strict_lockfiles = self.strict_lockfiles;
                        let inner_log = self.log.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            InitializedValidator::from_definition(
                                inner_def,
                                strict_lockfiles,
                                &inner_log,
                            )
                        })
                        .await
                        .map_err(Error::TokioJoin)?;

                        match result {
                            Ok(init) => {
                                self.validators
                                    .insert(init.voting_public_key().clone(), init);
                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key)
                                );
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "validator" => format!("{:?}", def.voting_public_key)
                                );

                                // Exit on an invalid validator.
                                return Err(e);
                            }
                        }
                    }
                }
            } else {
                self.validators.remove(&def.voting_public_key);
                info!(
                    self.log,
                    "Disabled validator";
                    "voting_pubkey" => format!("{:?}", def.voting_public_key)
                );
            }
        }
        Ok(())
    }
}
