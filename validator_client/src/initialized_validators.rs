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
    ZeroizeString,
};
use environment::TaskExecutor;
use eth2_keystore::Keystore;
use slog::{debug, error, info, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use types::{Keypair, PublicKey};

use crate::key_cache;
use crate::key_cache::KeyCache;

// Use TTY instead of stdin to capture passwords from users.
const USE_STDIN: bool = false;

const SAVE_CACHE_TASK_NAME: &str = "validator_client_save_key_cache";

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
    UnableToOpenKeyCache(key_cache::Error),
    /// The keystore path is not as expected. It should be a file, not `..` or something obscure
    /// like that.
    BadVotingKeystorePath(PathBuf),
    BadKeyCachePath(PathBuf),
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
    /// It is not legal to try and initialize a disabled validator definition.
    PasswordUnknown(PathBuf),
    /// There was an error reading from stdin.
    UnableToReadPasswordFromUser(String),
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

fn open_keystore(path: &PathBuf) -> Result<Keystore, Error> {
    let keystore_file = File::open(path).map_err(Error::UnableToOpenVotingKeystore)?;
    Keystore::from_json_reader(keystore_file).map_err(Error::UnableToParseVotingKeystore)
}

fn get_lockfile_path(file_path: &PathBuf) -> Option<PathBuf> {
    file_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .map(|filename| {
            file_path
                .clone()
                .with_file_name(format!("{}.lock", filename))
        })
}

fn create_lock_file(
    file_path: &PathBuf,
    strict_lockfiles: bool,
    log: &Logger,
) -> Result<(), Error> {
    if file_path.exists() {
        if strict_lockfiles {
            return Err(Error::LockfileExists(file_path.clone()));
        } else {
            // If **not** respecting lockfiles, just raise a warning if the voting
            // keypair cannot be unlocked.
            warn!(
                log,
                "Ignoring validator lockfile";
                "file" => format!("{:?}", file_path)
            );
        }
    } else {
        // Create a new lockfile.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .map_err(Error::UnableToCreateLockfile)?;
    }
    Ok(())
}

fn remove_lock(lock_path: &PathBuf) {
    if lock_path.exists() {
        if let Err(e) = fs::remove_file(&lock_path) {
            eprintln!("Failed to remove {:?}: {:?}", lock_path, e)
        }
    } else {
        eprintln!("Lockfile missing: {:?}", lock_path)
    }
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
        strict_lockfiles: bool,
        log: &Logger,
        key_cache: &mut KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
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
                use std::collections::hash_map::Entry::*;
                let voting_keystore = match key_stores.entry(voting_keystore_path.clone()) {
                    Vacant(entry) => entry.insert(open_keystore(&voting_keystore_path)?),
                    Occupied(entry) => entry.into_mut(),
                };

                let voting_keypair = if let Some(keypair) = key_cache.get(voting_keystore.uuid()) {
                    keypair
                } else {
                    let (password, keypair) =
                        match (voting_keystore_password_path, voting_keystore_password) {
                            // If the password is supplied, use it and ignore the path (if supplied).
                            (_, Some(password)) => (
                                password.as_ref().into(),
                                voting_keystore
                                    .decrypt_keypair(password.as_ref())
                                    .map_err(Error::UnableToDecryptKeystore)?,
                            ),
                            // If only the path is supplied, use the path.
                            (Some(path), None) => {
                                let password = read_password(path)
                                    .map_err(Error::UnableToReadVotingKeystorePassword)?;

                                (
                                    password.as_ref().into(),
                                    voting_keystore
                                        .decrypt_keypair(password.as_bytes())
                                        .map_err(Error::UnableToDecryptKeystore)?,
                                )
                            }
                            // If there is no password available, maybe prompt for a password.
                            (None, None) => {
                                let (password, keypair) = unlock_keystore_via_stdin_password(
                                    voting_keystore,
                                    &voting_keystore_path,
                                )?;
                                (password.as_ref().into(), keypair)
                            }
                        };
                    key_cache.add(keypair.clone(), voting_keystore.uuid(), password);
                    keypair
                };

                if voting_keypair.pk != def.voting_public_key {
                    return Err(Error::VotingPublicKeyMismatch {
                        definition: Box::new(def.voting_public_key),
                        keystore: Box::new(voting_keypair.pk),
                    });
                }

                // Append a `.lock` suffix to the voting keystore.
                let voting_keystore_lockfile_path = get_lockfile_path(&voting_keystore_path)
                    .ok_or_else(|| Error::BadVotingKeystorePath(voting_keystore_path.clone()))?;

                create_lock_file(&voting_keystore_lockfile_path, strict_lockfiles, &log)?;

                Ok(Self {
                    signing_method: SigningMethod::LocalKeystore {
                        voting_keystore_path,
                        voting_keystore_lockfile_path,
                        voting_keystore: voting_keystore.clone(),
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
                remove_lock(voting_keystore_lockfile_path);
            }
        }
    }
}

/// Try to unlock `keystore` at `keystore_path` by prompting the user via `stdin`.
fn unlock_keystore_via_stdin_password(
    keystore: &Keystore,
    keystore_path: &PathBuf,
) -> Result<(ZeroizeString, Keypair), Error> {
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
            Ok(keystore) => break Ok((password, keystore)),
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
    pub fn from_definitions(
        definitions: ValidatorDefinitions,
        validators_dir: PathBuf,
        strict_lockfiles: bool,
        log: Logger,
        executor: &TaskExecutor,
    ) -> Result<Self, Error> {
        let mut this = Self {
            strict_lockfiles,
            validators_dir,
            definitions,
            validators: HashMap::default(),
            log,
        };
        this.update_validators(executor)?;
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

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `enabled` values.
    ///
    /// ## Notes
    ///
    /// Enabling or disabling a validator will cause `self.definitions` to be updated and saved to
    /// disk. A newly enabled validator will be added to `self.validators`, whilst a newly disabled
    /// validator will be removed from `self.validators`.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn set_validator_status(
        &mut self,
        voting_public_key: &PublicKey,
        enabled: bool,
        executor: &TaskExecutor,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.enabled = enabled;
        }

        self.update_validators(executor)?;

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Tries to decrypt the key cache.
    ///
    /// Returns `Ok(true)` if decryption was successful, `Ok(false)` if it couldn't get decrypted
    /// and an error if a needed password couldn't get extracted.
    ///
    fn try_decrypt_key_cache(
        &self,
        cache: &mut KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
    ) -> Result<bool, Error> {
        //read relevant key_stores
        let mut definitions_map = HashMap::new();
        for def in self.definitions.as_slice() {
            match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    ..
                } => {
                    use std::collections::hash_map::Entry::*;
                    let key_store = match key_stores.entry(voting_keystore_path.clone()) {
                        Vacant(entry) => entry.insert(open_keystore(voting_keystore_path)?),
                        Occupied(entry) => entry.into_mut(),
                    };
                    definitions_map.insert(*key_store.uuid(), def);
                }
            }
        }

        //check if all paths are in the definitions_map
        for uuid in cache.uuids() {
            if !definitions_map.contains_key(uuid) {
                warn!(
                    self.log,
                    "Unknown uuid in cache";
                    "uuid" => format!("{}", uuid)
                );
                return Ok(false);
            }
        }

        //collect passwords
        let mut passwords = Vec::new();
        let mut public_keys = Vec::new();
        for uuid in cache.uuids() {
            let def = definitions_map.get(uuid).expect("Existence checked before");
            let pw = match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_password_path,
                    voting_keystore_password,
                    voting_keystore_path,
                } => {
                    if let Some(p) = voting_keystore_password {
                        p.as_ref().into()
                    } else if let Some(path) = voting_keystore_password_path {
                        read_password(path)
                            .map_err(Error::UnableToReadVotingKeystorePassword)?
                            .as_ref()
                            .into()
                    } else {
                        let keystore = open_keystore(voting_keystore_path)?;
                        unlock_keystore_via_stdin_password(&keystore, &voting_keystore_path)?
                            .0
                            .as_ref()
                            .into()
                    }
                }
            };
            passwords.push(pw);
            public_keys.push(def.voting_public_key.clone());
        }

        //decrypt
        match cache.decrypt(passwords, public_keys) {
            Ok(_) | Err(key_cache::Error::AlreadyDecrypted) => Ok(true),
            Err(_) => Ok(false),
        }
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
    fn update_validators(&mut self, executor: &TaskExecutor) -> Result<(), Error> {
        //use key cache if available
        let mut key_stores = HashMap::new();

        // Create a lock file for the cache
        let key_cache_path = KeyCache::cache_file_path(&self.validators_dir);
        let cache_lockfile_path = get_lockfile_path(&key_cache_path)
            .ok_or_else(|| Error::BadKeyCachePath(key_cache_path))?;
        create_lock_file(&cache_lockfile_path, self.strict_lockfiles, &self.log)?;

        let mut key_cache = {
            let mut cache = KeyCache::open_or_create(&self.validators_dir)
                .map_err(Error::UnableToOpenKeyCache)?;
            if self.try_decrypt_key_cache(&mut cache, &mut key_stores)? {
                cache
            } else {
                KeyCache::new()
            }
        };

        let mut disabled_uuids = HashSet::new();
        for def in self.definitions.as_slice() {
            if def.enabled {
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        if self.validators.contains_key(&def.voting_public_key) {
                            continue;
                        }

                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.remove(key_store.uuid());
                        }

                        match InitializedValidator::from_definition(
                            def.clone(),
                            self.strict_lockfiles,
                            &self.log,
                            &mut key_cache,
                            &mut key_stores,
                        ) {
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
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.insert(*key_store.uuid());
                        }
                    }
                }

                info!(
                    self.log,
                    "Disabled validator";
                    "voting_pubkey" => format!("{:?}", def.voting_public_key)
                );
            }
        }
        for uuid in disabled_uuids {
            key_cache.remove(&uuid);
        }

        let validators_dir = self.validators_dir.clone();
        let log = self.log.clone();
        if key_cache.is_modified() {
            executor.spawn_blocking(
                move || {
                    match key_cache.save(validators_dir) {
                        Err(e) => warn!(
                            log,
                            "Error during saving of key_cache";
                            "err" => format!("{:?}", e)
                        ),
                        Ok(true) => info!(log, "Modified key_cache saved successfully"),
                        _ => {}
                    };
                    remove_lock(&cache_lockfile_path);
                },
                SAVE_CACHE_TASK_NAME,
            );
        } else {
            debug!(log, "Key cache not modified");
            remove_lock(&cache_lockfile_path);
        }
        Ok(())
    }
}
