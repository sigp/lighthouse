//! Provides management of "initialized" validators.
//!
//! A validator is "initialized" if it is ready for signing blocks, attestations, etc in this
//! validator client.
//!
//! The `InitializedValidators` struct in this file serves as the source-of-truth of which
//! validators are managed by this validator client.

use crate::signing_method::SigningMethod;
use account_utils::{
    read_password, read_password_from_user,
    validator_definitions::{
        self, SigningDefinition, ValidatorDefinition, ValidatorDefinitions, CONFIG_FILENAME,
    },
    ZeroizeString,
};
use eth2_keystore::Keystore;
use lighthouse_metrics::set_gauge;
use lockfile::{Lockfile, LockfileError};
use reqwest::{Certificate, Client, Error as ReqwestError};
use slog::{debug, error, info, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use types::{Graffiti, Keypair, PublicKey, PublicKeyBytes};
use url::{ParseError, Url};

use crate::key_cache;
use crate::key_cache::KeyCache;

/// Default timeout for a request to a remote signer for a signature.
///
/// Set to 12 seconds since that's the duration of a slot. A remote signer that cannot sign within
/// that time is outside the synchronous assumptions of Eth2.
const DEFAULT_REMOTE_SIGNER_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

// Use TTY instead of stdin to capture passwords from users.
const USE_STDIN: bool = false;

#[derive(Debug)]
pub enum Error {
    /// Refused to open a validator with an existing lockfile since that validator may be in-use by
    /// another process.
    Lockfile(LockfileError),
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
    /// There was an error reading from stdin.
    UnableToReadPasswordFromUser(String),
    /// There was an error running a tokio async task.
    TokioJoin(tokio::task::JoinError),
    /// Cannot initialize the same validator twice.
    DuplicatePublicKey,
    /// The public key does not exist in the set of initialized validators.
    ValidatorNotInitialized(PublicKey),
    /// Unable to read the slot clock.
    SlotClock,
    /// The URL for the remote signer cannot be parsed.
    InvalidWeb3SignerUrl(String),
    /// Unable to read the root certificate file for the remote signer.
    InvalidWeb3SignerRootCertificateFile(io::Error),
    InvalidWeb3SignerRootCertificate(ReqwestError),
    UnableToBuildWeb3SignerClient(ReqwestError),
}

impl From<LockfileError> for Error {
    fn from(error: LockfileError) -> Self {
        Self::Lockfile(error)
    }
}

/// A validator that is ready to sign messages.
pub struct InitializedValidator {
    signing_method: Arc<SigningMethod>,
    graffiti: Option<Graffiti>,
    /// The validators index in `state.validators`, to be updated by an external service.
    index: Option<u64>,
}

impl InitializedValidator {
    /// Return a reference to this validator's lockfile if it has one.
    pub fn keystore_lockfile(&self) -> Option<&Lockfile> {
        match self.signing_method.as_ref() {
            SigningMethod::LocalKeystore {
                ref voting_keystore_lockfile,
                ..
            } => Some(voting_keystore_lockfile),
            // Web3Signer validators do not have any lockfiles.
            SigningMethod::Web3Signer { .. } => None,
        }
    }
}

fn open_keystore(path: &Path) -> Result<Keystore, Error> {
    let keystore_file = File::open(path).map_err(Error::UnableToOpenVotingKeystore)?;
    Keystore::from_json_reader(keystore_file).map_err(Error::UnableToParseVotingKeystore)
}

fn get_lockfile_path(file_path: &Path) -> Option<PathBuf> {
    file_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .map(|filename| file_path.with_file_name(format!("{}.lock", filename)))
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
    async fn from_definition(
        def: ValidatorDefinition,
        key_cache: &mut KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
    ) -> Result<Self, Error> {
        if !def.enabled {
            return Err(Error::UnableToInitializeDisabledValidator);
        }

        let signing_method = match def.signing_definition {
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
                    let keystore = voting_keystore.clone();
                    let keystore_path = voting_keystore_path.clone();
                    // Decoding a local keystore can take several seconds, therefore it's best
                    // to keep if off the core executor. This also has the fortunate effect of
                    // interrupting the potentially long-running task during shut down.
                    let (password, keypair) = tokio::task::spawn_blocking(move || {
                        Result::<_, Error>::Ok(
                            match (voting_keystore_password_path, voting_keystore_password) {
                                // If the password is supplied, use it and ignore the path
                                // (if supplied).
                                (_, Some(password)) => (
                                    password.as_ref().to_vec().into(),
                                    keystore
                                        .decrypt_keypair(password.as_ref())
                                        .map_err(Error::UnableToDecryptKeystore)?,
                                ),
                                // If only the path is supplied, use the path.
                                (Some(path), None) => {
                                    let password = read_password(path)
                                        .map_err(Error::UnableToReadVotingKeystorePassword)?;
                                    let keypair = keystore
                                        .decrypt_keypair(password.as_bytes())
                                        .map_err(Error::UnableToDecryptKeystore)?;
                                    (password, keypair)
                                }
                                // If there is no password available, maybe prompt for a password.
                                (None, None) => {
                                    let (password, keypair) = unlock_keystore_via_stdin_password(
                                        &keystore,
                                        &keystore_path,
                                    )?;
                                    (password.as_ref().to_vec().into(), keypair)
                                }
                            },
                        )
                    })
                    .await
                    .map_err(Error::TokioJoin)??;
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
                let lockfile_path = get_lockfile_path(&voting_keystore_path)
                    .ok_or_else(|| Error::BadVotingKeystorePath(voting_keystore_path.clone()))?;

                let voting_keystore_lockfile = Lockfile::new(lockfile_path)?;

                SigningMethod::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_lockfile,
                    voting_keystore: voting_keystore.clone(),
                    voting_keypair: Arc::new(voting_keypair),
                }
            }
            SigningDefinition::Web3Signer {
                url,
                root_certificate_path,
                request_timeout_ms,
            } => {
                let signing_url = build_web3_signer_url(&url, &def.voting_public_key)
                    .map_err(|e| Error::InvalidWeb3SignerUrl(e.to_string()))?;
                let request_timeout = request_timeout_ms
                    .map(Duration::from_millis)
                    .unwrap_or(DEFAULT_REMOTE_SIGNER_REQUEST_TIMEOUT);

                let builder = Client::builder().timeout(request_timeout);

                let builder = if let Some(path) = root_certificate_path {
                    let certificate = load_pem_certificate(path)?;
                    builder.add_root_certificate(certificate)
                } else {
                    builder
                };

                let http_client = builder
                    .build()
                    .map_err(Error::UnableToBuildWeb3SignerClient)?;

                SigningMethod::Web3Signer {
                    signing_url,
                    http_client,
                    voting_public_key: def.voting_public_key,
                }
            }
        };

        Ok(Self {
            signing_method: Arc::new(signing_method),
            graffiti: def.graffiti.map(Into::into),
            index: None,
        })
    }

    /// Returns the voting public key for this validator.
    pub fn voting_public_key(&self) -> &PublicKey {
        match self.signing_method.as_ref() {
            SigningMethod::LocalKeystore { voting_keypair, .. } => &voting_keypair.pk,
            SigningMethod::Web3Signer {
                voting_public_key, ..
            } => voting_public_key,
        }
    }
}

pub fn load_pem_certificate<P: AsRef<Path>>(pem_path: P) -> Result<Certificate, Error> {
    let mut buf = Vec::new();
    File::open(&pem_path)
        .map_err(Error::InvalidWeb3SignerRootCertificateFile)?
        .read_to_end(&mut buf)
        .map_err(Error::InvalidWeb3SignerRootCertificateFile)?;
    Certificate::from_pem(&buf).map_err(Error::InvalidWeb3SignerRootCertificate)
}

fn build_web3_signer_url(base_url: &str, voting_public_key: &PublicKey) -> Result<Url, ParseError> {
    Url::parse(base_url)?.join(&format!(
        "api/v1/eth2/sign/{}",
        voting_public_key.to_string()
    ))
}

/// Try to unlock `keystore` at `keystore_path` by prompting the user via `stdin`.
fn unlock_keystore_via_stdin_password(
    keystore: &Keystore,
    keystore_path: &Path,
) -> Result<(ZeroizeString, Keypair), Error> {
    eprintln!();
    eprintln!(
        "The {} file does not contain either of the following fields for {:?}:",
        CONFIG_FILENAME, keystore_path
    );
    eprintln!();
    eprintln!(" - voting_keystore_password");
    eprintln!(" - voting_keystore_password_path");
    eprintln!();
    eprintln!(
        "You may exit and update {} or enter a password. \
                            If you choose to enter a password now then this prompt \
                            will be raised next time the validator is started.",
        CONFIG_FILENAME
    );
    eprintln!();
    eprintln!("Enter password (or press Ctrl+c to exit):");

    loop {
        let password =
            read_password_from_user(USE_STDIN).map_err(Error::UnableToReadPasswordFromUser)?;

        eprintln!();

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
    /// A list of validator definitions which can be stored on-disk.
    definitions: ValidatorDefinitions,
    /// The directory that the `self.definitions` will be saved into.
    validators_dir: PathBuf,
    /// The canonical set of validators.
    validators: HashMap<PublicKeyBytes, InitializedValidator>,
    /// For logging via `slog`.
    log: Logger,
}

impl InitializedValidators {
    /// Instantiates `Self`, initializing all validators in `definitions`.
    pub async fn from_definitions(
        definitions: ValidatorDefinitions,
        validators_dir: PathBuf,
        log: Logger,
    ) -> Result<Self, Error> {
        let mut this = Self {
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

    /// Iterate through all voting public keys in `self` that should be used when querying for duties.
    pub fn iter_voting_pubkeys(&self) -> impl Iterator<Item = &PublicKeyBytes> {
        self.validators.iter().map(|(pubkey, _)| pubkey)
    }

    /// Returns the voting `Keypair` for a given voting `PublicKey`, if all are true:
    ///
    ///  - The validator is known to `self`.
    ///  - The validator is enabled.
    pub fn signing_method(&self, voting_public_key: &PublicKeyBytes) -> Option<Arc<SigningMethod>> {
        self.validators
            .get(voting_public_key)
            .map(|v| v.signing_method.clone())
    }

    /// Add a validator definition to `self`, overwriting the on-disk representation of `self`.
    pub async fn add_definition(&mut self, def: ValidatorDefinition) -> Result<(), Error> {
        if self
            .definitions
            .as_slice()
            .iter()
            .any(|existing| existing.voting_public_key == def.voting_public_key)
        {
            return Err(Error::DuplicatePublicKey);
        }

        self.definitions.push(def);

        self.update_validators().await?;

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Returns a slice of all defined validators (regardless of their enabled state).
    pub fn validator_definitions(&self) -> &[ValidatorDefinition] {
        self.definitions.as_slice()
    }

    /// Indicates if the `voting_public_key` exists in self and if it is enabled.
    pub fn is_enabled(&self, voting_public_key: &PublicKey) -> Option<bool> {
        self.definitions
            .as_slice()
            .iter()
            .find(|def| def.voting_public_key == *voting_public_key)
            .map(|def| def.enabled)
    }

    /// Returns the `graffiti` for a given public key specified in the `ValidatorDefinitions`.
    pub fn graffiti(&self, public_key: &PublicKeyBytes) -> Option<Graffiti> {
        self.validators.get(public_key).and_then(|v| v.graffiti)
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

    /// Tries to decrypt the key cache.
    ///
    /// Returns `Ok(true)` if decryption was successful, `Ok(false)` if it couldn't get decrypted
    /// and an error if a needed password couldn't get extracted.
    ///
    async fn decrypt_key_cache(
        &self,
        mut cache: KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
    ) -> Result<KeyCache, Error> {
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
                // Remote signer validators don't interact with the key cache.
                SigningDefinition::Web3Signer { .. } => (),
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
                return Ok(KeyCache::new());
            }
        }

        //collect passwords
        let mut passwords = Vec::new();
        let mut public_keys = Vec::new();
        for uuid in cache.uuids() {
            let def = definitions_map.get(uuid).expect("Existence checked before");
            match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_password_path,
                    voting_keystore_password,
                    voting_keystore_path,
                } => {
                    let pw = if let Some(p) = voting_keystore_password {
                        p.as_ref().to_vec().into()
                    } else if let Some(path) = voting_keystore_password_path {
                        read_password(path).map_err(Error::UnableToReadVotingKeystorePassword)?
                    } else {
                        let keystore = open_keystore(voting_keystore_path)?;
                        unlock_keystore_via_stdin_password(&keystore, voting_keystore_path)?
                            .0
                            .as_ref()
                            .to_vec()
                            .into()
                    };
                    passwords.push(pw);
                    public_keys.push(def.voting_public_key.clone());
                }
                // Remote signer validators don't interact with the key cache.
                SigningDefinition::Web3Signer { .. } => (),
            };
        }

        //decrypt
        tokio::task::spawn_blocking(move || match cache.decrypt(passwords, public_keys) {
            Ok(_) | Err(key_cache::Error::AlreadyDecrypted) => cache,
            _ => KeyCache::new(),
        })
        .await
        .map_err(Error::TokioJoin)
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
        //use key cache if available
        let mut key_stores = HashMap::new();

        // Create a lock file for the cache
        let key_cache_path = KeyCache::cache_file_path(&self.validators_dir);
        let cache_lockfile_path =
            get_lockfile_path(&key_cache_path).ok_or(Error::BadKeyCachePath(key_cache_path))?;
        let _cache_lockfile = Lockfile::new(cache_lockfile_path)?;

        let cache =
            KeyCache::open_or_create(&self.validators_dir).map_err(Error::UnableToOpenKeyCache)?;
        let mut key_cache = self.decrypt_key_cache(cache, &mut key_stores).await?;

        let mut disabled_uuids = HashSet::new();
        for def in self.definitions.as_slice() {
            if def.enabled {
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        let pubkey_bytes = def.voting_public_key.compress();

                        if self.validators.contains_key(&pubkey_bytes) {
                            continue;
                        }

                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.remove(key_store.uuid());
                        }

                        match InitializedValidator::from_definition(
                            def.clone(),
                            &mut key_cache,
                            &mut key_stores,
                        )
                        .await
                        {
                            Ok(init) => {
                                let existing_lockfile_path = init
                                    .keystore_lockfile()
                                    .as_ref()
                                    .filter(|l| l.file_existed())
                                    .map(|l| l.path().to_owned());

                                self.validators
                                    .insert(init.voting_public_key().compress(), init);
                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "signing_method" => "local_keystore",
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key),
                                );

                                if let Some(lockfile_path) = existing_lockfile_path {
                                    warn!(
                                        self.log,
                                        "Ignored stale lockfile";
                                        "path" => lockfile_path.display(),
                                        "cause" => "Ungraceful shutdown (harmless) OR \
                                                    non-Lighthouse client using this keystore \
                                                    (risky)"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "signing_method" => "local_keystore",
                                    "validator" => format!("{:?}", def.voting_public_key)
                                );

                                // Exit on an invalid validator.
                                return Err(e);
                            }
                        }
                    }
                    SigningDefinition::Web3Signer { .. } => {
                        match InitializedValidator::from_definition(
                            def.clone(),
                            &mut key_cache,
                            &mut key_stores,
                        )
                        .await
                        {
                            Ok(init) => {
                                self.validators
                                    .insert(init.voting_public_key().compress(), init);

                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "signing_method" => "remote_signer",
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key),
                                );
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "signing_method" => "remote_signer",
                                    "validator" => format!("{:?}", def.voting_public_key)
                                );

                                // Exit on an invalid validator.
                                return Err(e);
                            }
                        }
                    }
                }
            } else {
                self.validators.remove(&def.voting_public_key.compress());
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.insert(*key_store.uuid());
                        }
                    }
                    // Remote signers do not interact with the key cache.
                    SigningDefinition::Web3Signer { .. } => (),
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
            tokio::task::spawn_blocking(move || {
                match key_cache.save(validators_dir) {
                    Err(e) => warn!(
                        log,
                        "Error during saving of key_cache";
                        "err" => format!("{:?}", e)
                    ),
                    Ok(true) => info!(log, "Modified key_cache saved successfully"),
                    _ => {}
                };
            })
            .await
            .map_err(Error::TokioJoin)?;
        } else {
            debug!(log, "Key cache not modified");
        }

        // Update the enabled and total validator counts
        set_gauge(
            &crate::http_metrics::metrics::ENABLED_VALIDATORS_COUNT,
            self.num_enabled() as i64,
        );
        set_gauge(
            &crate::http_metrics::metrics::TOTAL_VALIDATORS_COUNT,
            self.num_total() as i64,
        );
        Ok(())
    }

    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<u64> {
        self.validators.get(pubkey).and_then(|val| val.index)
    }

    pub fn set_index(&mut self, pubkey: &PublicKeyBytes, index: u64) {
        if let Some(val) = self.validators.get_mut(pubkey) {
            val.index = Some(index);
        }
    }
}
