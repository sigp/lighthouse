//! Provides a file format for defining validators that should be initialized by this validator.
//!
//! Serves as the source-of-truth of which validators this validator client should attempt (or not
//! attempt) to load //! into the `crate::intialized_validators::InitializedValidators` struct.

use account_utils::{create_with_600_perms, default_keystore_password_path, ZeroizeString};
use eth2_keystore::Keystore;
use serde_derive::{Deserialize, Serialize};
use slog::{error, Logger};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use types::PublicKey;
use validator_dir::VOTING_KEYSTORE_FILE;

/// The file name for the serialized `ValidatorDefinitions` struct.
pub const CONFIG_FILENAME: &str = "validator_definitions.yml";

#[derive(Debug)]
pub enum Error {
    /// The config file could not be opened.
    UnableToOpenFile(io::Error),
    /// The config file could not be parsed as YAML.
    UnableToParseFile(serde_yaml::Error),
    /// There was an error whilst performing the recursive keystore search function.
    UnableToSearchForKeystores(io::Error),
    /// The config file could not be serialized as YAML.
    UnableToEncodeFile(serde_yaml::Error),
    /// The config file could not be written to the filesystem.
    UnableToWriteFile(io::Error),
}

/// Defines how the validator client should attempt to sign messages for this validator.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SigningDefinition {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    #[serde(rename = "local_keystore")]
    LocalKeystore {
        voting_keystore_path: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_password_path: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_password: Option<ZeroizeString>,
    },
}

/// A validator that may be initialized by this validator client.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorDefinition {
    pub enabled: bool,
    pub voting_public_key: PublicKey,
    #[serde(flatten)]
    pub signing_definition: SigningDefinition,
}

/// A list of `ValidatorDefinition` that serves as a serde-able configuration file which defines a
/// list of validators to be initialized by this validator client.
#[derive(Default, Serialize, Deserialize)]
pub struct ValidatorDefinitions(Vec<ValidatorDefinition>);

impl ValidatorDefinitions {
    /// Open an existing file or create a new, empty one if it does not exist.
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        if !config_path.exists() {
            let this = Self::default();
            this.save(&validators_dir)?;
        }
        Self::open(validators_dir)
    }

    /// Open an existing file, returning an error if the file does not exist.
    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(false)
            .open(&config_path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

    /// Perform a recursive, exhaustive search through `validators_dir` and add any keystores
    /// matching the `validator_dir::VOTING_KEYSTORE_FILE` file name.
    ///
    /// Returns the count of *new* keystores that were added to `self` during this search.
    ///
    /// ## Notes
    ///
    /// Determines the path for the password file based upon the scheme defined by
    /// `account_utils::default_keystore_password_path`.
    ///
    /// If a keystore cannot be parsed the function does not exit early. Instead it logs an `error`
    /// and continues searching.
    pub fn discover_local_keystores<P: AsRef<Path>>(
        &mut self,
        validators_dir: P,
        secrets_dir: P,
        log: &Logger,
    ) -> Result<usize, Error> {
        let mut keystore_paths = vec![];
        recursively_find_voting_keystores(validators_dir, &mut keystore_paths)
            .map_err(Error::UnableToSearchForKeystores)?;

        let known_paths: HashSet<&PathBuf> =
            HashSet::from_iter(self.0.iter().map(|def| match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    ..
                } => voting_keystore_path,
            }));

        let mut new_defs = keystore_paths
            .into_iter()
            .filter_map(|voting_keystore_path| {
                if known_paths.contains(&voting_keystore_path) {
                    return None;
                }

                let keystore_result = OpenOptions::new()
                    .read(true)
                    .create(false)
                    .open(&voting_keystore_path)
                    .map_err(|e| format!("{:?}", e))
                    .and_then(|file| {
                        Keystore::from_json_reader(file).map_err(|e| format!("{:?}", e))
                    });

                let keystore = match keystore_result {
                    Ok(keystore) => keystore,
                    Err(e) => {
                        error!(
                            log,
                            "Unable to read validator keystore";
                            "error" => e,
                            "keystore" => format!("{:?}", voting_keystore_path)
                        );
                        return None;
                    }
                };

                let voting_keystore_password_path = Some(default_keystore_password_path(
                    &keystore,
                    secrets_dir.as_ref(),
                ))
                .filter(|path| path.exists());

                let voting_public_key =
                    match serde_yaml::from_str(&format!("0x{}", keystore.pubkey())) {
                        Ok(pubkey) => pubkey,
                        Err(e) => {
                            error!(
                                log,
                                "Invalid keystore public key";
                                "error" => format!("{:?}", e),
                                "keystore" => format!("{:?}", voting_keystore_path)
                            );
                            return None;
                        }
                    };

                Some(ValidatorDefinition {
                    enabled: true,
                    voting_public_key,
                    signing_definition: SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        voting_keystore_password_path,
                        voting_keystore_password: None,
                    },
                })
            })
            .collect::<Vec<_>>();

        let new_defs_count = new_defs.len();

        self.0.append(&mut new_defs);

        Ok(new_defs_count)
    }

    /// Encodes `self` as a YAML string it writes it to the `CONFIG_FILENAME` file in the
    /// `validators_dir` directory.
    ///
    /// Will create a new file if it does not exist or over-write any existing file.
    pub fn save<P: AsRef<Path>>(&self, validators_dir: P) -> Result<(), Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let bytes = serde_yaml::to_vec(self).map_err(Error::UnableToEncodeFile)?;

        if config_path.exists() {
            fs::write(config_path, &bytes).map_err(Error::UnableToWriteFile)
        } else {
            create_with_600_perms(&config_path, &bytes).map_err(Error::UnableToWriteFile)
        }
    }

    /// Returns a slice of all `ValidatorDefinition` in `self`.
    pub fn as_slice(&self) -> &[ValidatorDefinition] {
        self.0.as_slice()
    }

    /// Returns a mutable slice of all `ValidatorDefinition` in `self`.
    pub fn as_mut_slice(&mut self) -> &mut [ValidatorDefinition] {
        self.0.as_mut_slice()
    }
}

/// Perform an exhaustive tree search of `dir`, adding any discovered voting keystore paths to
/// `matches`.
///
/// ## Errors
///
/// Returns with an error immediately if any filesystem error is raised.
pub fn recursively_find_voting_keystores<P: AsRef<Path>>(
    dir: P,
    matches: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
    fs::read_dir(dir)?.try_for_each(|dir_entry| {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if file_type.is_dir() {
            recursively_find_voting_keystores(dir_entry.path(), matches)?
        } else if file_type.is_file()
            && dir_entry
                .file_name()
                .to_str()
                .map_or(false, |filename| filename == VOTING_KEYSTORE_FILE)
        {
            matches.push(dir_entry.path())
        }
        Ok(())
    })
}
