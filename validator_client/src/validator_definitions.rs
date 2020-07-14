use account_utils::default_keystore_password_path;
use eth2_keystore::Keystore;
use serde_derive::{Deserialize, Serialize};
use serde_yaml;
use slog::{error, Logger};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use validator_dir::VOTING_KEYSTORE_FILE;

const CONFIG_FILENAME: &str = "validator_definitions.yml";

#[derive(Debug)]
pub enum Error {
    UnableToOpenFile(io::Error),
    UnableToParseFile(serde_yaml::Error),
    UnableToSearchForKeystores(io::Error),
    UnableToEncodeFile(serde_yaml::Error),
    UnableToWriteFile(io::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorDefinition {
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_password_path: PathBuf,
    },
}

#[derive(Default, Serialize, Deserialize)]
pub struct ValidatorDefinitions(Vec<ValidatorDefinition>);

impl ValidatorDefinitions {
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        if !config_path.exists() {
            let this = Self::default();
            this.save(&validators_dir)?;
        }
        Self::open(validators_dir)
    }

    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        // TODO: OpenOptions
        let file = File::open(config_path).map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

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
            HashSet::from_iter(self.0.iter().filter_map(|def| match def {
                ValidatorDefinition::LocalKeystore {
                    voting_keystore_path,
                    ..
                } => Some(voting_keystore_path),
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

                let voting_keystore_password_path = match keystore_result {
                    Ok(keystore) => {
                        default_keystore_password_path(&keystore, secrets_dir.as_ref().clone())
                    }
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

                Some(ValidatorDefinition::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_password_path,
                })
            })
            .collect::<Vec<_>>();

        let new_defs_count = new_defs.len();

        self.0.append(&mut new_defs);

        Ok(new_defs_count)
    }

    /*
    pub fn auto_populate<P: AsRef<Path>>(
        validators_dir: P,
        secrets_dir: P,
        log: &Logger,
    ) -> Result<Self, Error> {
        let mut keystores = vec![];
        recursively_find_voting_keystores(validators_dir, &mut keystores)
            .map_err(Error::UnableToSearchForKeystores)?;

        let keystores_and_passwords = keystores.into_iter().filter_map(|voting_keystore_path| {
            let keystore_result = OpenOptions::new()
                .read(true)
                .create(false)
                .open(&voting_keystore_path)
                .map_err(|e| format!("{:?}", e))
                .and_then(|file| Keystore::from_json_reader(file).map_err(|e| format!("{:?}", e)));

            match keystore_result {
                Ok(keystore) => Some((
                    voting_keystore_path,
                    default_keystore_password_path(&keystore, secrets_dir.as_ref().clone()),
                )),
                Err(e) => {
                    error!(
                        log,
                        "Unable to read validator keystore";
                        "error" => e,
                        "keystore" => format!("{:?}", voting_keystore_path)
                    );
                    None
                }
            }
        });

        let definitions = keystores_and_passwords
            .into_iter()
            .map(|(voting_keystore_path, voting_keystore_password_path)| {
                ValidatorDefinition::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_password_path,
                }
            })
            .collect();

        Ok(Self(definitions))
    }
    */

    pub fn save<P: AsRef<Path>>(&self, validators_dir: P) -> Result<(), Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let bytes = serde_yaml::to_vec(self).map_err(Error::UnableToEncodeFile)?;
        fs::write(config_path, &bytes).map_err(Error::UnableToWriteFile)
    }

    pub fn as_slice(&self) -> &[ValidatorDefinition] {
        self.0.as_slice()
    }
}

pub fn recursively_find_voting_keystores<P: AsRef<Path>>(
    dir: P,
    matches: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
    fs::read_dir(dir)?.try_for_each(|dir_entry| {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if file_type.is_dir() {
            recursively_find_voting_keystores(dir_entry.path(), matches)?
        } else if file_type.is_file() {
            if dir_entry
                .file_name()
                .to_str()
                .map_or(false, |filename| filename == VOTING_KEYSTORE_FILE)
            {
                matches.push(dir_entry.path())
            }
        }
        Ok(())
    })
}
