use serde_derive::{Deserialize, Serialize};
use serde_yaml;
use std::fs::{self, File};
use std::io;
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

#[derive(Serialize, Deserialize)]
pub enum ValidatorType {
    LocalKeystore { voting_keystore_path: PathBuf },
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorDefinitions(Vec<ValidatorType>);

impl ValidatorDefinitions {
    pub fn open_or_auto_populate<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        if !config_path.exists() {
            let this = ValidatorDefinitions::auto_populate(&validators_dir)?;
            this.save(&validators_dir)?;
        }
        Self::open(validators_dir)
    }

    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let file = File::open(config_path).map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

    pub fn auto_populate<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let mut keystores = vec![];
        recursively_find_voting_keystores(validators_dir, &mut keystores)
            .map_err(Error::UnableToSearchForKeystores)?;

        let definitions = keystores
            .into_iter()
            .map(|voting_keystore_path| ValidatorType::LocalKeystore {
                voting_keystore_path,
            })
            .collect();

        Ok(Self(definitions))
    }

    pub fn save<P: AsRef<Path>>(&self, validators_dir: P) -> Result<(), Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let bytes = serde_yaml::to_vec(self).map_err(Error::UnableToEncodeFile)?;
        fs::write(config_path, &bytes).map_err(Error::UnableToWriteFile)
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
