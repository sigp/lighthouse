use bls::Keypair;
use clap::ArgMatches;
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use types::ChainSpec;
use bincode;

/// Stores the core configuration for this validator instance.
#[derive(Clone)]
pub struct ValidatorClientConfig {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The directory where the individual validator configuration directories are stored.
    pub validator_dir: PathBuf,
    /// The server at which the Beacon Node can be contacted
    pub server: String,
    /// The chain specification that we are connecting to
    pub spec: ChainSpec,
}

const DEFAULT_VALIDATOR_DATADIR: &str = ".lighthouse-validator";
const DEFAULT_VALIDATORS_SUBDIR: &str = "validators";
const DEFAULT_PRIVATE_KEY_FILENAME: &str = "private.key";

impl ValidatorClientConfig {
    /// Build a new configuration from defaults, which are overrided by arguments provided.
    pub fn build_config(arguments: &ArgMatches) -> Result<Self, Error> {
        // Use the specified datadir, or default in the home directory
        let data_dir: PathBuf = match arguments.value_of("datadir") {
            Some(path) => PathBuf::from(path.to_string()),
            None => {
                let home = dirs::home_dir().ok_or_else(|| Error::new(
                    ErrorKind::NotFound,
                    "Unable to determine home directory.",
                ))?;
                home.join(DEFAULT_VALIDATOR_DATADIR)
            }
        };
        fs::create_dir_all(&data_dir)?;

        let validator_dir = data_dir.join(DEFAULT_VALIDATORS_SUBDIR);
        fs::create_dir_all(&validator_dir)?;

        let server: String = match arguments.value_of("server") {
            Some(srv) => {
                //TODO: I don't think this parses correctly a server & port combo
                srv.parse::<u16>()
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?
                    .to_string()
            }
            None => "localhost:50051".to_string(),
        };

        // TODO: Permit loading a custom spec from file.
        let spec: ChainSpec = match arguments.value_of("spec") {
            Some(spec_str) => {
                match spec_str {
                    "foundation" => ChainSpec::foundation(),
                    "few_validators" => ChainSpec::few_validators(),
                    // Should be impossible due to clap's `possible_values(..)` function.
                    _ => unreachable!(),
                }
            }
            None => ChainSpec::foundation(),
        };

        Ok(Self {
            data_dir,
            validator_dir,
            server,
            spec,
        })
    }

    /// Try to load keys from validator_dir, returning None if none are found or an error.
    pub fn fetch_keys(&self) -> Result<Option<Vec<Keypair>>, Error> {
        let mut validator_dirs = fs::read_dir(&self.validator_dir)?.peekable();

        // There are no validator directories.
        if validator_dirs.peek().is_none() {
            return Ok(None);
        }

        let mut key_pairs: Vec<Keypair> = Vec::new();

        for validator_dir_result in validator_dirs {
            let validator_dir = validator_dir_result?;

            // Try to open the key file directly
            // TODO skip keyfiles that are not found, and log the error instead of returning it.
            let mut key_file = File::open(validator_dir.path().join(DEFAULT_PRIVATE_KEY_FILENAME))?;

            let key: Keypair = bincode::deserialize_from(&mut key_file)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            // TODO skip keyfile if it's not matched, and log the error instead of returning it.
            let validator_directory_name = validator_dir.file_name().into_string().map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "The filename cannot be parsed to a string.",
                    )
                })?;
            if key.identifier() !=  validator_directory_name {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "The validator directory ID did not match the key found inside.",
                ));
            }

            key_pairs.push(key);
        }

        Ok(Some(key_pairs))
    }

    /// Saves a keypair to a file inside the appropriate validator directory. Returns the saved path filename.
    pub fn save_key(&self, key: &Keypair) -> Result<PathBuf, Error> {
        let validator_config_path = self.validator_dir.join(key.identifier());
        let key_path = validator_config_path.join(DEFAULT_PRIVATE_KEY_FILENAME);

        fs::create_dir_all(&validator_config_path)?;

        let mut key_file = File::create(&key_path)?;

        bincode::serialize_into(&mut key_file, &key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(key_path)
    }
}
