use account_manager::validator::ValidatorDirectory;
use bincode;
use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use slog::{error, warn};
use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use std::ops::Range;
use std::path::PathBuf;
use types::{
    test_utils::{generate_deterministic_keypair, load_keypairs_from_yaml},
    EthSpec, Keypair, MainnetEthSpec,
};

#[derive(Clone)]
pub enum KeySource {
    /// Load the keypairs from disk.
    Disk,
    /// Generate the keypairs (insecure, generates predictable keys).
    TestingKeypairRange(Range<usize>),
    /// Load testing keypairs from YAML
    YamlKeypairs(PathBuf),
}

impl Default for KeySource {
    fn default() -> Self {
        KeySource::Disk
    }
}

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The source for loading keypairs
    #[serde(skip)]
    pub key_source: KeySource,
    /// The path where the logs will be outputted
    pub log_file: PathBuf,
    /// The server at which the Beacon Node can be contacted
    pub server: String,
    /// The gRPC port on the server
    pub server_grpc_port: u16,
    /// The HTTP port on the server, for the REST API.
    pub server_http_port: u16,
    /// The number of slots per epoch.
    pub slots_per_epoch: u64,
}

const DEFAULT_PRIVATE_KEY_FILENAME: &str = "private.key";

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".lighthouse/validators"),
            key_source: <_>::default(),
            log_file: PathBuf::from(""),
            server: "localhost".into(),
            server_grpc_port: 5051,
            server_http_port: 5052,
            slots_per_epoch: MainnetEthSpec::slots_per_epoch(),
        }
    }
}

impl Config {
    /// Returns the full path for the client data directory (not just the name of the directory).
    pub fn full_data_dir(&self) -> Option<PathBuf> {
        dirs::home_dir().map(|path| path.join(&self.data_dir))
    }

    /// Creates the data directory (and any non-existing parent directories).
    pub fn create_data_dir(&self) -> Option<PathBuf> {
        let path = dirs::home_dir()?.join(&self.data_dir);
        fs::create_dir_all(&path).ok()?;
        Some(path)
    }

    /// Apply the following arguments to `self`, replacing values if they are specified in `args`.
    ///
    /// Returns an error if arguments are obviously invalid. May succeed even if some values are
    /// invalid.
    pub fn apply_cli_args(
        &mut self,
        args: &ArgMatches,
        _log: &slog::Logger,
    ) -> Result<(), &'static str> {
        if let Some(datadir) = args.value_of("datadir") {
            self.data_dir = PathBuf::from(datadir);
        };

        if let Some(srv) = args.value_of("server") {
            self.server = srv.to_string();
        };

        Ok(())
    }

    /// Loads the validator keys from disk.
    ///
    /// ## Errors
    ///
    /// Returns an error if the base directory does not exist, however it does not return for any
    /// invalid directories/files. Instead, it just filters out failures and logs errors. This
    /// behaviour is intended to avoid the scenario where a single invalid file can stop all
    /// validators.
    pub fn fetch_keys_from_disk(&self, log: &slog::Logger) -> Result<Vec<Keypair>, String> {
        let base_dir = self
            .full_data_dir()
            .ok_or_else(|| format!("Base directory does not exist: {:?}", self.full_data_dir()))?;

        let keypairs = fs::read_dir(&base_dir)
            .map_err(|e| format!("Failed to read base directory: {:?}", e))?
            .filter_map(|validator_dir| {
                let path = validator_dir.ok()?.path();

                if path.is_dir() {
                    match ValidatorDirectory::load_for_signing(path.clone()) {
                        Ok(validator_directory) => validator_directory.voting_keypair,
                        Err(e) => {
                            error!(
                                log,
                                "Failed to load a validator directory";
                                "error" => e,
                                "path" => path.to_str(),
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(keypairs)
    }

    pub fn fetch_testing_keypairs(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<Keypair>, String> {
        Ok(range.map(generate_deterministic_keypair).collect())
    }

    /// Loads the keypairs according to `self.key_source`. Will return one or more keypairs, or an
    /// error.
    #[allow(dead_code)]
    pub fn fetch_keys(&self, log: &slog::Logger) -> Result<Vec<Keypair>, String> {
        let keypairs = match &self.key_source {
            KeySource::Disk => self.fetch_keys_from_disk(log)?,
            KeySource::TestingKeypairRange(range) => {
                warn!(
                    log,
                    "Using insecure interop private keys";
                    "range" => format!("{:?}", range)
                );
                self.fetch_testing_keypairs(range.clone())?
            }
            KeySource::YamlKeypairs(path) => {
                warn!(
                    log,
                    "Private keys are stored insecurely (plain text). Testing use only."
                );

                load_keypairs_from_yaml(path.to_path_buf())?
            }
        };

        // Check if it's an empty vector, and return none.
        if keypairs.is_empty() {
            Err(
                "No validator keypairs were found, unable to proceed. To generate \
                 testing keypairs, see 'testnet range --help'."
                    .into(),
            )
        } else {
            Ok(keypairs)
        }
    }

    /// Saves a keypair to a file inside the appropriate validator directory. Returns the saved path filename.
    #[allow(dead_code)]
    pub fn save_key(&self, key: &Keypair) -> Result<PathBuf, Error> {
        use std::os::unix::fs::PermissionsExt;
        let validator_config_path = self.data_dir.join(key.identifier());
        let key_path = validator_config_path.join(DEFAULT_PRIVATE_KEY_FILENAME);

        fs::create_dir_all(&validator_config_path)?;

        let mut key_file = File::create(&key_path)?;
        let mut perm = key_file.metadata()?.permissions();
        perm.set_mode((libc::S_IWUSR | libc::S_IRUSR) as u32);
        key_file.set_permissions(perm)?;

        bincode::serialize_into(&mut key_file, &key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(key_path)
    }
}
