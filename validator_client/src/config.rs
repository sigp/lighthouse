use bincode;
use bls::Keypair;
use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use slog::{error, info, o, warn, Drain};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;
use types::{
    test_utils::{generate_deterministic_keypair, load_keypairs_from_yaml},
    EthSpec, MainnetEthSpec,
};

pub const DEFAULT_SERVER: &str = "localhost";
pub const DEFAULT_SERVER_GRPC_PORT: &str = "5051";
pub const DEFAULT_SERVER_HTTP_PORT: &str = "5052";

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
            data_dir: PathBuf::from(".lighthouse-validator"),
            key_source: <_>::default(),
            log_file: PathBuf::from(""),
            server: DEFAULT_SERVER.into(),
            server_grpc_port: DEFAULT_SERVER_GRPC_PORT
                .parse::<u16>()
                .expect("gRPC port constant should be valid"),
            server_http_port: DEFAULT_SERVER_GRPC_PORT
                .parse::<u16>()
                .expect("HTTP port constant should be valid"),
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
        log: &mut slog::Logger,
    ) -> Result<(), &'static str> {
        if let Some(datadir) = args.value_of("datadir") {
            self.data_dir = PathBuf::from(datadir);
        };

        if let Some(log_file) = args.value_of("logfile") {
            self.log_file = PathBuf::from(log_file);
            self.update_logger(log)?;
        };

        if let Some(srv) = args.value_of("server") {
            self.server = srv.to_string();
        };

        Ok(())
    }

    // Update the logger to output in JSON to specified file
    fn update_logger(&mut self, log: &mut slog::Logger) -> Result<(), &'static str> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.log_file);

        if file.is_err() {
            return Err("Cannot open log file");
        }
        let file = file.unwrap();

        if let Some(file) = self.log_file.to_str() {
            info!(
                *log,
                "Log file specified, output will now be written to {} in json.", file
            );
        } else {
            info!(
                *log,
                "Log file specified output will now be written in json"
            );
        }

        let drain = Mutex::new(slog_json::Json::default(file)).fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        *log = slog::Logger::root(drain, o!());

        Ok(())
    }

    /// Reads a single keypair from the given `path`.
    ///
    /// `path` should be the path to a directory containing a private key. The file name of `path`
    /// must align with the public key loaded from it, otherwise an error is returned.
    ///
    /// An error will be returned if `path` is a file (not a directory).
    fn read_keypair_file(&self, path: PathBuf) -> Result<Keypair, String> {
        if !path.is_dir() {
            return Err("Is not a directory".into());
        }

        let key_filename: PathBuf = path.join(DEFAULT_PRIVATE_KEY_FILENAME);

        if !key_filename.is_file() {
            return Err(format!(
                "Private key is not a file: {:?}",
                key_filename.to_str()
            ));
        }

        let mut key_file = File::open(key_filename.clone())
            .map_err(|e| format!("Unable to open private key file: {}", e))?;

        let key: Keypair = bincode::deserialize_from(&mut key_file)
            .map_err(|e| format!("Unable to deserialize private key: {:?}", e))?;

        let ki = key.identifier();
        if ki
            != path
                .file_name()
                .ok_or_else(|| "Invalid path".to_string())?
                .to_string_lossy()
        {
            Err(format!(
                "The validator key ({:?}) did not match the directory filename {:?}.",
                ki,
                path.to_str()
            ))
        } else {
            Ok(key)
        }
    }

    pub fn fetch_keys_from_disk(&self, log: &slog::Logger) -> Result<Vec<Keypair>, String> {
        Ok(
            fs::read_dir(&self.full_data_dir().expect("Data dir must exist"))
                .map_err(|e| format!("Failed to read datadir: {:?}", e))?
                .filter_map(|validator_dir| {
                    let path = validator_dir.ok()?.path();

                    if path.is_dir() {
                        match self.read_keypair_file(path.clone()) {
                            Ok(keypair) => Some(keypair),
                            Err(e) => {
                                error!(
                                    log,
                                    "Failed to parse a validator keypair";
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
                .collect(),
        )
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
