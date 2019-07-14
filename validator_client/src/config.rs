use bincode;
use bls::Keypair;
use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use slog::{debug, error, info, o, Drain};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::Mutex;
use types::{EthSpec, MainnetEthSpec};

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The path where the logs will be outputted
    pub log_file: PathBuf,
    /// The server at which the Beacon Node can be contacted
    pub server: String,
    /// The number of slots per epoch.
    pub slots_per_epoch: u64,
}

const DEFAULT_PRIVATE_KEY_FILENAME: &str = "private.key";

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".lighthouse-validator"),
            log_file: PathBuf::from(""),
            server: "localhost:5051".to_string(),
            slots_per_epoch: MainnetEthSpec::slots_per_epoch(),
        }
    }
}

impl Config {
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

    /// Try to load keys from validator_dir, returning None if none are found or an error.
    #[allow(dead_code)]
    pub fn fetch_keys(&self, log: &slog::Logger) -> Option<Vec<Keypair>> {
        let key_pairs: Vec<Keypair> = fs::read_dir(&self.data_dir)
            .ok()?
            .filter_map(|validator_dir| {
                let validator_dir = validator_dir.ok()?;

                if !(validator_dir.file_type().ok()?.is_dir()) {
                    // Skip non-directories (i.e. no files/symlinks)
                    return None;
                }

                let key_filename = validator_dir.path().join(DEFAULT_PRIVATE_KEY_FILENAME);

                if !(key_filename.is_file()) {
                    info!(
                        log,
                        "Private key is not a file: {:?}",
                        key_filename.to_str()
                    );
                    return None;
                }

                debug!(
                    log,
                    "Deserializing private key from file: {:?}",
                    key_filename.to_str()
                );

                let mut key_file = File::open(key_filename.clone()).ok()?;

                let key: Keypair = if let Ok(key_ok) = bincode::deserialize_from(&mut key_file) {
                    key_ok
                } else {
                    error!(
                        log,
                        "Unable to deserialize the private key file: {:?}", key_filename
                    );
                    return None;
                };

                let ki = key.identifier();
                if ki != validator_dir.file_name().into_string().ok()? {
                    error!(
                        log,
                        "The validator key ({:?}) did not match the directory filename {:?}.",
                        ki,
                        &validator_dir.path().to_string_lossy()
                    );
                    return None;
                }
                Some(key)
            })
            .collect();

        // Check if it's an empty vector, and return none.
        if key_pairs.is_empty() {
            None
        } else {
            Some(key_pairs)
        }
    }

    /// Saves a keypair to a file inside the appropriate validator directory. Returns the saved path filename.
    #[allow(dead_code)]
    pub fn save_key(&self, key: &Keypair) -> Result<PathBuf, Error> {
        let validator_config_path = self.data_dir.join(key.identifier());
        let key_path = validator_config_path.join(DEFAULT_PRIVATE_KEY_FILENAME);

        fs::create_dir_all(&validator_config_path)?;

        let mut key_file = File::create(&key_path)?;

        bincode::serialize_into(&mut key_file, &key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(key_path)
    }
}
