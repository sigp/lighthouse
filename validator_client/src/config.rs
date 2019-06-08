use bincode;
use bls::Keypair;
use clap::ArgMatches;
use slog::{debug, error, info};
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use types::{
    ChainSpec, EthSpec, FewValidatorsEthSpec, FoundationEthSpec, LighthouseTestnetEthSpec,
};

/// Stores the core configuration for this validator instance.
#[derive(Clone)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The server at which the Beacon Node can be contacted
    pub server: String,
    /// The chain specification that we are connecting to
    pub spec: ChainSpec,
    pub slots_per_epoch: u64,
}

const DEFAULT_PRIVATE_KEY_FILENAME: &str = "private.key";

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        let data_dir = {
            let home = dirs::home_dir().expect("Unable to determine home directory.");
            home.join(".lighthouse-validator")
        };

        let server = "localhost:5051".to_string();

        let spec = FoundationEthSpec::default_spec();

        Self {
            data_dir,
            server,
            spec,
            slots_per_epoch: FoundationEthSpec::slots_per_epoch(),
        }
    }
}

impl Config {
    /// Build a new configuration from defaults, which are overrided by arguments provided.
    pub fn parse_args(args: &ArgMatches, log: &slog::Logger) -> Result<Self, Error> {
        let mut config = Config::default();

        // Use the specified datadir, or default in the home directory
        if let Some(datadir) = args.value_of("datadir") {
            config.data_dir = PathBuf::from(datadir);
            info!(log, "Using custom data dir: {:?}", &config.data_dir);
        };

        fs::create_dir_all(&config.data_dir)
            .unwrap_or_else(|_| panic!("Unable to create {:?}", &config.data_dir));

        if let Some(srv) = args.value_of("server") {
            //TODO: Validate the server value, to ensure it makes sense.
            config.server = srv.to_string();
            info!(log, "Using custom server: {:?}", &config.server);
        };

        // TODO: Permit loading a custom spec from file.
        if let Some(spec_str) = args.value_of("spec") {
            info!(log, "Using custom spec: {:?}", spec_str);
            config.spec = match spec_str {
                "foundation" => FoundationEthSpec::default_spec(),
                "few_validators" => FewValidatorsEthSpec::default_spec(),
                "lighthouse_testnet" => LighthouseTestnetEthSpec::default_spec(),
                // Should be impossible due to clap's `possible_values(..)` function.
                _ => unreachable!(),
            };
        };
        // Log configuration
        info!(log, "";
              "data_dir" => &config.data_dir.to_str(),
              "server" => &config.server);

        Ok(config)
    }

    /// Try to load keys from validator_dir, returning None if none are found or an error.
    #[allow(dead_code)]
    pub fn fetch_keys(&self, log: &slog::Logger) -> Option<Vec<Keypair>> {
        let key_pairs: Vec<Keypair> = fs::read_dir(&self.data_dir)
            .unwrap()
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
