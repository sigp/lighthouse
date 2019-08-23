use clap::ArgMatches;
use client::{Bootstrapper, ClientConfig, Eth2Config};
use eth2_config::{read_from_file, write_to_file};
use rand::{distributions::Alphanumeric, Rng};
use slog::{crit, info, Logger};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

type Result<T> = std::result::Result<T, String>;
type Config = (ClientConfig, Eth2Config);

/// Gets the fully-initialized global client and eth2 configuration objects.
pub fn get_configs(matches: &ArgMatches, log: &Logger) -> Result<Config> {
    let mut builder = ConfigBuilder::new(matches, log)?;

    match matches.subcommand() {
        ("testnet", Some(sub_matches)) => {
            if sub_matches.is_present("random-datadir") {
                builder.set_random_datadir()?;
            }

            info!(
                log,
                "Creating new datadir";
                "path" => format!("{:?}", builder.data_dir)
            );

            builder.update_spec_from_subcommand(&sub_matches)?;

            match sub_matches.subcommand() {
                // The bootstrap testnet method requires inserting a libp2p address into the
                // network config.
                ("bootstrap", Some(sub_matches)) => {
                    let server = sub_matches
                        .value_of("server")
                        .ok_or_else(|| "No bootstrap server specified".into())?;

                    let bootstrapper = Bootstrapper::from_server_string(server.to_string())?;

                    if let Some(server_multiaddr) =
                        bootstrapper.best_effort_multiaddr(sub_matches.value_of("libp2p_port"))
                    {
                        info!(
                            log,
                            "Estimated bootstrapper libp2p address";
                            "multiaddr" => format!("{:?}", server_multiaddr)
                        );

                        builder
                            .client_config
                            .network
                            .libp2p_nodes
                            .push(server_multiaddr);
                    } else {
                        warn!(
                            log,
                            "Unable to estimate a bootstrapper libp2p address, this node may not find any peers."
                        );
                    };
                }
                _ => (),
            };

            builder.write_configs_to_new_datadir()?;
        }
        _ => {
            info!(
                log,
                "Resuming from existing datadir";
                "path" => format!("{:?}", builder.data_dir)
            );

            // If the `testnet` command was not provided, attempt to load an existing datadir and
            // continue with an existing chain.
            builder.load_from_datadir()?;
        }
    };

    builder.build()
}

/// Allows for building a set of configurations based upon `clap` arguments.
struct ConfigBuilder<'a> {
    matches: &'a ArgMatches<'a>,
    log: &'a Logger,
    pub data_dir: PathBuf,
    pub eth2_config: Eth2Config,
    pub client_config: ClientConfig,
}

impl<'a> ConfigBuilder<'a> {
    /// Create a new builder with default settings.
    pub fn new(matches: &'a ArgMatches, log: &'a Logger) -> Result<Self> {
        // Read the `--datadir` flag.
        //
        // If it's not present, try and find the home directory (`~`) and push the default data
        // directory onto it.
        let data_dir: PathBuf = matches
            .value_of("datadir")
            .map(|string| PathBuf::from(string))
            .or_else(|| {
                dirs::home_dir().map(|mut home| {
                    home.push(DEFAULT_DATA_DIR);
                    home
                })
            })
            .ok_or_else(|| "Unable to find a home directory for the datadir".to_string())?;

        Ok(Self {
            matches,
            log,
            data_dir,
            eth2_config: Eth2Config::minimal(),
            client_config: ClientConfig::default(),
        })
    }

    /// Consumes self, returning the configs.
    pub fn build(mut self) -> Result<Config> {
        self.eth2_config.apply_cli_args(&self.matches)?;
        self.client_config
            .apply_cli_args(&self.matches, &mut self.log.clone())?;

        if self.eth2_config.spec_constants != self.client_config.spec_constants {
            crit!(self.log, "Specification constants do not match.";
                  "client_config" => format!("{}", self.client_config.spec_constants),
                  "eth2_config" => format!("{}", self.eth2_config.spec_constants)
            );
            return Err("Specification constant mismatch".into());
        }

        self.client_config.data_dir = self.data_dir;

        Ok((self.client_config, self.eth2_config))
    }

    /// Set the config data_dir to be an random directory.
    ///
    /// Useful for easily spinning up ephemeral testnets.
    pub fn set_random_datadir(&mut self) -> Result<()> {
        let random = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .collect::<String>();

        let mut s = DEFAULT_DATA_DIR.to_string();
        s.push_str("_random_");
        s.push_str(&random);

        self.data_dir.pop();
        self.data_dir.push(s);

        Ok(())
    }

    /// Reads the subcommand and tries to update `self.eth2_config` based up on the `--spec` flag.
    ///
    /// Returns an error if the `--spec` flag is not present.
    pub fn update_spec_from_subcommand(&mut self, sub_matches: &ArgMatches) -> Result<()> {
        // Re-initialise the `Eth2Config`.
        //
        // If a CLI parameter is set, overwrite any config file present.
        // If a parameter is not set, use either the config file present or default to minimal.
        let eth2_config = match sub_matches.value_of("spec") {
            Some("mainnet") => Eth2Config::mainnet(),
            Some("minimal") => Eth2Config::minimal(),
            Some("interop") => Eth2Config::interop(),
            _ => return Err("Unable to determine specification type.".into()),
        };

        self.client_config.spec_constants = sub_matches
            .value_of("spec")
            .expect("Guarded by prior match statement")
            .to_string();
        self.eth2_config = eth2_config;

        Ok(())
    }

    /// Writes the configs in `self` to `self.data_dir`.
    ///
    /// Returns an error if `self.data_dir` already exists.
    pub fn write_configs_to_new_datadir(&mut self) -> Result<()> {
        // Do not permit creating a new config when the datadir exists.
        if self.data_dir.exists() {
            return Err(
                "Datadir already exists, will not overwrite. Remove the directory or use --datadir."
                    .into(),
            );
        }

        // Create `datadir` and any non-existing parent directories.
        fs::create_dir_all(&self.data_dir).map_err(|e| {
            crit!(self.log, "Failed to initialize data dir"; "error" => format!("{}", e));
            format!("{}", e)
        })?;

        // Write the client config to a TOML file in the datadir.
        write_to_file(
            self.data_dir.join(CLIENT_CONFIG_FILENAME),
            &self.client_config,
        )
        .map_err(|e| format!("Unable to write {} file: {:?}", CLIENT_CONFIG_FILENAME, e))?;

        // Write the eth2 config to a TOML file in the datadir.
        write_to_file(self.data_dir.join(ETH2_CONFIG_FILENAME), &self.eth2_config)
            .map_err(|e| format!("Unable to write {} file: {:?}", ETH2_CONFIG_FILENAME, e))?;

        Ok(())
    }

    /// Attempts to load the client and eth2 configs from `self.data_dir`.
    ///
    /// Returns an error if any files are not found or are invalid.
    pub fn load_from_datadir(&mut self) -> Result<()> {
        // Check to ensure the datadir exists.
        //
        // For now we return an error. In the future we may decide to boot a default (e.g.,
        // public testnet or mainnet).
        if !self.data_dir.exists() {
            return Err(
                "No datadir found. Use the 'testnet' sub-command to select a testnet type.".into(),
            );
        }

        self.eth2_config = read_from_file::<Eth2Config>(self.data_dir.join(ETH2_CONFIG_FILENAME))
            .map_err(|e| format!("Unable to parse {} file: {:?}", ETH2_CONFIG_FILENAME, e))?
            .ok_or_else(|| format!("{} file does not exist", ETH2_CONFIG_FILENAME))?;

        self.client_config =
            read_from_file::<ClientConfig>(self.data_dir.join(CLIENT_CONFIG_FILENAME))
                .map_err(|e| format!("Unable to parse {} file: {:?}", CLIENT_CONFIG_FILENAME, e))?
                .ok_or_else(|| format!("{} file does not exist", ETH2_CONFIG_FILENAME))?;

        Ok(())
    }
}
