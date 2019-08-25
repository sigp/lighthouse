use clap::ArgMatches;
use client::{Bootstrapper, ClientConfig, Eth2Config};
use eth2_config::{read_from_file, write_to_file};
use rand::{distributions::Alphanumeric, Rng};
use slog::{crit, info, warn, Logger};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

type Result<T> = std::result::Result<T, String>;
type Config = (ClientConfig, Eth2Config);

/// Gets the fully-initialized global client and eth2 configuration objects.
pub fn get_configs(cli_args: &ArgMatches, log: &Logger) -> Result<Config> {
    let mut builder = ConfigBuilder::new(cli_args, log)?;

    match cli_args.subcommand() {
        ("testnet", Some(sub_cmd_args)) => {
            if sub_cmd_args.is_present("random-datadir") {
                builder.set_random_datadir()?;
            }

            info!(
                log,
                "Creating new datadir";
                "path" => format!("{:?}", builder.data_dir)
            );

            builder.update_spec_from_subcommand(&sub_cmd_args)?;

            match sub_cmd_args.subcommand() {
                // The bootstrap testnet method requires inserting a libp2p address into the
                // network config.
                ("bootstrap", Some(sub_cmd_args)) => {
                    builder.import_bootstrap_libp2p_address(&sub_cmd_args)?;
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

    builder.build(cli_args)
}

/// Decodes an optional string into an optional u16.
fn parse_port_option(o: Option<&str>) -> Option<u16> {
    o.and_then(|s| s.parse::<u16>().ok())
}

/// Allows for building a set of configurations based upon `clap` arguments.
struct ConfigBuilder<'a> {
    log: &'a Logger,
    pub data_dir: PathBuf,
    eth2_config: Eth2Config,
    client_config: ClientConfig,
}

impl<'a> ConfigBuilder<'a> {
    /// Create a new builder with default settings.
    pub fn new(cli_args: &'a ArgMatches, log: &'a Logger) -> Result<Self> {
        // Read the `--datadir` flag.
        //
        // If it's not present, try and find the home directory (`~`) and push the default data
        // directory onto it.
        let data_dir: PathBuf = cli_args
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
            log,
            data_dir,
            eth2_config: Eth2Config::minimal(),
            client_config: ClientConfig::default(),
        })
    }

    pub fn set_beacon_chain_start_method(&mut self, cli_args: &ArgMatches) -> Result<()> {
        //
    }

    /// Reads a `server` flag from `cli_args` and attempts to generate a libp2p `Multiaddr` that
    /// this client can use to connect to the given `server`.
    ///
    /// Also reads for a `libp2p_port` flag in `cli_args`, using that as the port for the
    /// `Multiaddr`. If `libp2p_port` is not in `cli_args`, attempts to connect to `server` via HTTP
    /// and retrieve it's libp2p listen port.
    ///
    /// Returns an error if the `server` flag is not present in `cli_args`.
    pub fn import_bootstrap_libp2p_address(&mut self, cli_args: &ArgMatches) -> Result<()> {
        let server: String = cli_args
            .value_of("server")
            .ok_or_else(|| "No bootstrap server specified")?
            .to_string();

        let bootstrapper = Bootstrapper::from_server_string(server.to_string())?;

        if let Some(server_multiaddr) =
            bootstrapper.best_effort_multiaddr(parse_port_option(cli_args.value_of("libp2p_port")))
        {
            info!(
                self.log,
                "Estimated bootstrapper libp2p address";
                "multiaddr" => format!("{:?}", server_multiaddr)
            );

            self.client_config
                .network
                .libp2p_nodes
                .push(server_multiaddr);
        } else {
            warn!(
                        self.log,
                        "Unable to estimate a bootstrapper libp2p address, this node may not find any peers."
                    );
        };

        Ok(())
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
    /// Returns an error if the `--spec` flag is not present in the given `cli_args`.
    pub fn update_spec_from_subcommand(&mut self, cli_args: &ArgMatches) -> Result<()> {
        // Re-initialise the `Eth2Config`.
        //
        // If a CLI parameter is set, overwrite any config file present.
        // If a parameter is not set, use either the config file present or default to minimal.
        let eth2_config = match cli_args.value_of("spec") {
            Some("mainnet") => Eth2Config::mainnet(),
            Some("minimal") => Eth2Config::minimal(),
            Some("interop") => Eth2Config::interop(),
            _ => return Err("Unable to determine specification type.".into()),
        };

        self.client_config.spec_constants = cli_args
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

    /// Consumes self, returning the configs.
    ///
    /// The supplied `cli_args` should be the base-level `clap` cli_args (i.e., not a subcommand
    /// cli_args).
    pub fn build(mut self, cli_args: &ArgMatches) -> Result<Config> {
        self.eth2_config.apply_cli_args(cli_args)?;
        self.client_config
            .apply_cli_args(cli_args, &mut self.log.clone())?;

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
}
