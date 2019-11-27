use clap::ArgMatches;
use client::{ClientConfig, ClientGenesis, Eth2Config};
use eth2_config::{read_from_file, write_to_file};
use genesis::recent_genesis_time;
use lighthouse_bootstrap::Bootstrapper;
use rand::{distributions::Alphanumeric, Rng};
use slog::{crit, info, warn, Logger};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use types::{Address, Epoch, Fork};

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

type Result<T> = std::result::Result<T, String>;
type Config = (ClientConfig, Eth2Config, Logger);

/// Gets the fully-initialized global client and eth2 configuration objects.
///
/// The top-level `clap` arguments should be provied as `cli_args`.
///
/// The output of this function depends primarily upon the given `cli_args`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
pub fn get_configs(cli_args: &ArgMatches, core_log: Logger) -> Result<Config> {
    let log = core_log.clone();

    let mut builder = ConfigBuilder::new(cli_args, core_log)?;

    if cli_args.is_present("dummy-eth1") {
        builder.client_config.dummy_eth1_backend = true;
    }

    if let Some(val) = cli_args.value_of("eth1-endpoint") {
        builder.set_eth1_endpoint(val)
    }

    if let Some(val) = cli_args.value_of("deposit-contract") {
        builder.set_deposit_contract(
            val.parse::<Address>()
                .map_err(|e| format!("Unable to parse deposit-contract address: {:?}", e))?,
        )
    }

    if let Some(val) = cli_args.value_of("deposit-contract-deploy") {
        builder.set_deposit_contract_deploy_block(
            val.parse::<u64>()
                .map_err(|e| format!("Unable to parse deposit-contract-deploy: {:?}", e))?,
        )
    }

    if let Some(val) = cli_args.value_of("eth1-follow") {
        builder.set_eth1_follow(
            val.parse::<u64>()
                .map_err(|e| format!("Unable to parse follow distance: {:?}", e))?,
        )
    }

    match cli_args.subcommand() {
        ("testnet", Some(sub_cmd_args)) => {
            process_testnet_subcommand(&mut builder, sub_cmd_args, &log)?
        }
        // No sub-command assumes a resume operation.
        _ => {
            info!(
                log,
                "Resuming from existing datadir";
                "path" => format!("{:?}", builder.client_config.data_dir)
            );

            // If no primary subcommand was given, start the beacon chain from an existing
            // database.
            builder.set_genesis(ClientGenesis::Resume);

            // Whilst there is no large testnet or mainnet force the user to specify how they want
            // to start a new chain (e.g., from a genesis YAML file, another node, etc).
            if !builder.client_config.data_dir.exists() {
                return Err(
                    "No datadir found. To start a new beacon chain, see `testnet --help`. \
                     Use `--datadir` to specify a different directory"
                        .into(),
                );
            }

            // If the `testnet` command was not provided, attempt to load an existing datadir and
            // continue with an existing chain.
            builder.load_from_datadir()?;
        }
    };

    builder.build(cli_args)
}

/// Process the `testnet` CLI subcommand arguments, updating the `builder`.
fn process_testnet_subcommand(
    builder: &mut ConfigBuilder,
    cli_args: &ArgMatches,
    log: &Logger,
) -> Result<()> {
    if cli_args.is_present("random-datadir") {
        builder.set_random_datadir()?;
    }

    if cli_args.is_present("force") {
        builder.clean_datadir()?;
    }

    if let Some(propagation_percentage_string) = cli_args.value_of("random-propagation") {
        let percentage = propagation_percentage_string
            .parse::<u8>()
            .map_err(|_| format!("Unable to parse the propagation percentage"))?;
        if percentage > 100 {
            return Err(format!("Propagation percentage greater than 100"));
        }
        builder.client_config.network.propagation_percentage = Some(percentage);
    }

    let is_bootstrap = cli_args.subcommand_name() == Some("bootstrap");

    if let Some(path_string) = cli_args.value_of("eth2-config") {
        if is_bootstrap {
            return Err("Cannot supply --eth2-config when using bootstrap".to_string());
        }

        let path = path_string
            .parse::<PathBuf>()
            .map_err(|e| format!("Unable to parse eth2-config path: {:?}", e))?;
        builder.load_eth2_config(path)?;
    } else {
        builder.update_spec_from_subcommand(&cli_args)?;
    }

    if let Some(slot_time) = cli_args.value_of("slot-time") {
        if is_bootstrap {
            return Err("Cannot supply --slot-time flag whilst using bootstrap.".into());
        }

        let slot_time = slot_time
            .parse::<u64>()
            .map_err(|e| format!("Unable to parse slot-time: {:?}", e))?;

        builder.set_slot_time(slot_time);
    }

    if let Some(path_string) = cli_args.value_of("client-config") {
        let path = path_string
            .parse::<PathBuf>()
            .map_err(|e| format!("Unable to parse client config path: {:?}", e))?;
        builder.load_client_config(path)?;
    }

    info!(
        log,
        "Creating new datadir";
        "path" => format!("{:?}", builder.client_config.data_dir)
    );

    // When using the testnet command we listen on all addresses.
    builder.set_listen_addresses("0.0.0.0".into())?;
    warn!(log, "All services listening on 0.0.0.0");

    // Start matching on the second subcommand (e.g., `testnet bootstrap ...`).
    match cli_args.subcommand() {
        ("bootstrap", Some(cli_args)) => {
            let server = cli_args
                .value_of("server")
                .ok_or_else(|| "No bootstrap server specified")?;
            let port: Option<u16> = cli_args
                .value_of("libp2p-port")
                .and_then(|s| s.parse::<u16>().ok());

            builder.import_bootstrap_libp2p_address(server, port)?;
            builder.import_bootstrap_enr_address(server)?;
            builder.import_bootstrap_eth2_config(server)?;

            builder.set_genesis(ClientGenesis::RemoteNode {
                server: server.to_string(),
                port,
            })
        }
        ("recent", Some(cli_args)) => {
            let validator_count = cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator_count specified")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator_count: {:?}", e))?;

            let minutes = cli_args
                .value_of("minutes")
                .ok_or_else(|| "No recent genesis minutes supplied")?
                .parse::<u64>()
                .map_err(|e| format!("Unable to parse minutes: {:?}", e))?;

            builder.client_config.dummy_eth1_backend = true;

            builder.set_genesis(ClientGenesis::Interop {
                validator_count,
                genesis_time: recent_genesis_time(minutes),
            })
        }
        ("quick", Some(cli_args)) => {
            let validator_count = cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator_count specified")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator_count: {:?}", e))?;

            let genesis_time = cli_args
                .value_of("genesis_time")
                .ok_or_else(|| "No genesis time supplied")?
                .parse::<u64>()
                .map_err(|e| format!("Unable to parse genesis time: {:?}", e))?;

            builder.client_config.dummy_eth1_backend = true;

            builder.set_genesis(ClientGenesis::Interop {
                validator_count,
                genesis_time,
            })
        }
        ("file", Some(cli_args)) => {
            let path = cli_args
                .value_of("file")
                .ok_or_else(|| "No filename specified")?
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse filename: {:?}", e))?;

            let format = cli_args
                .value_of("format")
                .ok_or_else(|| "No file format specified")?;

            let start_method = match format {
                "ssz" => ClientGenesis::SszFile { path },
                other => return Err(format!("Unknown genesis file format: {}", other)),
            };

            builder.set_genesis(start_method)
        }
        ("prysm", Some(_)) => {
            let mut spec = &mut builder.eth2_config.spec;
            let mut client_config = &mut builder.client_config;

            spec.min_deposit_amount = 100;
            spec.max_effective_balance = 3_200_000_000;
            spec.ejection_balance = 1_600_000_000;
            spec.effective_balance_increment = 100_000_000;
            spec.min_genesis_time = 0;
            spec.genesis_fork = Fork {
                previous_version: [0; 4],
                current_version: [0, 0, 0, 2],
                epoch: Epoch::new(0),
            };

            client_config.eth1.deposit_contract_address =
                "0x802dF6aAaCe28B2EEb1656bb18dF430dDC42cc2e".to_string();
            client_config.eth1.deposit_contract_deploy_block = 1487270;
            client_config.eth1.follow_distance = 16;
            client_config.dummy_eth1_backend = false;

            builder.set_genesis(ClientGenesis::DepositContract)
        }
        (cmd, Some(_)) => {
            return Err(format!(
                "Invalid valid method specified: {}. See 'testnet --help'.",
                cmd
            ))
        }
        _ => return Err("No testnet method specified. See 'testnet --help'.".into()),
    };

    builder.write_configs_to_new_datadir()?;

    Ok(())
}

/// Allows for building a set of configurations based upon `clap` arguments.
struct ConfigBuilder {
    log: Logger,
    pub eth2_config: Eth2Config,
    pub client_config: ClientConfig,
}

impl ConfigBuilder {
    /// Create a new builder with default settings.
    pub fn new(cli_args: &ArgMatches, log: Logger) -> Result<Self> {
        // Read the `--datadir` flag.
        //
        // If it's not present, try and find the home directory (`~`) and push the default data
        // directory onto it.
        let data_dir: PathBuf = cli_args
            .value_of("datadir")
            .map(PathBuf::from)
            .or_else(|| {
                dirs::home_dir().map(|mut home| {
                    home.push(DEFAULT_DATA_DIR);
                    home
                })
            })
            .ok_or_else(|| "Unable to find a home directory for the datadir".to_string())?;

        let mut client_config = ClientConfig::default();
        client_config.data_dir = data_dir;

        Ok(Self {
            log,
            eth2_config: Eth2Config::minimal(),
            client_config,
        })
    }

    /// Clears any configuration files that would interfere with writing new configs.
    ///
    /// Moves the following files in `data_dir` into a backup directory:
    ///
    /// - Client config
    /// - Eth2 config
    /// - All database directories
    pub fn clean_datadir(&mut self) -> Result<()> {
        let backup_dir = {
            let mut s = String::from("backup_");
            s.push_str(&random_string(6));
            self.client_config.data_dir.join(s)
        };

        fs::create_dir_all(&backup_dir)
            .map_err(|e| format!("Unable to create config backup dir: {:?}", e))?;

        let move_to_backup_dir = |path: &Path| -> Result<()> {
            let file_name = path
                .file_name()
                .ok_or_else(|| "Invalid path found during datadir clean (no filename).")?;

            let mut new = path.to_path_buf();
            new.pop();
            new.push(backup_dir.clone());
            new.push(file_name);

            let _ = fs::rename(path, new);

            Ok(())
        };

        move_to_backup_dir(&self.client_config.data_dir.join(CLIENT_CONFIG_FILENAME))?;
        move_to_backup_dir(&self.client_config.data_dir.join(ETH2_CONFIG_FILENAME))?;
        move_to_backup_dir(&self.client_config.create_db_path()?)?;
        move_to_backup_dir(&self.client_config.create_freezer_db_path()?)?;

        Ok(())
    }

    pub fn set_eth1_endpoint(&mut self, endpoint: &str) {
        self.client_config.eth1.endpoint = endpoint.to_string();
    }

    pub fn set_deposit_contract(&mut self, deposit_contract: Address) {
        self.client_config.eth1.deposit_contract_address = format!("{:?}", deposit_contract);
    }

    pub fn set_deposit_contract_deploy_block(&mut self, eth1_block_number: u64) {
        self.client_config.eth1.deposit_contract_deploy_block = eth1_block_number;
    }

    pub fn set_eth1_follow(&mut self, distance: u64) {
        self.client_config.eth1.follow_distance = distance;
    }

    pub fn set_genesis(&mut self, method: ClientGenesis) {
        self.client_config.genesis = method;
    }

    /// Import the libp2p address for `server` into the list of libp2p nodes to connect with.
    ///
    /// If `port` is `Some`, it is used as the port for the `Multiaddr`. If `port` is `None`,
    /// attempts to connect to the `server` via HTTP and retrieve it's libp2p listen port.
    pub fn import_bootstrap_libp2p_address(
        &mut self,
        server: &str,
        port: Option<u16>,
    ) -> Result<()> {
        let bootstrapper = Bootstrapper::connect(server.to_string(), &self.log)?;

        if let Some(server_multiaddr) = bootstrapper.best_effort_multiaddr(port) {
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

    /// Import the enr address for `server` into the list of initial enrs (boot nodes).
    pub fn import_bootstrap_enr_address(&mut self, server: &str) -> Result<()> {
        let bootstrapper = Bootstrapper::connect(server.to_string(), &self.log)?;

        if let Ok(enr) = bootstrapper.enr() {
            info!(
                self.log,
                "Loaded bootstrapper libp2p address";
                "enr" => format!("{:?}", enr)
            );

            self.client_config.network.boot_nodes.push(enr);
        } else {
            warn!(
                self.log,
                "Unable to estimate a bootstrapper enr address, this node may not find any peers."
            );
        };

        Ok(())
    }

    /// Set the config data_dir to be an random directory.
    ///
    /// Useful for easily spinning up ephemeral testnets.
    pub fn set_random_datadir(&mut self) -> Result<()> {
        self.client_config
            .data_dir
            .push(format!("random_{}", random_string(6)));
        self.client_config.network.network_dir = self.client_config.data_dir.join("network");

        Ok(())
    }

    /// Imports an `Eth2Config` from `server`, returning an error if this fails.
    pub fn import_bootstrap_eth2_config(&mut self, server: &str) -> Result<()> {
        let bootstrapper = Bootstrapper::connect(server.to_string(), &self.log)?;

        self.update_eth2_config(bootstrapper.eth2_config()?);

        Ok(())
    }

    fn update_eth2_config(&mut self, eth2_config: Eth2Config) {
        self.eth2_config = eth2_config;
    }

    fn set_slot_time(&mut self, milliseconds_per_slot: u64) {
        self.eth2_config.spec.milliseconds_per_slot = milliseconds_per_slot;
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
        let db_exists = self
            .client_config
            .get_db_path()
            .map(|d| d.exists())
            .unwrap_or_else(|| false);

        // Do not permit creating a new config when the datadir exists.
        if db_exists {
            return Err("Database already exists. See `-f` or `-r` in `testnet --help`".into());
        }

        // Create `datadir` and any non-existing parent directories.
        fs::create_dir_all(&self.client_config.data_dir).map_err(|e| {
            crit!(self.log, "Failed to initialize data dir"; "error" => format!("{}", e));
            format!("{}", e)
        })?;

        let client_config_file = self.client_config.data_dir.join(CLIENT_CONFIG_FILENAME);
        if client_config_file.exists() {
            return Err(format!(
                "Datadir is not clean, {} exists. See `-f` in `testnet --help`.",
                CLIENT_CONFIG_FILENAME
            ));
        } else {
            // Write the onfig to a TOML file in the datadir.
            write_to_file(
                self.client_config.data_dir.join(CLIENT_CONFIG_FILENAME),
                &self.client_config,
            )
            .map_err(|e| format!("Unable to write {} file: {:?}", CLIENT_CONFIG_FILENAME, e))?;
        }

        let eth2_config_file = self.client_config.data_dir.join(ETH2_CONFIG_FILENAME);
        if eth2_config_file.exists() {
            return Err(format!(
                "Datadir is not clean, {} exists. See `-f` in `testnet --help`.",
                ETH2_CONFIG_FILENAME
            ));
        } else {
            // Write the config to a TOML file in the datadir.
            write_to_file(
                self.client_config.data_dir.join(ETH2_CONFIG_FILENAME),
                &self.eth2_config,
            )
            .map_err(|e| format!("Unable to write {} file: {:?}", ETH2_CONFIG_FILENAME, e))?;
        }

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
        if !self
            .client_config
            .get_data_dir()
            .map_or(false, |d| d.exists())
        {
            return Err(
                "No datadir found. Either create a new testnet or specify a different `--datadir`."
                    .into(),
            );
        }

        // If there is a path to a database in the config, ensure it exists.
        if !self
            .client_config
            .get_db_path()
            .map_or(false, |path| path.exists())
        {
            return Err(
                "No database found in datadir. Use 'testnet -f' to overwrite the existing \
                 datadir, or specify a different `--datadir`."
                    .into(),
            );
        }

        self.load_eth2_config(self.client_config.data_dir.join(ETH2_CONFIG_FILENAME))?;
        self.load_client_config(self.client_config.data_dir.join(CLIENT_CONFIG_FILENAME))?;

        Ok(())
    }

    /// Attempts to load the client config from `path`.
    ///
    /// Returns an error if any files are not found or are invalid.
    pub fn load_client_config(&mut self, path: PathBuf) -> Result<()> {
        self.client_config = read_from_file::<ClientConfig>(path.clone())
            .map_err(|e| format!("Unable to parse {:?} file: {:?}", path, e))?
            .ok_or_else(|| format!("{:?} file does not exist", path))?;

        Ok(())
    }

    /// Attempts to load the eth2 config from `path`.
    ///
    /// Returns an error if any files are not found or are invalid.
    pub fn load_eth2_config(&mut self, path: PathBuf) -> Result<()> {
        self.eth2_config = read_from_file::<Eth2Config>(path.clone())
            .map_err(|e| format!("Unable to parse {:?} file: {:?}", path, e))?
            .ok_or_else(|| format!("{:?} file does not exist", path))?;

        Ok(())
    }

    /// Sets all listening addresses to the given `addr`.
    pub fn set_listen_addresses(&mut self, addr: String) -> Result<()> {
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Unable to parse default listen address: {:?}", e))?;

        self.client_config.network.listen_address = addr.into();
        self.client_config.rest_api.listen_address = addr;

        Ok(())
    }

    /// Consumes self, returning the configs.
    ///
    /// The supplied `cli_args` should be the base-level `clap` cli_args (i.e., not a subcommand
    /// cli_args).
    pub fn build(mut self, cli_args: &ArgMatches) -> Result<Config> {
        self.client_config.apply_cli_args(cli_args, &mut self.log)?;

        if let Some(bump) = cli_args.value_of("port-bump") {
            let bump = bump
                .parse::<u16>()
                .map_err(|e| format!("Unable to parse port bump: {}", e))?;

            self.client_config.network.libp2p_port += bump;
            self.client_config.network.discovery_port += bump;
            self.client_config.rest_api.port += bump;
            self.client_config.websocket_server.port += bump;
        }

        if self.eth2_config.spec_constants != self.client_config.spec_constants {
            crit!(self.log, "Specification constants do not match.";
                  "client_config" => self.client_config.spec_constants.to_string(),
                  "eth2_config" => self.eth2_config.spec_constants.to_string()
            );
            return Err("Specification constant mismatch".into());
        }

        Ok((self.client_config, self.eth2_config, self.log))
    }
}

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect::<String>()
}
