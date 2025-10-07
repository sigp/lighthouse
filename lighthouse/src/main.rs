mod cli;
mod metrics;

use account_utils::STDIN_INPUTS_FLAG;
use beacon_node::ProductionBeaconNode;
use clap::FromArgMatches;
use clap::Subcommand;
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::{
    FLAG_HEADER, flags::DISABLE_MALLOC_TUNING_FLAG, get_color_style, get_eth2_network_config,
};
use cli::LighthouseSubcommands;
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_VALIDATOR_DIR, parse_path_or_default};
use environment::tracing_common;
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_network_config::{DEFAULT_HARDCODED_NETWORK, Eth2NetworkConfig, HARDCODED_NET_NAMES};
use ethereum_hashing::have_sha_extensions;
use futures::TryFutureExt;
use lighthouse_version::VERSION;
use logging::{MetricsLayer, build_workspace_filter, crit};
use malloc_utils::configure_memory_allocator;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use std::backtrace::Backtrace;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::exit;
use std::sync::LazyLock;
use task_executor::ShutdownReason;
use tracing::{Level, info};
use tracing_subscriber::{Layer, filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

pub static SHORT_VERSION: LazyLock<String> = LazyLock::new(|| VERSION.replace("Lighthouse/", ""));
pub static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}\n\
         BLS library: {}\n\
         BLS hardware acceleration: {}\n\
         SHA256 hardware acceleration: {}\n\
         Allocator: {}\n\
         Profile: {}\n\
         Specs: mainnet (true), minimal ({}), gnosis ({})",
        SHORT_VERSION.as_str(),
        bls_library_name(),
        bls_hardware_acceleration(),
        have_sha_extensions(),
        allocator_name(),
        build_profile_name(),
        cfg!(feature = "spec-minimal"),
        cfg!(feature = "gnosis"),
    )
});

fn bls_library_name() -> &'static str {
    if cfg!(feature = "portable") {
        "blst-portable"
    } else if cfg!(feature = "modern") {
        "blst-modern"
    } else {
        "blst"
    }
}

#[inline(always)]
fn bls_hardware_acceleration() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::is_x86_feature_detected!("adx");

    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("neon");

    #[cfg(target_arch = "riscv64")]
    return false;
}

fn allocator_name() -> String {
    malloc_utils::allocator_name()
}

fn build_profile_name() -> String {
    // Nice hack from https://stackoverflow.com/questions/73595435/how-to-get-profile-from-cargo-toml-in-build-rs-or-at-runtime
    // The profile name is always the 3rd last part of the path (with 1 based indexing).
    // e.g. /code/core/target/cli/build/my-build-info-9f91ba6f99d7a061/out
    std::env!("OUT_DIR")
        .split(std::path::MAIN_SEPARATOR)
        .nth_back(3)
        .unwrap_or("unknown")
        .to_string()
}

fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var("RUST_BACKTRACE").is_err() {
        // `set_var` is marked unsafe because it is unsafe to use if there are multiple threads
        // reading or writing from the environment. We are at the very beginning of execution and
        // have not spun up any threads or the tokio runtime, so it is safe to use.
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    // Parse the CLI parameters.
    let cli = Command::new("Lighthouse")
        .version(SHORT_VERSION.as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .styles(get_color_style())
        .next_line_help(true)
        .term_width(80)
        .disable_help_flag(true)
        .about(
            "Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon \
             node, a validator client and utilities for managing validator accounts.",
        )
        .long_version(LONG_VERSION.as_str())
        .display_order(0)
        .arg(
            Arg::new(STDIN_INPUTS_FLAG)
                .long(STDIN_INPUTS_FLAG)
                .action(ArgAction::SetTrue)
                .help("If present, read all user inputs from stdin instead of tty.")
                .help_heading(FLAG_HEADER)
                .hide(cfg!(windows))
                .global(true)
                .display_order(0),
        )
        .arg(
            Arg::new("logfile-dir")
                .long("logfile-dir")
                .value_name("DIR")
                .help(
                    "Directory path where the log file will be stored")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-debug-level")
                .long("logfile-debug-level")
                .value_name("LEVEL")
                .help("The verbosity level used when emitting logs to the log file.")
                .action(ArgAction::Set)
                .value_parser(["info", "debug", "trace", "warn", "error"])
                .default_value("debug")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-format")
                .long("logfile-format")
                .value_name("FORMAT")
                .help("Specifies the log format used when emitting logs to the logfile.")
                .value_parser(["DEFAULT", "JSON"])
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-max-size")
                .long("logfile-max-size")
                .value_name("SIZE")
                .help(
                    "The maximum size (in MB) each log file can grow to before rotating. If set \
                    to 0, background file logging is disabled.")
                .action(ArgAction::Set)
                .default_value("200")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-max-number")
                .long("logfile-max-number")
                .value_name("COUNT")
                .help(
                    "The maximum number of log files that will be stored. If set to 0, \
                    background file logging is disabled.")
                .action(ArgAction::Set)
                .default_value("10")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-compress")
                .long("logfile-compress")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "If present, compress old log files. This can help reduce the space needed \
                    to store old logs.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-no-restricted-perms")
                .long("logfile-no-restricted-perms")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "If present, log files will be generated as world-readable meaning they can be read by \
                    any user on the machine. Note that logs can often contain sensitive information \
                    about your validator and so this flag should be used with caution. For Windows users, \
                    the log file permissions will be inherited from the parent folder.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("log-format")
                .long("log-format")
                .value_name("FORMAT")
                .help("Specifies the log format used when emitting logs to the terminal.")
                .value_parser(["JSON"])
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("log-color")
                .long("log-color")
                .alias("log-color")
                .help("Enables/Disables colors for logs in terminal. \
                    Set it to false to disable colors.")
                .num_args(0..=1)
                .default_missing_value("true")
                .default_value("true")
                .value_parser(clap::value_parser!(bool))
                .help_heading(FLAG_HEADER)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-color")
                .long("logfile-color")
                .alias("logfile-colour")
                .help("Enables colors in logfile.")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("log-extra-info")
            .long("log-extra-info")
            .action(ArgAction::SetTrue)
            .help_heading(FLAG_HEADER)
            .help("If present, show module,file,line in logs")
            .global(true)
            .display_order(0)
        )
        .arg(
            Arg::new("disable-log-timestamp")
            .long("disable-log-timestamp")
            .action(ArgAction::SetTrue)
            .help_heading(FLAG_HEADER)
            .help("If present, do not include timestamps in logging output.")
            .global(true)
            .display_order(0)
        )
        .arg(
            Arg::new("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("Specifies the verbosity level used when emitting logs to the terminal.")
                .action(ArgAction::Set)
                .value_parser(["info", "debug", "trace", "warn", "error"])
                .global(true)
                .default_value("info")
                .display_order(0)
        )
        .arg(
            Arg::new("telemetry-collector-url")
                .long("telemetry-collector-url")
                .value_name("URL")
                .help(
                    "URL of the OpenTelemetry collector to export tracing spans \
                    (e.g., http://localhost:4317). If not set, tracing export is disabled.",
                )
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("telemetry-service-name")
                .long("telemetry-service-name")
                .value_name("NAME")
                .help(
                    "Override the OpenTelemetry service name. \
                    Defaults to 'lighthouse-bn' for beacon node, 'lighthouse-vc' for validator \
                    client, or 'lighthouse' for other subcommands."
                )
                .requires("telemetry-collector-url")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("datadir")
                .long("datadir")
                .short('d')
                .value_name("DIR")
                .global(true)
                .help(
                    "Used to specify a custom root data directory for lighthouse keys and databases. \
                    Defaults to $HOME/.lighthouse/{network} where network is the value of the `network` flag \
                    Note: Users should specify separate custom datadirs for different networks.")
                .action(ArgAction::Set)
                .display_order(0)
        )
        .arg(
            Arg::new("testnet-dir")
                .short('t')
                .long("testnet-dir")
                .value_name("DIR")
                .help(
                    "Path to directory containing eth2_testnet specs. Defaults to \
                      a hard-coded Lighthouse testnet. Only effective if there is no \
                      existing database.",
                )
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("network")
                .help("Name of the Eth2 chain Lighthouse will sync and follow.")
                .value_parser(HARDCODED_NET_NAMES.to_vec())
                .conflicts_with("testnet-dir")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("dump-config")
                .long("dump-config")
                .hide(true)
                .help("Dumps the config to a desired location. Used for testing only.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("dump-chain-config")
                .long("dump-chain-config")
                .hide(true)
                .help("Dumps the chain config to a desired location. Used for testing only.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("immediate-shutdown")
                .long("immediate-shutdown")
                .hide(true)
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
                    Used for testing only, DO NOT USE IN PRODUCTION.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new(DISABLE_MALLOC_TUNING_FLAG)
                .long(DISABLE_MALLOC_TUNING_FLAG)
                .help(
                    "If present, do not configure the system allocator. Providing this flag will \
                    generally increase memory usage, it should only be provided when debugging \
                    specific memory allocation issues."
                )
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("genesis-state-url")
                .long("genesis-state-url")
                .value_name("URL")
                .help(
                    "A URL of a beacon-API compatible server from which to download the genesis state. \
                    Checkpoint sync server URLs can generally be used with this flag. \
                    If not supplied, a default URL or the --checkpoint-sync-url may be used. \
                    If the genesis state is already included in this binary then this value will be ignored.",
                )
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("genesis-state-url-timeout")
                .long("genesis-state-url-timeout")
                .value_name("SECONDS")
                .help(
                    "The timeout in seconds for the request to --genesis-state-url.",
                )
                .action(ArgAction::Set)
                .default_value("300")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("help")
            .long("help")
            .short('h')
            .help("Prints help information")
            .action(ArgAction::HelpLong)
            .display_order(0)
            .help_heading(FLAG_HEADER)
            .global(true)
        )
        .subcommand(beacon_node::cli_app())
        .subcommand(boot_node::cli_app())
        .subcommand(account_manager::cli_app())
        .subcommand(validator_manager::cli_app());

    let cli = LighthouseSubcommands::augment_subcommands(cli);

    let matches = cli.get_matches();

    // Configure the allocator early in the process, before it has the chance to use the default values for
    // anything important.
    //
    // Only apply this optimization for the beacon node. It's the only process with a substantial
    // memory footprint.
    let is_beacon_node = matches.subcommand_name() == Some("beacon_node");
    if is_beacon_node
        && !matches.get_flag(DISABLE_MALLOC_TUNING_FLAG)
        && let Err(e) = configure_memory_allocator()
    {
        eprintln!(
            "Unable to configure the memory allocator: {} \n\
                Try providing the --{} flag",
            e, DISABLE_MALLOC_TUNING_FLAG
        );
        exit(1)
    }

    let result = get_eth2_network_config(&matches).and_then(|eth2_network_config| {
        let eth_spec_id = eth2_network_config.eth_spec_id()?;

        // boot node subcommand circumvents the environment
        if let Some(bootnode_matches) = matches.subcommand_matches("boot_node") {
            // The bootnode uses the main debug-level flag
            let debug_info = matches
                .get_one::<String>("debug-level")
                .expect("Debug-level must be present")
                .into();

            boot_node::run(
                &matches,
                bootnode_matches,
                eth_spec_id,
                &eth2_network_config,
                debug_info,
            );

            return Ok(());
        }

        match eth_spec_id {
            EthSpecId::Mainnet => run(EnvironmentBuilder::mainnet(), &matches, eth2_network_config),
            #[cfg(feature = "gnosis")]
            EthSpecId::Gnosis => run(EnvironmentBuilder::gnosis(), &matches, eth2_network_config),
            #[cfg(feature = "spec-minimal")]
            EthSpecId::Minimal => run(EnvironmentBuilder::minimal(), &matches, eth2_network_config),
            #[cfg(not(all(feature = "spec-minimal", feature = "gnosis")))]
            other => {
                eprintln!(
                    "Eth spec `{}` is not supported by this build of Lighthouse",
                    other
                );
                eprintln!("You must compile with a feature flag to enable this spec variant");
                exit(1);
            }
        }
    });

    // `std::process::exit` does not run destructors so we drop manually.
    drop(matches);

    // Return the appropriate error code.
    match result {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("{}", e);
            drop(e);
            exit(1)
        }
    }
}

fn run<E: EthSpec>(
    environment_builder: EnvironmentBuilder<E>,
    matches: &ArgMatches,
    eth2_network_config: Eth2NetworkConfig,
) -> Result<(), String> {
    if std::mem::size_of::<usize>() != 8 {
        return Err(format!(
            "{}-bit architecture is not supported (64-bit only).",
            std::mem::size_of::<usize>() * 8
        ));
    }

    let debug_level = matches
        .get_one::<String>("debug-level")
        .ok_or("Expected --debug-level flag")?;

    let log_format = matches.get_one::<String>("log-format");

    let log_color = if std::io::stdin().is_terminal() {
        matches
            .get_one::<bool>("log-color")
            .copied()
            .unwrap_or(true)
    } else {
        // Disable color when in non-interactive mode.
        false
    };

    let logfile_color = matches.get_flag("logfile-color");

    let disable_log_timestamp = matches.get_flag("disable-log-timestamp");

    let extra_info = matches.get_flag("log-extra-info");
    let logfile_debug_level = matches
        .get_one::<String>("logfile-debug-level")
        .ok_or("Expected --logfile-debug-level flag")?;

    let logfile_format = matches
        .get_one::<String>("logfile-format")
        // Ensure that `logfile-format` defaults to the value of `log-format`.
        .or_else(|| matches.get_one::<String>("log-format"));

    let logfile_max_size: u64 = matches
        .get_one::<String>("logfile-max-size")
        .ok_or("Expected --logfile-max-size flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-size`: {:?}", e))?;

    let logfile_max_number: usize = matches
        .get_one::<String>("logfile-max-number")
        .ok_or("Expected --logfile-max-number flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-number`: {:?}", e))?;

    let logfile_compress = matches.get_flag("logfile-compress");

    let logfile_restricted = !matches.get_flag("logfile-no-restricted-perms");

    // Construct the path to the log file.
    let mut log_path: Option<PathBuf> = clap_utils::parse_optional(matches, "logfile-dir")?;
    if log_path.is_none() {
        log_path = match matches.subcommand() {
            Some(("beacon_node", _)) => Some(
                parse_path_or_default(matches, "datadir")?
                    .join(DEFAULT_BEACON_NODE_DIR)
                    .join("logs"),
            ),
            Some(("validator_client", vc_matches)) => {
                let base_path = if vc_matches.contains_id("validators-dir") {
                    parse_path_or_default(vc_matches, "validators-dir")?
                } else {
                    parse_path_or_default(matches, "datadir")?.join(DEFAULT_VALIDATOR_DIR)
                };

                Some(base_path.join("logs"))
            }
            _ => None,
        };
    }

    let sse_logging = {
        if let Some(bn_matches) = matches.subcommand_matches("beacon_node") {
            bn_matches.get_flag("gui")
        } else if let Some(vc_matches) = matches.subcommand_matches("validator_client") {
            vc_matches.get_flag("http")
        } else {
            false
        }
    };

    let (
        builder,
        logger_config,
        stdout_logging_layer,
        file_logging_layer,
        sse_logging_layer_opt,
        libp2p_discv5_layer,
    ) = tracing_common::construct_logger(
        LoggerConfig {
            path: log_path.clone(),
            debug_level: tracing_common::parse_level(debug_level),
            logfile_debug_level: tracing_common::parse_level(logfile_debug_level),
            log_format: log_format.map(String::from),
            logfile_format: logfile_format.map(String::from),
            log_color,
            logfile_color,
            disable_log_timestamp,
            max_log_size: logfile_max_size,
            max_log_number: logfile_max_number,
            compression: logfile_compress,
            is_restricted: logfile_restricted,
            sse_logging,
            extra_info,
        },
        matches,
        environment_builder,
    );

    let workspace_filter = build_workspace_filter()?;

    let mut logging_layers = Vec::new();

    logging_layers.push(
        stdout_logging_layer
            .with_filter(logger_config.debug_level)
            .with_filter(workspace_filter.clone())
            .boxed(),
    );

    if let Some(file_logging_layer) = file_logging_layer {
        logging_layers.push(
            file_logging_layer
                .with_filter(logger_config.logfile_debug_level)
                .with_filter(workspace_filter.clone())
                .boxed(),
        );
    }

    if let Some(sse_logging_layer) = sse_logging_layer_opt {
        logging_layers.push(
            sse_logging_layer
                .with_filter(workspace_filter.clone())
                .boxed(),
        );
    }

    if let Some(libp2p_discv5_layer) = libp2p_discv5_layer {
        logging_layers.push(
            libp2p_discv5_layer
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(Level::DEBUG.into())
                        .from_env_lossy(),
                )
                .boxed(),
        );
    }

    logging_layers.push(MetricsLayer.boxed());

    let mut environment = builder
        .multi_threaded_tokio_runtime()?
        .eth2_network_config(eth2_network_config)?
        .build()?;

    if let Some(telemetry_collector_url) = matches.get_one::<String>("telemetry-collector-url") {
        let telemetry_layer = environment.runtime().block_on(async {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_tls_config(ClientTlsConfig::new().with_native_roots())
                .with_endpoint(telemetry_collector_url)
                .build()
                .map_err(|e| format!("Failed to create OTLP exporter: {:?}", e))?;

            let service_name = matches
                .get_one::<String>("telemetry-service-name")
                .cloned()
                .unwrap_or_else(|| match matches.subcommand() {
                    Some(("beacon_node", _)) => "lighthouse-bn".to_string(),
                    Some(("validator_client", _)) => "lighthouse-vc".to_string(),
                    _ => "lighthouse".to_string(),
                });

            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name(service_name)
                        .build(),
                )
                .build();

            let tracer = provider.tracer("lighthouse");
            Ok::<_, String>(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_filter(workspace_filter),
            )
        })?;

        logging_layers.push(telemetry_layer.boxed());
    }

    #[cfg(feature = "console-subscriber")]
    {
        let console_layer = console_subscriber::spawn();
        logging_layers.push(console_layer.boxed());
    }

    let logging_result = tracing_subscriber::registry()
        .with(logging_layers)
        .try_init();

    if let Err(e) = logging_result {
        eprintln!("Failed to initialize logger: {e}");
    }

    // Log panics properly.
    {
        std::panic::set_hook(Box::new(move |info| {
            crit!(
                location = info.location().map(ToString::to_string),
                message = info.payload().downcast_ref::<String>(),
                backtrace = %Backtrace::capture(),
                advice = "Please check above for a backtrace and notify the developers",
                "Task panic. This is a bug!"
            );
        }));
    }

    // Allow Prometheus to export the time at which the process was started.
    metrics::expose_process_start_time();

    // Allow Prometheus access to the version and commit of the Lighthouse build.
    metrics::expose_lighthouse_version();

    #[cfg(all(feature = "modern", target_arch = "x86_64"))]
    if !std::is_x86_feature_detected!("adx") {
        tracing::warn!(
            advice = "If you get a SIGILL, please try Lighthouse portable build",
            "CPU seems incompatible with optimized Lighthouse build"
        );
    }

    // Note: the current code technically allows for starting a beacon node _and_ a validator
    // client at the same time.
    //
    // Whilst this is possible, the mutual-exclusivity of `clap` sub-commands prevents it from
    // actually happening.
    //
    // Creating a command which can run both might be useful future works.

    // Print an indication of which network is currently in use.
    let optional_testnet = clap_utils::parse_optional::<String>(matches, "network")?;
    let optional_testnet_dir = clap_utils::parse_optional::<PathBuf>(matches, "testnet-dir")?;

    let network_name = match (optional_testnet, optional_testnet_dir) {
        (Some(testnet), None) => testnet,
        (None, Some(testnet_dir)) => format!("custom ({})", testnet_dir.display()),
        (None, None) => DEFAULT_HARDCODED_NETWORK.to_string(),
        (Some(_), Some(_)) => panic!("CLI prevents both --network and --testnet-dir"),
    };

    if let Some(sub_matches) = matches.subcommand_matches(account_manager::CMD) {
        eprintln!("Running account manager for {} network", network_name);
        // Pass the entire `environment` to the account manager so it can run blocking operations.
        account_manager::run(sub_matches, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    }

    if let Some(sub_matches) = matches.subcommand_matches(validator_manager::CMD) {
        eprintln!("Running validator manager for {} network", network_name);

        // Pass the entire `environment` to the account manager so it can run blocking operations.
        validator_manager::run::<E>(sub_matches, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    }

    match LighthouseSubcommands::from_arg_matches(matches) {
        Ok(LighthouseSubcommands::DatabaseManager(db_manager_config)) => {
            info!("Running database manager for {} network", network_name);
            database_manager::run(matches, &db_manager_config, environment)?;
            return Ok(());
        }
        Ok(LighthouseSubcommands::ValidatorClient(validator_client_config)) => {
            let context = environment.core_context();
            let executor = context.executor.clone();
            let config = validator_client::Config::from_cli(matches, &validator_client_config)
                .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;

            let shutdown_flag = matches.get_flag("immediate-shutdown");
            if shutdown_flag {
                info!("Validator client immediate shutdown triggered.");
                return Ok(());
            }

            executor.clone().spawn(
                async move {
                    if let Err(e) = ProductionValidatorClient::new(context, config)
                        .and_then(|mut vc| async move { vc.start_service().await })
                        .await
                    {
                        crit!(reason = e, "Failed to start validator client");
                        // Ignore the error since it always occurs during normal operation when
                        // shutting down.
                        let _ = executor
                            .shutdown_sender()
                            .try_send(ShutdownReason::Failure("Failed to start validator client"));
                    }
                },
                "validator_client",
            );
        }
        Err(_) => (),
    };

    info!(version = VERSION, "Lighthouse started");
    info!(network_name, "Configured network");

    match matches.subcommand() {
        Some(("beacon_node", matches)) => {
            let context = environment.core_context();
            let executor = context.executor.clone();
            let mut config = beacon_node::get_config::<E>(matches, &context)?;
            config.logger_config = logger_config;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;

            let shutdown_flag = matches.get_flag("immediate-shutdown");
            if shutdown_flag {
                info!("Beacon node immediate shutdown triggered.");
                return Ok(());
            }

            executor.clone().spawn(
                async move {
                    if let Err(e) = ProductionBeaconNode::new(context.clone(), config).await {
                        crit!(reason = ?e, "Failed to start beacon node");
                        // Ignore the error since it always occurs during normal operation when
                        // shutting down.
                        let _ = executor
                            .shutdown_sender()
                            .try_send(ShutdownReason::Failure("Failed to start beacon node"));
                    }
                },
                "beacon_node",
            );
        }
        // TODO(clap-derive) delete this once we've fully migrated to clap derive.
        // Qt the moment this needs to exist so that we dont trigger a crit.
        Some(("validator_client", _)) => (),
        _ => {
            crit!("No subcommand supplied. See --help .");
            return Err("No subcommand supplied.".into());
        }
    };

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    let shutdown_reason = environment.block_until_shutdown_requested()?;
    info!(reason = ?shutdown_reason, "Shutting down..");

    environment.fire_signal();

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle();

    match shutdown_reason {
        ShutdownReason::Success(_) => Ok(()),
        ShutdownReason::Failure(msg) => Err(msg.to_string()),
    }
}
