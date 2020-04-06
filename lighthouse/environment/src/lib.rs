//! This crate aims to provide a common set of tools that can be used to create a "environment" to
//! run Lighthouse services like the `beacon_node` or `validator_client`. This allows for the
//! unification of creating tokio runtimes, loggers and eth2 specifications in production and in
//! testing.
//!
//! The idea is that the main thread creates an `Environment`, which is then used to spawn a
//! `Context` which can be handed to any service that wishes to start async tasks or perform
//! logging.

use clap::ArgMatches;
use eth2_config::{read_from_file, Eth2Config};
use eth2_testnet_config::Eth2TestnetConfig;
use futures::{sync::oneshot, Future};
use slog::{info, o, Drain, Level, Logger};
use sloggers::{null::NullLoggerBuilder, Build};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::{rename as FsRename, OpenOptions};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime, TaskExecutor};
use types::{EthSpec, InteropEthSpec, MainnetEthSpec, MinimalEthSpec};

pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

/// Builds an `Environment`.
pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Runtime>,
    log: Option<Logger>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
}

impl EnvironmentBuilder<MinimalEthSpec> {
    /// Creates a new builder using the `minimal` eth2 specification.
    pub fn minimal() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MinimalEthSpec,
            eth2_config: Eth2Config::minimal(),
        }
    }
}

impl EnvironmentBuilder<MainnetEthSpec> {
    /// Creates a new builder using the `mainnet` eth2 specification.
    pub fn mainnet() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MainnetEthSpec,
            eth2_config: Eth2Config::mainnet(),
        }
    }
}

impl EnvironmentBuilder<InteropEthSpec> {
    /// Creates a new builder using the `interop` eth2 specification.
    pub fn interop() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: InteropEthSpec,
            eth2_config: Eth2Config::interop(),
        }
    }
}

impl<E: EthSpec> EnvironmentBuilder<E> {
    /// Specifies that a multi-threaded tokio runtime should be used. Ideal for production uses.
    ///
    /// The `Runtime` used is just the standard tokio runtime.
    pub fn multi_threaded_tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime =
            Some(Runtime::new().map_err(|e| format!("Failed to start runtime: {:?}", e))?);
        Ok(self)
    }

    /// Specifies that a single-threaded tokio runtime should be used. Ideal for testing purposes
    /// where tests are already multi-threaded.
    ///
    /// This can solve problems if "too many open files" errors are thrown during tests.
    pub fn single_thread_tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime = Some(
            RuntimeBuilder::new()
                .core_threads(1)
                .build()
                .map_err(|e| format!("Failed to start runtime: {:?}", e))?,
        );
        Ok(self)
    }

    /// Specifies that all logs should be sent to `null` (i.e., ignored).
    pub fn null_logger(mut self) -> Result<Self, String> {
        self.log = Some(null_logger()?);
        Ok(self)
    }

    /// Specifies that the `slog` asynchronous logger should be used. Ideal for production.
    ///
    /// The logger is "async" because it has a dedicated thread that accepts logs and then
    /// asynchronously flushes them to stdout/files/etc. This means the thread that raised the log
    /// does not have to wait for the logs to be flushed.
    pub fn async_logger(
        mut self,
        debug_level: &str,
        log_format: Option<&str>,
    ) -> Result<Self, String> {
        // Setting up the initial logger format and building it.
        let drain = if let Some(format) = log_format {
            match format.to_uppercase().as_str() {
                "JSON" => {
                    let drain = slog_json::Json::default(std::io::stdout()).fuse();
                    slog_async::Async::new(drain).build()
                }
                _ => return Err("Logging format provided is not supported".to_string()),
            }
        } else {
            let decorator = slog_term::TermDecorator::new().build();
            let decorator =
                logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain).build()
        };

        let drain = match debug_level {
            "info" => drain.filter_level(Level::Info),
            "debug" => drain.filter_level(Level::Debug),
            "trace" => drain.filter_level(Level::Trace),
            "warn" => drain.filter_level(Level::Warning),
            "error" => drain.filter_level(Level::Error),
            "crit" => drain.filter_level(Level::Critical),
            unknown => return Err(format!("Unknown debug-level: {}", unknown)),
        };

        self.log = Some(Logger::root(drain.fuse(), o!()));
        Ok(self)
    }

    /// Setups eth2 config using the CLI arguments.
    pub fn setup_eth2_config(
        mut self,
        datadir: PathBuf,
        eth2_testnet_config: Eth2TestnetConfig<E>,
        cli_args: &ArgMatches,
    ) -> Result<Self, String> {
        self.load_eth2_config(&datadir)?;

        match cli_args.subcommand() {
            ("testnet", Some(sub_cli_args)) => {
                // Modify the `SECONDS_PER_SLOT` "constant".
                if let Some(slot_time) = sub_cli_args.value_of("slot-time") {
                    let slot_time = slot_time
                        .parse::<u64>()
                        .map_err(|e| format!("Unable to parse slot-time: {:?}", e))?;

                    self.eth2_config.spec.milliseconds_per_slot = slot_time;
                }
            }
            _ => {
                if !datadir.exists() {
                    // Create a new chain spec from the default configuration.
                    self.eth2_config.spec = eth2_testnet_config
                        .yaml_config
                        .as_ref()
                        .ok_or_else(|| {
                            "The testnet directory must contain a spec config".to_string()
                        })?
                        .apply_to_chain_spec::<E>(&self.eth2_config.spec)
                        .ok_or_else(|| {
                            format!(
                                "The loaded config is not compatible with the {} spec",
                                &self.eth2_config.spec_constants
                            )
                        })?;
                }
            }
        }

        Ok(self)
    }

    /// Loads the eth2 config if the file exists.
    fn load_eth2_config(&mut self, datadir: &PathBuf) -> Result<(), String> {
        let filename = datadir.join(ETH2_CONFIG_FILENAME);
        if filename.exists() {
            let loaded_eth2_config: Eth2Config = read_from_file(filename.clone())
                .map_err(|e| format!("Unable to parse {:?} file: {:?}", filename, e))?
                .ok_or_else(|| format!("{:?} file does not exist", filename))?;

            // The loaded spec must be using the same spec constants (e.g., minimal, mainnet) as the
            // client expects.
            if loaded_eth2_config.spec_constants == self.eth2_config.spec_constants {
                self.eth2_config = loaded_eth2_config;
            } else {
                return Err(format!(
                    "Eth2 config loaded from disk does not match client spec version. Got {} \
                         expected {}",
                    &loaded_eth2_config.spec_constants, &self.eth2_config.spec_constants
                ));
            }
        }

        Ok(())
    }

    /// Consumes the builder, returning an `Environment`.
    pub fn build(self) -> Result<Environment<E>, String> {
        Ok(Environment {
            runtime: self
                .runtime
                .ok_or_else(|| "Cannot build environment without runtime".to_string())?,
            log: self
                .log
                .ok_or_else(|| "Cannot build environment without log".to_string())?,
            eth_spec_instance: self.eth_spec_instance,
            eth2_config: self.eth2_config,
        })
    }
}

/// An execution context that can be used by a service.
///
/// Distinct from an `Environment` because a `Context` is not able to give a mutable reference to a
/// `Runtime`, instead it only has access to a `TaskExecutor`.
#[derive(Clone)]
pub struct RuntimeContext<E: EthSpec> {
    pub executor: TaskExecutor,
    pub log: Logger,
    pub eth_spec_instance: E,
    pub eth2_config: Eth2Config,
}

impl<E: EthSpec> RuntimeContext<E> {
    /// Returns a sub-context of this context.
    ///
    /// The generated service will have the `service_name` in all it's logs.
    pub fn service_context(&self, service_name: String) -> Self {
        Self {
            executor: self.executor.clone(),
            log: self.log.new(o!("service" => service_name)),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns the `eth2_config` for this service.
    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }
}

/// An environment where Lighthouse services can run. Used to start a production beacon node or
/// validator client, or to run tests that involve logging and async task execution.
pub struct Environment<E: EthSpec> {
    runtime: Runtime,
    log: Logger,
    eth_spec_instance: E,
    pub eth2_config: Eth2Config,
}

impl<E: EthSpec> Environment<E> {
    /// Returns a mutable reference to the `tokio` runtime.
    ///
    /// Useful in the rare scenarios where it's necessary to block the current thread until a task
    /// is finished (e.g., during testing).
    pub fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// Returns a `Context` where no "service" has been added to the logger output.
    pub fn core_context(&mut self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: self.runtime.executor(),
            log: self.log.clone(),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns a `Context` where the `service_name` is added to the logger output.
    pub fn service_context(&mut self, service_name: String) -> RuntimeContext<E> {
        RuntimeContext {
            executor: self.runtime.executor(),
            log: self.log.new(o!("service" => service_name)),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Block the current thread until Ctrl+C is received.
    pub fn block_until_ctrl_c(&mut self) -> Result<(), String> {
        let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
        let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
        ctrlc::set_handler(move || {
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                ctrlc_send.send(()).expect("Error sending ctrl-c message");
            }
        })
        .map_err(|e| format!("Could not set ctrlc handler: {:?}", e))?;

        // Block this thread until Crtl+C is pressed.
        self.runtime()
            .block_on(ctrlc_oneshot)
            .map_err(|e| format!("Ctrlc oneshot failed: {:?}", e))
    }

    /// Shutdown the `tokio` runtime when all tasks are idle.
    pub fn shutdown_on_idle(self) -> Result<(), String> {
        self.runtime
            .shutdown_on_idle()
            .wait()
            .map_err(|e| format!("Tokio runtime shutdown returned an error: {:?}", e))
    }

    /// Sets the logger (and all child loggers) to log to a file.
    pub fn log_to_json_file(
        &mut self,
        path: PathBuf,
        debug_level: &str,
        log_format: Option<&str>,
    ) -> Result<(), String> {
        // Creating a backup if the logfile already exists.
        if path.exists() {
            let start = SystemTime::now();
            let timestamp = start
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let file_stem = path
                .file_stem()
                .ok_or_else(|| "Invalid file name".to_string())?
                .to_str()
                .ok_or_else(|| "Failed to create str from filename".to_string())?;
            let file_ext = path.extension().unwrap_or_else(|| OsStr::new(""));
            let backup_name = format!("{}_backup_{}", file_stem, timestamp);
            let backup_path = path.with_file_name(backup_name).with_extension(file_ext);
            FsRename(&path, &backup_path).map_err(|e| e.to_string())?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("Unable to open logfile: {:?}", e))?;

        let log_format = log_format.unwrap_or("JSON");
        let drain = match log_format.to_uppercase().as_str() {
            "JSON" => {
                let drain = slog_json::Json::default(file).fuse();
                slog_async::Async::new(drain).build()
            }
            _ => return Err("Logging format provided is not supported".to_string()),
        };

        let drain = match debug_level {
            "info" => drain.filter_level(Level::Info),
            "debug" => drain.filter_level(Level::Debug),
            "trace" => drain.filter_level(Level::Trace),
            "warn" => drain.filter_level(Level::Warning),
            "error" => drain.filter_level(Level::Error),
            "crit" => drain.filter_level(Level::Critical),
            unknown => return Err(format!("Unknown debug-level: {}", unknown)),
        };

        self.log = Logger::root(drain.fuse(), o!());

        info!(
            self.log,
            "Logging to JSON file";
            "path" => format!("{:?}", path)
        );

        Ok(())
    }

    pub fn eth_spec_instance(&self) -> &E {
        &self.eth_spec_instance
    }

    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }
}

pub fn null_logger() -> Result<Logger, String> {
    let log_builder = NullLoggerBuilder;
    log_builder
        .build()
        .map_err(|e| format!("Failed to start null logger: {:?}", e))
}
