//! This crate aims to provide a common set of tools that can be used to create a "environment" to
//! run Lighthouse services like the `beacon_node` or `validator_client`. This allows for the
//! unification of creating tokio runtimes, loggers and eth2 specifications in production and in
//! testing.
//!
//! The idea is that the main thread creates an `Environment`, which is then used to spawn a
//! `Context` which can be handed to any service that wishes to start async tasks or perform
//! logging.

use eth2_config::Eth2Config;
use eth2_network_config::Eth2NetworkConfig;
use futures::channel::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};
use futures::{future, StreamExt};

use slog::{error, info, o, warn, Drain, Level, Logger};
use sloggers::{null::NullLoggerBuilder, Build};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::{rename as FsRename, OpenOptions};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use task_executor::{ShutdownReason, TaskExecutor};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use types::{EthSpec, MainnetEthSpec, MinimalEthSpec, V012LegacyEthSpec};

pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";
const LOG_CHANNEL_SIZE: usize = 2048;
/// The maximum time in seconds the client will wait for all internal tasks to shutdown.
const MAXIMUM_SHUTDOWN_TIME: u64 = 15;

/// Builds an `Environment`.
pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Arc<Runtime>>,
    log: Option<Logger>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
    testnet: Option<Eth2NetworkConfig>,
}

impl EnvironmentBuilder<MinimalEthSpec> {
    /// Creates a new builder using the `minimal` eth2 specification.
    pub fn minimal() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MinimalEthSpec,
            eth2_config: Eth2Config::minimal(),
            testnet: None,
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
            testnet: None,
        }
    }
}

impl EnvironmentBuilder<V012LegacyEthSpec> {
    /// Creates a new builder using the v0.12.x eth2 specification.
    pub fn v012_legacy() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: V012LegacyEthSpec,
            eth2_config: Eth2Config::v012_legacy(),
            testnet: None,
        }
    }
}

impl<E: EthSpec> EnvironmentBuilder<E> {
    /// Specifies that a multi-threaded tokio runtime should be used. Ideal for production uses.
    ///
    /// The `Runtime` used is just the standard tokio runtime.
    pub fn multi_threaded_tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime = Some(Arc::new(
            RuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("Failed to start runtime: {:?}", e))?,
        ));
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
                    slog_async::Async::new(drain)
                        .chan_size(LOG_CHANNEL_SIZE)
                        .build()
                }
                _ => return Err("Logging format provided is not supported".to_string()),
            }
        } else {
            let decorator = slog_term::TermDecorator::new().build();
            let decorator =
                logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain)
                .chan_size(LOG_CHANNEL_SIZE)
                .build()
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

    /// Sets the logger (and all child loggers) to log to a file.
    pub fn log_to_file(
        mut self,
        path: PathBuf,
        debug_level: &str,
        log_format: Option<&str>,
    ) -> Result<Self, String> {
        // Creating a backup if the logfile already exists.
        if path.exists() {
            let start = SystemTime::now();
            let timestamp = start
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let file_stem = path
                .file_stem()
                .ok_or("Invalid file name")?
                .to_str()
                .ok_or("Failed to create str from filename")?;
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

        // Setting up the initial logger format and building it.
        let drain = if let Some(format) = log_format {
            match format.to_uppercase().as_str() {
                "JSON" => {
                    let drain = slog_json::Json::default(file).fuse();
                    slog_async::Async::new(drain)
                        .chan_size(LOG_CHANNEL_SIZE)
                        .build()
                }
                _ => return Err("Logging format provided is not supported".to_string()),
            }
        } else {
            let decorator = slog_term::PlainDecorator::new(file);
            let decorator =
                logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain)
                .chan_size(LOG_CHANNEL_SIZE)
                .build()
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

        let log = Logger::root(drain.fuse(), o!());
        info!(
            log,
            "Logging to file";
            "path" => format!("{:?}", path)
        );

        self.log = Some(log);

        Ok(self)
    }

    /// Adds a testnet configuration to the environment.
    pub fn eth2_network_config(
        mut self,
        eth2_network_config: Eth2NetworkConfig,
    ) -> Result<Self, String> {
        // Create a new chain spec from the default configuration.
        self.eth2_config.spec = eth2_network_config
            .yaml_config
            .as_ref()
            .ok_or("The testnet directory must contain a spec config")?
            .apply_to_chain_spec::<E>(&self.eth2_config.spec)
            .ok_or_else(|| {
                format!(
                    "The loaded config is not compatible with the {} spec",
                    &self.eth2_config.eth_spec_id
                )
            })?;

        self.testnet = Some(eth2_network_config);

        Ok(self)
    }

    /// Optionally adds a testnet configuration to the environment.
    pub fn optional_eth2_network_config(
        self,
        optional_config: Option<Eth2NetworkConfig>,
    ) -> Result<Self, String> {
        if let Some(config) = optional_config {
            self.eth2_network_config(config)
        } else {
            Ok(self)
        }
    }

    /// Consumes the builder, returning an `Environment`.
    pub fn build(self) -> Result<Environment<E>, String> {
        let (signal, exit) = exit_future::signal();
        let (signal_tx, signal_rx) = channel(1);
        Ok(Environment {
            runtime: self
                .runtime
                .ok_or("Cannot build environment without runtime")?,
            signal_tx,
            signal_rx: Some(signal_rx),
            signal: Some(signal),
            exit,
            log: self.log.ok_or("Cannot build environment without log")?,
            eth_spec_instance: self.eth_spec_instance,
            eth2_config: self.eth2_config,
            testnet: self.testnet,
        })
    }
}

/// An execution context that can be used by a service.
///
/// Distinct from an `Environment` because a `Context` is not able to give a mutable reference to a
/// `Runtime`, instead it only has access to a `Runtime`.
#[derive(Clone)]
pub struct RuntimeContext<E: EthSpec> {
    pub executor: TaskExecutor,
    pub eth_spec_instance: E,
    pub eth2_config: Eth2Config,
}

impl<E: EthSpec> RuntimeContext<E> {
    /// Returns a sub-context of this context.
    ///
    /// The generated service will have the `service_name` in all it's logs.
    pub fn service_context(&self, service_name: String) -> Self {
        Self {
            executor: self.executor.clone_with_name(service_name),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns the `eth2_config` for this service.
    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }

    /// Returns a reference to the logger for this service.
    pub fn log(&self) -> &slog::Logger {
        self.executor.log()
    }
}

/// An environment where Lighthouse services can run. Used to start a production beacon node or
/// validator client, or to run tests that involve logging and async task execution.
pub struct Environment<E: EthSpec> {
    runtime: Arc<Runtime>,
    /// Receiver side of an internal shutdown signal.
    signal_rx: Option<Receiver<ShutdownReason>>,
    /// Sender to request shutting down.
    signal_tx: Sender<ShutdownReason>,
    signal: Option<exit_future::Signal>,
    exit: exit_future::Exit,
    log: Logger,
    eth_spec_instance: E,
    pub eth2_config: Eth2Config,
    pub testnet: Option<Eth2NetworkConfig>,
}

impl<E: EthSpec> Environment<E> {
    /// Returns a mutable reference to the `tokio` runtime.
    ///
    /// Useful in the rare scenarios where it's necessary to block the current thread until a task
    /// is finished (e.g., during testing).
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Returns a `Context` where no "service" has been added to the logger output.
    pub fn core_context(&mut self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.log.clone(),
                self.signal_tx.clone(),
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns a `Context` where the `service_name` is added to the logger output.
    pub fn service_context(&mut self, service_name: String) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.log.new(o!("service" => service_name)),
                self.signal_tx.clone(),
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Block the current thread until a shutdown signal is received.
    ///
    /// This can be either the user Ctrl-C'ing or a task requesting to shutdown.
    pub fn block_until_shutdown_requested(&mut self) -> Result<ShutdownReason, String> {
        // future of a task requesting to shutdown
        let mut rx = self
            .signal_rx
            .take()
            .ok_or("Inner shutdown already received")?;
        let inner_shutdown =
            async move { rx.next().await.ok_or("Internal shutdown channel exhausted") };
        futures::pin_mut!(inner_shutdown);

        // setup for handling a Ctrl-C
        let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
        let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
        let log = self.log.clone();
        ctrlc::set_handler(move || {
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                if let Err(e) = ctrlc_send.send(()) {
                    error!(
                        log,
                        "Error sending ctrl-c message";
                        "error" => e
                    );
                }
            }
        })
        .map_err(|e| format!("Could not set ctrlc handler: {:?}", e))?;

        // Block this thread until a shutdown signal is received.
        match self
            .runtime()
            .block_on(future::select(inner_shutdown, ctrlc_oneshot))
        {
            future::Either::Left((Ok(reason), _)) => {
                info!(self.log, "Internal shutdown received"; "reason" => reason.message());
                Ok(reason)
            }
            future::Either::Left((Err(e), _)) => Err(e.into()),
            future::Either::Right((x, _)) => x
                .map(|()| ShutdownReason::Success("Received Ctrl+C"))
                .map_err(|e| format!("Ctrlc oneshot failed: {}", e)),
        }
    }

    /// Shutdown the `tokio` runtime when all tasks are idle.
    pub fn shutdown_on_idle(self) {
        match Arc::try_unwrap(self.runtime) {
            Ok(runtime) => {
                runtime.shutdown_timeout(std::time::Duration::from_secs(MAXIMUM_SHUTDOWN_TIME))
            }
            Err(e) => warn!(
                self.log,
                "Failed to obtain runtime access to shutdown gracefully";
                "error" => ?e
            ),
        }
    }

    /// Fire exit signal which shuts down all spawned services
    pub fn fire_signal(&mut self) {
        if let Some(signal) = self.signal.take() {
            let _ = signal.fire();
        }
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
