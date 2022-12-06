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
use futures::channel::mpsc::{channel, Receiver, Sender};
use futures::{future, StreamExt};

use serde_derive::{Deserialize, Serialize};
use slog::{error, info, o, warn, Drain, Duplicate, Level, Logger};
use sloggers::{file::FileLoggerBuilder, types::Format, types::Severity, Build};
use std::fs::create_dir_all;
use std::io::{Result as IOResult, Write};
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::{ShutdownReason, TaskExecutor};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use types::{EthSpec, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};

#[cfg(target_family = "unix")]
use {
    futures::Future,
    std::{pin::Pin, task::Context, task::Poll},
    tokio::signal::unix::{signal, Signal, SignalKind},
};

#[cfg(not(target_family = "unix"))]
use {futures::channel::oneshot, std::cell::RefCell};

pub use task_executor::test_utils::null_logger;

const LOG_CHANNEL_SIZE: usize = 2048;
/// The maximum time in seconds the client will wait for all internal tasks to shutdown.
const MAXIMUM_SHUTDOWN_TIME: u64 = 15;

/// Configuration for logging.
/// Background file logging is disabled if one of:
/// - `path` == None,
/// - `max_log_size` == 0,
/// - `max_log_number` == 0,
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub path: Option<PathBuf>,
    pub debug_level: String,
    pub logfile_debug_level: String,
    pub log_format: Option<String>,
    pub log_color: bool,
    pub disable_log_timestamp: bool,
    pub max_log_size: u64,
    pub max_log_number: usize,
    pub compression: bool,
    pub is_restricted: bool,
}
impl Default for LoggerConfig {
    fn default() -> Self {
        LoggerConfig {
            path: None,
            debug_level: String::from("info"),
            logfile_debug_level: String::from("debug"),
            log_format: None,
            log_color: false,
            disable_log_timestamp: false,
            max_log_size: 200,
            max_log_number: 5,
            compression: false,
            is_restricted: true,
        }
    }
}

/// Builds an `Environment`.
pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Arc<Runtime>>,
    log: Option<Logger>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
    eth2_network_config: Option<Eth2NetworkConfig>,
}

impl EnvironmentBuilder<MinimalEthSpec> {
    /// Creates a new builder using the `minimal` eth2 specification.
    pub fn minimal() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MinimalEthSpec,
            eth2_config: Eth2Config::minimal(),
            eth2_network_config: None,
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
            eth2_network_config: None,
        }
    }
}

impl EnvironmentBuilder<GnosisEthSpec> {
    /// Creates a new builder using the `gnosis` eth2 specification.
    pub fn gnosis() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: GnosisEthSpec,
            eth2_config: Eth2Config::gnosis(),
            eth2_network_config: None,
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

    fn log_nothing(_: &mut dyn Write) -> IOResult<()> {
        Ok(())
    }

    /// Initializes the logger using the specified configuration.
    /// The logger is "async" because it has a dedicated thread that accepts logs and then
    /// asynchronously flushes them to stdout/files/etc. This means the thread that raised the log
    /// does not have to wait for the logs to be flushed.
    /// The logger can be duplicated and more detailed logs can be output to `logfile`.
    /// Note that background file logging will spawn a new thread.
    pub fn initialize_logger(mut self, config: LoggerConfig) -> Result<Self, String> {
        // Setting up the initial logger format and build it.
        let stdout_drain = if let Some(ref format) = config.log_format {
            match format.to_uppercase().as_str() {
                "JSON" => {
                    let stdout_drain = slog_json::Json::default(std::io::stdout()).fuse();
                    slog_async::Async::new(stdout_drain)
                        .chan_size(LOG_CHANNEL_SIZE)
                        .build()
                }
                _ => return Err("Logging format provided is not supported".to_string()),
            }
        } else {
            let stdout_decorator_builder = slog_term::TermDecorator::new();
            let stdout_decorator = if config.log_color {
                stdout_decorator_builder.force_color()
            } else {
                stdout_decorator_builder
            }
            .build();
            let stdout_decorator =
                logging::AlignedTermDecorator::new(stdout_decorator, logging::MAX_MESSAGE_WIDTH);
            let stdout_drain = slog_term::FullFormat::new(stdout_decorator);
            let stdout_drain = if config.disable_log_timestamp {
                stdout_drain.use_custom_timestamp(Self::log_nothing)
            } else {
                stdout_drain
            }
            .build()
            .fuse();
            slog_async::Async::new(stdout_drain)
                .chan_size(LOG_CHANNEL_SIZE)
                .build()
        };

        let stdout_drain = match config.debug_level.as_str() {
            "info" => stdout_drain.filter_level(Level::Info),
            "debug" => stdout_drain.filter_level(Level::Debug),
            "trace" => stdout_drain.filter_level(Level::Trace),
            "warn" => stdout_drain.filter_level(Level::Warning),
            "error" => stdout_drain.filter_level(Level::Error),
            "crit" => stdout_drain.filter_level(Level::Critical),
            unknown => return Err(format!("Unknown debug-level: {}", unknown)),
        };

        let stdout_logger = Logger::root(stdout_drain.fuse(), o!());

        // Disable file logging if values set to 0.
        if config.max_log_size == 0 || config.max_log_number == 0 {
            self.log = Some(stdout_logger);
            return Ok(self);
        }

        // Disable file logging if no path is specified.
        let path = match config.path {
            Some(path) => path,
            None => {
                self.log = Some(stdout_logger);
                return Ok(self);
            }
        };

        // Ensure directories are created becfore the logfile.
        if !path.exists() {
            let mut dir = path.clone();
            dir.pop();

            // Create the necessary directories for the correct service and network.
            if !dir.exists() {
                let res = create_dir_all(dir);

                // If the directories cannot be created, warn and disable the logger.
                match res {
                    Ok(_) => (),
                    Err(e) => {
                        let log = stdout_logger;
                        warn!(
                            log,
                            "Background file logging is disabled";
                            "error" => e);
                        self.log = Some(log);
                        return Ok(self);
                    }
                }
            }
        }

        let logfile_level = match config.logfile_debug_level.as_str() {
            "info" => Severity::Info,
            "debug" => Severity::Debug,
            "trace" => Severity::Trace,
            "warn" => Severity::Warning,
            "error" => Severity::Error,
            "crit" => Severity::Critical,
            unknown => return Err(format!("Unknown loglevel-debug-level: {}", unknown)),
        };

        let file_logger = FileLoggerBuilder::new(&path)
            .level(logfile_level)
            .channel_size(LOG_CHANNEL_SIZE)
            .format(match config.log_format.as_deref() {
                Some("JSON") => Format::Json,
                _ => Format::default(),
            })
            .rotate_size(config.max_log_size)
            .rotate_keep(config.max_log_number)
            .rotate_compress(config.compression)
            .restrict_permissions(config.is_restricted)
            .build()
            .map_err(|e| format!("Unable to build file logger: {}", e))?;

        let log = Logger::root(Duplicate::new(stdout_logger, file_logger).fuse(), o!());

        info!(
            log,
            "Logging to file";
            "path" => format!("{:?}", path)
        );

        self.log = Some(log);

        Ok(self)
    }

    /// Adds a network configuration to the environment.
    pub fn eth2_network_config(
        mut self,
        eth2_network_config: Eth2NetworkConfig,
    ) -> Result<Self, String> {
        // Create a new chain spec from the default configuration.
        self.eth2_config.spec = eth2_network_config.chain_spec::<E>()?;
        self.eth2_network_config = Some(eth2_network_config);

        Ok(self)
    }

    /// Optionally adds a network configuration to the environment.
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
            eth2_network_config: self.eth2_network_config.map(Arc::new),
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
    pub eth2_network_config: Option<Arc<Eth2NetworkConfig>>,
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
            eth2_network_config: self.eth2_network_config.clone(),
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
    pub eth2_network_config: Option<Arc<Eth2NetworkConfig>>,
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
    pub fn core_context(&self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.log.clone(),
                self.signal_tx.clone(),
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
            eth2_network_config: self.eth2_network_config.clone(),
        }
    }

    /// Returns a `Context` where the `service_name` is added to the logger output.
    pub fn service_context(&self, service_name: String) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.log.new(o!("service" => service_name)),
                self.signal_tx.clone(),
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
            eth2_network_config: self.eth2_network_config.clone(),
        }
    }

    /// Block the current thread until a shutdown signal is received.
    ///
    /// This can be either the user Ctrl-C'ing or a task requesting to shutdown.
    #[cfg(target_family = "unix")]
    pub fn block_until_shutdown_requested(&mut self) -> Result<ShutdownReason, String> {
        // future of a task requesting to shutdown
        let mut rx = self
            .signal_rx
            .take()
            .ok_or("Inner shutdown already received")?;
        let inner_shutdown =
            async move { rx.next().await.ok_or("Internal shutdown channel exhausted") };
        futures::pin_mut!(inner_shutdown);

        match self.runtime().block_on(async {
            let mut handles = vec![];

            // setup for handling SIGTERM
            match signal(SignalKind::terminate()) {
                Ok(terminate_stream) => {
                    let terminate = SignalFuture::new(terminate_stream, "Received SIGTERM");
                    handles.push(terminate);
                }
                Err(e) => error!(self.log, "Could not register SIGTERM handler"; "error" => e),
            };

            // setup for handling SIGINT
            match signal(SignalKind::interrupt()) {
                Ok(interrupt_stream) => {
                    let interrupt = SignalFuture::new(interrupt_stream, "Received SIGINT");
                    handles.push(interrupt);
                }
                Err(e) => error!(self.log, "Could not register SIGINT handler"; "error" => e),
            }

            // setup for handling a SIGHUP
            match signal(SignalKind::hangup()) {
                Ok(hup_stream) => {
                    let hup = SignalFuture::new(hup_stream, "Received SIGHUP");
                    handles.push(hup);
                }
                Err(e) => error!(self.log, "Could not register SIGHUP handler"; "error" => e),
            }

            future::select(inner_shutdown, future::select_all(handles.into_iter())).await
        }) {
            future::Either::Left((Ok(reason), _)) => {
                info!(self.log, "Internal shutdown received"; "reason" => reason.message());
                Ok(reason)
            }
            future::Either::Left((Err(e), _)) => Err(e.into()),
            future::Either::Right(((res, _, _), _)) => {
                res.ok_or_else(|| "Handler channel closed".to_string())
            }
        }
    }

    /// Block the current thread until a shutdown signal is received.
    ///
    /// This can be either the user Ctrl-C'ing or a task requesting to shutdown.
    #[cfg(not(target_family = "unix"))]
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

#[cfg(target_family = "unix")]
struct SignalFuture {
    signal: Signal,
    message: &'static str,
}

#[cfg(target_family = "unix")]
impl SignalFuture {
    pub fn new(signal: Signal, message: &'static str) -> SignalFuture {
        SignalFuture { signal, message }
    }
}

#[cfg(target_family = "unix")]
impl Future for SignalFuture {
    type Output = Option<ShutdownReason>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.signal.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(_)) => Poll::Ready(Some(ShutdownReason::Success(self.message))),
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}
