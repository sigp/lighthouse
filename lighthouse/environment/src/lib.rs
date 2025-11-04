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
use futures::channel::mpsc::{Receiver, Sender, channel};
use futures::{StreamExt, future};
use logging::SSELoggingComponents;
use logging::tracing_logging_layer::LoggingLayer;
use logroller::{Compression, LogRollerBuilder, Rotation, RotationSize};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::{ShutdownReason, TaskExecutor};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tracing::{error, info, warn};
use tracing_subscriber::filter::LevelFilter;
use types::{EthSpec, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};

#[cfg(target_family = "unix")]
use {
    futures::Future,
    std::{pin::Pin, task::Context, task::Poll},
    tokio::signal::unix::{Signal, SignalKind, signal},
};

#[cfg(not(target_family = "unix"))]
use {futures::channel::oneshot, std::cell::RefCell};

pub mod tracing_common;

pub const SSE_LOG_CHANNEL_SIZE: usize = 2048;
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
    #[serde(skip_serializing, skip_deserializing, default = "default_debug_level")]
    pub debug_level: LevelFilter,
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "default_logfile_debug_level"
    )]
    pub logfile_debug_level: LevelFilter,
    pub log_format: Option<String>,
    pub logfile_format: Option<String>,
    pub log_color: bool,
    pub logfile_color: bool,
    pub disable_log_timestamp: bool,
    pub max_log_size: u64,
    pub max_log_number: usize,
    pub compression: bool,
    pub is_restricted: bool,
    pub sse_logging: bool,
    pub extra_info: bool,
}
impl Default for LoggerConfig {
    fn default() -> Self {
        LoggerConfig {
            path: None,
            debug_level: LevelFilter::INFO,
            logfile_debug_level: LevelFilter::DEBUG,
            log_format: None,
            log_color: true,
            logfile_format: None,
            logfile_color: false,
            disable_log_timestamp: false,
            max_log_size: 200,
            max_log_number: 5,
            compression: false,
            is_restricted: true,
            sse_logging: false,
            extra_info: false,
        }
    }
}

fn default_debug_level() -> LevelFilter {
    LevelFilter::INFO
}

fn default_logfile_debug_level() -> LevelFilter {
    LevelFilter::DEBUG
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
    pub sse_logging_components: Option<SSELoggingComponents>,
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
            sse_logging_components: self.sse_logging_components.clone(),
        }
    }

    /// Returns the `eth2_config` for this service.
    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }
}

/// Builds an `Environment`.
pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Arc<Runtime>>,
    sse_logging_components: Option<SSELoggingComponents>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
    eth2_network_config: Option<Eth2NetworkConfig>,
}

impl EnvironmentBuilder<MinimalEthSpec> {
    /// Creates a new builder using the `minimal` eth2 specification.
    pub fn minimal() -> Self {
        Self {
            runtime: None,
            sse_logging_components: None,
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
            sse_logging_components: None,
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
            sse_logging_components: None,
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

    /// Initialize the Lighthouse-specific tracing logging components from
    /// the provided config.
    ///
    /// This consists of 3 tracing `Layers`:
    /// - A `Layer` which logs to `stdout`
    /// - An `Option<Layer>` which logs to a log file
    /// - An `Option<Layer>` which emits logs to an SSE stream
    pub fn init_tracing(
        mut self,
        config: LoggerConfig,
        logfile_prefix: &str,
        file_mode: u32,
    ) -> (
        Self,
        LoggingLayer,
        Option<LoggingLayer>,
        Option<SSELoggingComponents>,
    ) {
        let filename_prefix = match logfile_prefix {
            "beacon_node" => "beacon",
            "validator_client" => "validator",
            _ => logfile_prefix,
        };

        let file_logging_layer = match config.path {
            None => {
                eprintln!("No logfile path provided, logging to file is disabled");
                None
            }
            Some(_) if config.max_log_number == 0 || config.max_log_size == 0 => {
                // User has explicitly disabled logging to file, so don't emit a message.
                None
            }
            Some(path) => {
                let log_filename = PathBuf::from(format!("{}.log", filename_prefix));
                let mut appender = LogRollerBuilder::new(path.clone(), log_filename)
                    .rotation(Rotation::SizeBased(RotationSize::MB(config.max_log_size)))
                    .max_keep_files(config.max_log_number.try_into().unwrap_or_else(|e| {
                        eprintln!("Failed to convert max_log_number to u64: {}", e);
                        10
                    }))
                    .file_mode(file_mode);

                if config.compression {
                    appender = appender.compression(Compression::Gzip);
                }

                match appender.build() {
                    Ok(file_appender) => {
                        let (writer, guard) = tracing_appender::non_blocking(file_appender);
                        Some(LoggingLayer::new(
                            writer,
                            guard,
                            config.disable_log_timestamp,
                            config.logfile_color,
                            config.logfile_format.clone(),
                            config.extra_info,
                        ))
                    }
                    Err(e) => {
                        eprintln!("Failed to initialize rolling file appender: {}", e);
                        None
                    }
                }
            }
        };

        let (stdout_non_blocking_writer, stdout_guard) =
            tracing_appender::non_blocking(std::io::stdout());

        let stdout_logging_layer = LoggingLayer::new(
            stdout_non_blocking_writer,
            stdout_guard,
            config.disable_log_timestamp,
            config.log_color,
            config.log_format,
            config.extra_info,
        );

        let sse_logging_layer_opt = if config.sse_logging {
            Some(SSELoggingComponents::new(SSE_LOG_CHANNEL_SIZE))
        } else {
            None
        };

        self.sse_logging_components = sse_logging_layer_opt.clone();

        (
            self,
            stdout_logging_layer,
            file_logging_layer,
            sse_logging_layer_opt,
        )
    }

    /// Adds a network configuration to the environment.
    pub fn eth2_network_config(
        mut self,
        eth2_network_config: Eth2NetworkConfig,
    ) -> Result<Self, String> {
        // Create a new chain spec from the default configuration.
        self.eth2_config.spec = eth2_network_config.chain_spec::<E>()?.into();
        self.eth2_network_config = Some(eth2_network_config);

        Ok(self)
    }

    /// Consumes the builder, returning an `Environment`.
    pub fn build(self) -> Result<Environment<E>, String> {
        let (signal, exit) = async_channel::bounded(1);
        let (signal_tx, signal_rx) = channel(1);
        Ok(Environment {
            runtime: self
                .runtime
                .ok_or("Cannot build environment without runtime")?,
            signal_tx,
            signal_rx: Some(signal_rx),
            signal: Some(signal),
            exit,
            sse_logging_components: self.sse_logging_components,
            eth_spec_instance: self.eth_spec_instance,
            eth2_config: self.eth2_config,
            eth2_network_config: self.eth2_network_config.map(Arc::new),
        })
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
    signal: Option<async_channel::Sender<()>>,
    exit: async_channel::Receiver<()>,
    sse_logging_components: Option<SSELoggingComponents>,
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

    /// Returns a `Context` where a "core" service has been added to the logger output.
    pub fn core_context(&self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.signal_tx.clone(),
                "core".to_string(),
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
            eth2_network_config: self.eth2_network_config.clone(),
            sse_logging_components: self.sse_logging_components.clone(),
        }
    }

    /// Returns a `Context` where the `service_name` is added to the logger output.
    pub fn service_context(&self, service_name: String) -> RuntimeContext<E> {
        RuntimeContext {
            executor: TaskExecutor::new(
                Arc::downgrade(self.runtime()),
                self.exit.clone(),
                self.signal_tx.clone(),
                service_name,
            ),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
            eth2_network_config: self.eth2_network_config.clone(),
            sse_logging_components: self.sse_logging_components.clone(),
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

        let register_handlers = async {
            let mut handles = vec![];

            // setup for handling SIGTERM
            match signal(SignalKind::terminate()) {
                Ok(terminate_stream) => {
                    let terminate = SignalFuture::new(terminate_stream, "Received SIGTERM");
                    handles.push(terminate);
                }
                Err(e) => error!(error = ?e, "Could not register SIGTERM handler"),
            };

            // setup for handling SIGINT
            match signal(SignalKind::interrupt()) {
                Ok(interrupt_stream) => {
                    let interrupt = SignalFuture::new(interrupt_stream, "Received SIGINT");
                    handles.push(interrupt);
                }
                Err(e) => error!(error = ?e, "Could not register SIGINT handler"),
            }

            // setup for handling a SIGHUP
            match signal(SignalKind::hangup()) {
                Ok(hup_stream) => {
                    let hup = SignalFuture::new(hup_stream, "Received SIGHUP");
                    handles.push(hup);
                }
                Err(e) => error!(error = ?e, "Could not register SIGHUP handler"),
            }

            future::select(inner_shutdown, future::select_all(handles.into_iter())).await
        };

        match self.runtime().block_on(register_handlers) {
            future::Either::Left((Ok(reason), _)) => {
                info!("Internal shutdown received");
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
        ctrlc::set_handler(move || {
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                if let Err(e) = ctrlc_send.send(()) {
                    error!(
                        error = ?e,
                        "Error sending ctrl-c message"
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
                info!(reason = reason.message(), "Internal shutdown received");
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
                error = ?e,
                "Failed to obtain runtime access to shutdown gracefully"
            ),
        }
    }

    /// Fire exit signal which shuts down all spawned services
    pub fn fire_signal(&mut self) {
        if let Some(signal) = self.signal.take() {
            drop(signal);
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
